"""Server-owned identity, RBAC, sandbox tools, and the canonical tool executor.

This module intentionally contains development authentication and disposable
resources only.  It is not a production authentication service and it never
exposes arbitrary shell execution or a production database handle.
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PureWindowsPath
from contextvars import ContextVar
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field

from schema.interception import ToolRequest

logger = logging.getLogger("agent_shield.tool_security")


class ToolRole(str, Enum):
    """Roles resolved by the server-side development identity store."""

    USER = "USER"
    ANALYST = "ANALYST"
    ADMIN = "ADMIN"


Role = ToolRole


class Identity(BaseModel):
    """Authenticated identity metadata owned by the server.

    ``role`` is deliberately absent from :class:`ToolRequest`; callers may
    identify themselves, but cannot select this value through a tool request.
    """

    subject_id: str = Field(min_length=1)
    role: ToolRole
    authenticated: bool = True
    auth_source: str = "development authentication / server-side identity context"


IdentityContext = Identity
AuthenticatedIdentity = Identity


class ToolResult(BaseModel):
    """Structured result returned by :class:`SecureToolExecutor`."""

    tool_call_id: str
    request_id: str
    tool_name: str
    status: str
    output: Optional[str] = None
    security_decision: str
    timestamp: str
    subject_id: Optional[str] = None
    resolved_role: Optional[ToolRole] = None
    authorization_decision: str = "NOT_RUN"
    argument_security_decision: str = "NOT_RUN"
    execution_status: str = "NOT_RUN"
    output_security_decision: str = "NOT_RUN"
    approval_id: Optional[str] = None
    reason: Optional[str] = None


class ToolSecurityError(RuntimeError):
    """Base class for server-side tool security failures."""


class ToolAuthorizationError(ToolSecurityError):
    """Raised by policy code when an identity lacks a permission."""


class ToolArgumentError(ToolSecurityError):
    """Raised when tool arguments cannot be safely interpreted."""


class ToolQuotaError(ToolSecurityError):
    """Raised when a request exceeds its explicit tool-use budget."""


class StrictToolArguments(BaseModel):
    """Base model for server-owned tool schemas; unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=True)


class SearchArguments(StrictToolArguments):
    query: str = Field(min_length=1, max_length=2_000)


class DatabaseSearchArguments(StrictToolArguments):
    search: str = Field(min_length=1, max_length=512)


class DatabaseEntityArguments(StrictToolArguments):
    entity_key: str = Field(min_length=1, max_length=512)


class SandboxPathArguments(StrictToolArguments):
    path: str = Field(min_length=1, max_length=512)


class SandboxWriteArguments(SandboxPathArguments):
    content: str = Field(min_length=0, max_length=32_000)


class DeleteRecordArguments(StrictToolArguments):
    record_id: str = Field(min_length=6, max_length=128, pattern=r"^temp-[A-Za-z0-9_-]+$")


TOOL_ARGUMENT_MODELS: Mapping[str, type[StrictToolArguments]] = {
    "search_web": SearchArguments,
    "web_search_tool": SearchArguments,
    "query_test_db": DatabaseSearchArguments,
    "mock_database_tool": DatabaseEntityArguments,
    "read_document": SandboxPathArguments,
    "read_temp_file": SandboxPathArguments,
    "write_temp_file": SandboxWriteArguments,
    "delete_temp_record": DeleteRecordArguments,
}


def validate_tool_arguments(tool_name: str, arguments: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate active-tool inputs before their implementation can run."""
    model = TOOL_ARGUMENT_MODELS.get(tool_name)
    if model is None:
        return dict(arguments)
    try:
        supplied = dict(arguments)
        # Decorated development fixtures historically use ``_query`` as the
        # single Python parameter. Translate only that explicit alias for
        # validation, then restore it for the implementation signature.
        aliases = (
            {"_query": "query"}
            if tool_name in {"search_web", "web_search_tool"}
            else {"_query": "entity_key"}
            if tool_name == "mock_database_tool"
            else {}
        )
        normalized = dict(supplied)
        for alias, canonical in aliases.items():
            if alias in normalized:
                if canonical in normalized:
                    raise ToolArgumentError("Tool arguments contain conflicting aliases")
                normalized[canonical] = normalized.pop(alias)
        validated = model.model_validate(normalized).model_dump()
        for alias, canonical in aliases.items():
            if alias in supplied:
                validated[alias] = validated.pop(canonical)
        return validated
    except Exception as exc:
        raise ToolArgumentError("Tool arguments do not match the allowed schema") from exc


class ServerIdentityResolver:
    """Small local identity/session mapping for development deployments.

    The mapping is server-owned.  ``requested_role`` is accepted only as a
    compatibility parameter and is intentionally ignored.
    """

    _SUBJECTS: Mapping[str, ToolRole] = {
        "user_default": ToolRole.USER,
        "user_html": ToolRole.USER,
        "user_demo": ToolRole.USER,
        "analyst_demo": ToolRole.ANALYST,
        "admin_demo": ToolRole.ADMIN,
    }
    _TOKENS: Mapping[str, tuple[str, ToolRole]] = {
        "dev-user-token": ("user_demo", ToolRole.USER),
        "dev-analyst-token": ("analyst_demo", ToolRole.ANALYST),
        "dev-admin-token": ("admin_demo", ToolRole.ADMIN),
    }

    @classmethod
    def _production_identity(cls, auth_token: Optional[str]) -> Identity | None:
        """Resolve a token from an environment-only JSON mapping.

        ``AGENTSHIELD_API_TOKENS`` is intentionally absent from the example
        environment file.  Expected shape: ``{"opaque-token": {"subject_id":
        "researcher-1", "role": "ANALYST"}}``.  This modest adapter keeps
        the prototype self-contained without pretending to be an OAuth/OIDC
        platform.
        """
        raw = os.getenv("AGENTSHIELD_API_TOKENS", "").strip()
        if not auth_token or not raw:
            return None
        try:
            records = json.loads(raw)
            if not isinstance(records, dict):
                return None
            selected = None
            for token, value in records.items():
                if isinstance(token, str) and hmac.compare_digest(token, auth_token):
                    selected = value
                    break
            if not isinstance(selected, dict):
                return None
            subject = str(selected.get("subject_id", "")).strip()
            role = ToolRole(str(selected.get("role", "USER")).upper())
            if not subject:
                return None
            return Identity(
                subject_id=subject,
                role=role,
                authenticated=True,
                auth_source="environment token mapping",
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    @classmethod
    def resolve(
        cls,
        subject_id: Optional[str] = None,
        *,
        auth_token: Optional[str] = None,
        requested_role: Optional[str] = None,
    ) -> Identity:
        del requested_role  # caller-controlled role is never authorization input
        from config import APP_ENV, DEVELOPMENT_AUTH_ENABLED

        dev_auth_active = (
            APP_ENV in {"development", "test"} and DEVELOPMENT_AUTH_ENABLED
        )
        normalized_subject = str(subject_id or "user_default").strip() or "user_default"
        # These identities are fixtures, not authentication.  Outside an
        # explicit development/test mode they remain visible only as an
        # unauthenticated USER so callers cannot select admin_demo in
        # production by subject or token.
        if not dev_auth_active:
            production_identity = cls._production_identity(auth_token)
            if production_identity is not None:
                return production_identity
            if auth_token in cls._TOKENS or normalized_subject in cls._SUBJECTS:
                return Identity(
                    subject_id=normalized_subject,
                    role=ToolRole.USER,
                    authenticated=False,
                    auth_source="development authentication disabled outside development/test mode",
                )
            return Identity(
                subject_id=normalized_subject,
                role=ToolRole.USER,
                authenticated=False,
                auth_source="no production identity provider configured",
            )
        if auth_token and auth_token in cls._TOKENS:
            resolved_subject, role = cls._TOKENS[auth_token]
            return Identity(
                subject_id=resolved_subject,
                role=role,
                authenticated=True,
            )
        if auth_token:
            return cls._production_identity(auth_token) or Identity(
                subject_id="anonymous", role=ToolRole.USER, authenticated=False,
                auth_source="invalid bearer token",
            )
        role = cls._SUBJECTS.get(normalized_subject, ToolRole.USER)
        return Identity(subject_id=normalized_subject, role=role, authenticated=True)


def resolve_server_identity(
    subject_id: Optional[str] = None,
    *,
    auth_token: Optional[str] = None,
    requested_role: Optional[str] = None,
) -> Identity:
    """Resolve identity from server-side mappings; never trust a role field."""

    return ServerIdentityResolver.resolve(
        subject_id,
        auth_token=auth_token,
        requested_role=requested_role,
    )


class ToolSecurityPolicy:
    """Single centralized RBAC policy for active and legacy tool names."""

    PERMISSIONS: Mapping[str, frozenset[ToolRole]] = {
        "read_document": frozenset(ToolRole),
        "search_web": frozenset(ToolRole),
        # Compatibility aliases point to the same safe implementations.
        "web_search_tool": frozenset(ToolRole),
        "query_test_db": frozenset({ToolRole.ANALYST, ToolRole.ADMIN}),
        # Compatibility alias for the historical read-only fixture.  The real
        # restricted test database tool is ``query_test_db`` below.
        "mock_database_tool": frozenset(ToolRole),
        "write_temp_file": frozenset({ToolRole.ANALYST, ToolRole.ADMIN}),
        "read_temp_file": frozenset({ToolRole.ANALYST, ToolRole.ADMIN}),
        "delete_temp_record": frozenset({ToolRole.ADMIN}),
    }
    LEGACY_TOOLS = frozenset({"system_cmd", "tool_delete_database", "delete_database_tool"})
    APPROVAL_REQUIRED_TOOLS = frozenset({"delete_temp_record"})
    # Agent identity is a second authorization axis.  An LLM may request a
    # tool, but it cannot turn a writer/finalizer into a researcher by placing
    # a different agent string in generated content; the graph supplies this
    # value server-side when it invokes the executor.
    AGENT_CAPABILITIES: Mapping[str, frozenset[str]] = {
        "researcher": frozenset({
            "search_web", "web_search_tool", "read_document", "mock_database_tool", "query_test_db"
        }),
        "planner": frozenset(),
        "writer": frozenset(),
        "finalizer": frozenset(),
        "admin_agent": frozenset({"delete_temp_record"}),
        # API approval creation can only request the approval-gated disposable
        # action; it has no generic tool execution capability.
        "api": frozenset({"delete_temp_record"}),
    }
    SENSITIVE_TOOLS = frozenset({"read_document", "query_test_db", "write_temp_file", "read_temp_file", "delete_temp_record"})

    @classmethod
    def requires_approval(cls, tool_name: str) -> bool:
        """Return whether the centrally-defined sandbox action needs HITL."""

        return tool_name in cls.APPROVAL_REQUIRED_TOOLS

    @classmethod
    def permission_for(cls, tool_name: str) -> frozenset[ToolRole] | None:
        return cls.PERMISSIONS.get(tool_name)

    @classmethod
    def authorize(
        cls, identity: Identity, tool_name: str, agent_caller: Optional[str] = None
    ) -> tuple[bool, str]:
        from config import APP_ENV, SECURITY_DEGRADED_MODE

        if not identity.authenticated:
            return False, "DENY_UNAUTHENTICATED"
        if tool_name in cls.LEGACY_TOOLS:
            return False, "DENY_LEGACY_TOOL"
        allowed_roles = cls.permission_for(tool_name)
        if allowed_roles is None:
            return False, "DENY_UNREGISTERED_TOOL"
        if identity.role not in allowed_roles:
            return False, "DENY_ROLE_NOT_PERMITTED"
        if (
            SECURITY_DEGRADED_MODE in {"restrict_sensitive_tools", "fail_closed"}
            and tool_name in cls.SENSITIVE_TOOLS
            and (APP_ENV == "production" or SECURITY_DEGRADED_MODE == "fail_closed")
        ):
            try:
                from analyzer.semantic_similarity import get_semantic_detector

                if get_semantic_detector().status().get("status") == "unavailable":
                    return False, "DENY_SECURITY_DEGRADED_SENSITIVE_TOOL"
            except Exception:
                # Failure to determine detector health is itself an unsafe
                # state for sensitive capabilities.
                return False, "DENY_SECURITY_HEALTH_UNKNOWN"
        if agent_caller:
            allowed_tools = cls.AGENT_CAPABILITIES.get(agent_caller)
            if allowed_tools is not None and tool_name not in allowed_tools:
                return False, "DENY_AGENT_CAPABILITY"
            if allowed_tools is None and APP_ENV == "production":
                return False, "DENY_UNKNOWN_AGENT"
        return True, "ALLOW"


RBACPolicy = ToolSecurityPolicy


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    implementation: Callable[..., str]
    permission: str
    resource_scope: str
    legacy: bool = False


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


_TOOL_USAGE: ContextVar[dict[str, Any] | None] = ContextVar("agentshield_tool_usage", default=None)


def reset_tool_usage() -> None:
    """Clear request-local tool accounting at a server request boundary."""
    _TOOL_USAGE.set(None)


def _consume_tool_budget(request: ToolRequest, agent_caller: str) -> None:
    """Enforce bounded request, agent, and identical-call budgets."""
    from config import (
        TOOL_MAX_CALLS_PER_AGENT,
        TOOL_MAX_CALLS_PER_REQUEST,
        TOOL_MAX_IDENTICAL_CALLS,
    )

    usage = _TOOL_USAGE.get()
    if usage is None or usage.get("request_id") != request.request_id:
        usage = {"request_id": request.request_id, "total": 0, "agents": {}, "calls": {}}
        _TOOL_USAGE.set(usage)
    fingerprint = hashlib.sha256(
        json.dumps(
            {"tool": request.tool_name, "arguments": request.arguments},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    if usage["total"] >= TOOL_MAX_CALLS_PER_REQUEST:
        raise ToolQuotaError("request tool-call budget exceeded")
    if int(usage["agents"].get(agent_caller, 0)) >= TOOL_MAX_CALLS_PER_AGENT:
        raise ToolQuotaError("agent tool-call budget exceeded")
    if int(usage["calls"].get(fingerprint, 0)) >= TOOL_MAX_IDENTICAL_CALLS:
        raise ToolQuotaError("repeated identical tool call blocked")
    usage["total"] += 1
    usage["agents"][agent_caller] = int(usage["agents"].get(agent_caller, 0)) + 1
    usage["calls"][fingerprint] = int(usage["calls"].get(fingerprint, 0)) + 1


def _decode_path(value: str) -> str:
    decoded = str(value)
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


class ToolSandbox:
    """Dedicated temporary directory with a strict path-containment invariant."""

    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        from config import TOOL_SANDBOX_PATH

        configured = root or TOOL_SANDBOX_PATH
        self.root = Path(configured) if configured else Path(tempfile.gettempdir()) / "agentshield-tool-sandbox"
        self.root = self.root.absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self._root_resolved = self.root.resolve()

    def resolve_path(self, user_path: str) -> Path:
        if not isinstance(user_path, str) or not user_path.strip():
            raise ToolArgumentError("A non-empty sandbox-relative path is required")
        decoded = _decode_path(user_path.strip())
        # Reject absolute paths before joining, including Windows paths when
        # tests run on a POSIX host and vice versa.
        if Path(decoded).is_absolute() or PureWindowsPath(decoded).is_absolute() or PureWindowsPath(decoded).drive:
            raise ToolArgumentError("Absolute paths are not permitted")
        candidate = (self.root / decoded).resolve(strict=False)
        try:
            candidate.relative_to(self._root_resolved)
        except ValueError as exc:
            raise ToolArgumentError("Path escapes the dedicated tool sandbox") from exc
        return candidate

    def write_text(self, user_path: str, content: str) -> str:
        if not isinstance(content, str) or len(content) > 32_000:
            raise ToolArgumentError("Temporary file content is oversized")
        path = self.resolve_path(user_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="")
        return json.dumps({"status": "OK", "path": str(path.relative_to(self._root_resolved))})

    def read_text(self, user_path: str) -> str:
        path = self.resolve_path(user_path)
        if not path.is_file():
            return json.dumps({"status": "NOT_FOUND", "path": str(path.relative_to(self._root_resolved))})
        with path.open(encoding="utf-8") as handle:
            text = handle.read(64_001)
        if len(text) > 64_000:
            raise ToolArgumentError("Sandbox document exceeds the bounded read limit")
        return text


class TestDatabase:
    """Disposable SQLite database used only for test/sandbox records."""

    def __init__(self, sandbox: ToolSandbox | None = None) -> None:
        self.sandbox = sandbox or get_tool_sandbox()
        self.path = self.sandbox.root / "tool_test.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS temp_records ("
                "record_id TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.executemany(
                "INSERT OR IGNORE INTO temp_records(record_id, value) VALUES (?, ?)",
                [("temp-1", "disposable development record"), ("temp-2", "sandbox fixture")],
            )

    def query(self, search: str) -> str:
        pattern = f"%{search}%"
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_id, value FROM temp_records "
                "WHERE record_id LIKE ? OR value LIKE ? ORDER BY record_id",
                (pattern, pattern),
            ).fetchall()
        return json.dumps([dict(row) for row in rows])

    def delete(self, record_id: str) -> str:
        if not isinstance(record_id, str) or not record_id.startswith("temp-"):
            raise ToolArgumentError("Only disposable temp-* records may be deleted")
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM temp_records WHERE record_id = ?", (record_id,)
            )
        return json.dumps({"status": "DELETED" if cursor.rowcount else "NOT_FOUND", "record_id": record_id})


_TOOL_SANDBOX: ToolSandbox | None = None
_TEST_DATABASE: TestDatabase | None = None


def get_tool_sandbox() -> ToolSandbox:
    global _TOOL_SANDBOX
    if _TOOL_SANDBOX is None:
        _TOOL_SANDBOX = ToolSandbox()
    return _TOOL_SANDBOX


def get_test_database() -> TestDatabase:
    global _TEST_DATABASE
    if _TEST_DATABASE is None:
        _TEST_DATABASE = TestDatabase(get_tool_sandbox())
    return _TEST_DATABASE


def search_web_impl(query: str) -> str:
    """Perform explicit, bounded web search with a no-egress fallback."""

    if not query or not query.strip():
        return "No search query provided."
    query = query.strip()
    from config import LIVE_WEB_SEARCH_ENABLED, WEB_SEARCH_TIMEOUT_SECONDS

    if not LIVE_WEB_SEARCH_ENABLED:
        return (
            "OFFLINE SEARCH FALLBACK (live web egress is disabled). "
            "No query was transmitted to an external search provider."
        )
    try:
        from ddgs import DDGS

        with DDGS(timeout=WEB_SEARCH_TIMEOUT_SECONDS) as ddgs:
            results = list(ddgs.text(query, region="us-en", max_results=4))
        if results:
            return "\n\n".join(
                f"Source [{index}]: {item.get('title', 'Untitled')}\n"
                f"Summary: {item.get('body', 'No snippet available')}\n"
                f"URL: {item.get('href', '#')}"
                for index, item in enumerate(results, 1)
            )
    except Exception as exc:  # network/rate limits must not break the workflow
        logger.info("bounded web search fallback: %s", exc.__class__.__name__)
    return (
        "OFFLINE SEARCH FALLBACK (no live result fetched). "
        "The query is withheld from fallback output; this is not evidence of "
        "a completed external search."
    )


def read_document_impl(path: str) -> str:
    return get_tool_sandbox().read_text(path)


def query_test_db_impl(search: str) -> str:
    return get_test_database().query(search)


def write_temp_file_impl(path: str, content: str) -> str:
    return get_tool_sandbox().write_text(path, content)


def read_temp_file_impl(path: str) -> str:
    return get_tool_sandbox().read_text(path)


def delete_temp_record_impl(record_id: str) -> str:
    return get_test_database().delete(record_id)


ACTIVE_TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    "read_document": ToolDefinition("read_document", read_document_impl, "USER", "dedicated temporary sandbox"),
    "search_web": ToolDefinition("search_web", search_web_impl, "USER", "bounded web provider output"),
    "web_search_tool": ToolDefinition("web_search_tool", search_web_impl, "USER", "bounded web provider output"),
    "query_test_db": ToolDefinition("query_test_db", query_test_db_impl, "ANALYST", "disposable test database"),
        "mock_database_tool": ToolDefinition("mock_database_tool", query_test_db_impl, "USER", "disposable test database (compatibility alias)"),
    "write_temp_file": ToolDefinition("write_temp_file", write_temp_file_impl, "ANALYST", "dedicated temporary sandbox"),
    "read_temp_file": ToolDefinition("read_temp_file", read_temp_file_impl, "ANALYST", "dedicated temporary sandbox"),
    "delete_temp_record": ToolDefinition("delete_temp_record", delete_temp_record_impl, "ADMIN", "disposable test database records"),
}


def get_tool_definition(tool_name: str) -> ToolDefinition | None:
    return ACTIVE_TOOL_REGISTRY.get(tool_name)


def is_active_tool(tool_name: str) -> bool:
    return tool_name in ACTIVE_TOOL_REGISTRY


class ArgumentSecurityScanner:
    """Thin public adapter over the canonical :class:`hooks.ToolGuard` scan."""

    @staticmethod
    def scan(tool_name: str, arguments: Mapping[str, Any]):
        from hooks.tool_guard import ToolGuard

        return ToolGuard._scan_args(dict(arguments), tool_name=tool_name)


def scan_tool_arguments(tool_name: str, arguments: Mapping[str, Any]):
    return ArgumentSecurityScanner.scan(tool_name, arguments)


class SecureToolExecutor:
    """Canonical identity → RBAC → argument scan → execute → output scan flow."""

    def execute(
        self,
        request: ToolRequest,
        *,
        identity: Identity | None = None,
        agent_caller: str = "unknown_agent",
        source_type: str | None = None,
        implementation: Callable[..., Any] | None = None,
        raise_on_block: bool = False,
        enforce_registry: bool = True,
        approved_execution: bool = False,
        approval_id: Optional[str] = None,
    ) -> ToolResult:
        from hooks.tool_guard import (
            ToolBlockedError,
            ToolGuard,
            ToolOutputBlockedError,
            get_current_identity,
        )

        started = time.perf_counter()
        resolved_identity = identity or get_current_identity()
        definition = get_tool_definition(request.tool_name)
        selected_implementation = implementation or (definition.implementation if definition else None)
        if getattr(selected_implementation, "_agentshield_guarded", False):
            # A decorated compatibility seam can be injected by a development
            # test.  Unwrap it once so this executor remains the sole guard.
            selected_implementation = getattr(selected_implementation, "__wrapped__", selected_implementation)
        source = source_type or (
            "web"
            if request.tool_name in {"search_web", "web_search_tool"}
            else "database"
            if "db" in request.tool_name or "record" in request.tool_name
            else "filesystem"
            if "file" in request.tool_name or "document" in request.tool_name
            else "tool_output"
        )

        try:
            pre_event = ToolGuard.pre_tool_execution(
                request.tool_name,
                agent_caller,
                request.arguments,
                source_type=source,
                identity=resolved_identity,
                tool_call_id=request.tool_call_id,
                enforce_registry=enforce_registry,
                request_id=request.request_id,
            )
            _, safe_args, _ = ToolGuard._scan_args(request.arguments, tool_name=request.tool_name)
        except ToolBlockedError as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            from hooks.tool_guard import TOOL_EXECUTION_AUDIT_LOG

            audit_event = None
            if TOOL_EXECUTION_AUDIT_LOG and TOOL_EXECUTION_AUDIT_LOG[-1].tool_call_id == request.tool_call_id:
                audit_event = TOOL_EXECUTION_AUDIT_LOG[-1]
                audit_event.latency_ms = elapsed_ms
            result = ToolResult(
                tool_call_id=request.tool_call_id,
                request_id=request.request_id,
                tool_name=request.tool_name,
                status="DENIED",
                security_decision="DENY",
                timestamp=_utc_now(),
                subject_id=resolved_identity.subject_id,
                resolved_role=resolved_identity.role,
                authorization_decision=getattr(audit_event, "authorization_decision", None) or "DENY",
                argument_security_decision=getattr(audit_event, "argument_security_decision", None) or "BLOCKED",
                execution_status="NOT_EXECUTED",
                output_security_decision="NOT_RUN",
                reason=str(exc),
            )
            if raise_on_block:
                raise
            return result

        if selected_implementation is None:
            # This is an active-registry invariant, not a shell-like fallback.
            error = ToolBlockedError(
                request.tool_name,
                agent_caller,
                "Tool is not registered in the active safe tool registry",
                ["TOOL_NOT_REGISTERED"],
            )
            result = ToolResult(
                tool_call_id=request.tool_call_id,
                request_id=request.request_id,
                tool_name=request.tool_name,
                status="DENIED",
                security_decision="DENY",
                timestamp=_utc_now(),
                subject_id=resolved_identity.subject_id,
                resolved_role=resolved_identity.role,
                authorization_decision="DENY",
                argument_security_decision="NOT_RUN",
                execution_status="NOT_EXECUTED",
                output_security_decision="NOT_RUN",
                reason=str(error),
            )
            if raise_on_block:
                raise error
            return result

        try:
            # Only active, registry-enforced capabilities participate in the
            # request budget. Historical decorator fixtures are not exposed
            # by the runtime and should not share accounting state with a real
            # request merely because a test reuses an illustrative ID.
            if enforce_registry:
                _consume_tool_budget(request, agent_caller)
        except ToolQuotaError as exc:
            # The pre-execution event has already recorded identity and schema
            # validation.  Emit a correlated denial instead of silently
            # stopping a loop.
            quota_event = pre_event.model_copy(
                update={
                    "pre_exec_status": "BLOCKED",
                    "status": "BLOCKED",
                    "mitigated_threat": "TOOL_QUOTA:" + str(exc),
                    "pre_exec_flags": list(pre_event.pre_exec_flags) + ["TOOL_QUOTA_EXCEEDED"],
                    "execution_status": "NOT_EXECUTED",
                }
            )
            ToolGuard._emit_audit(quota_event)
            result = ToolResult(
                tool_call_id=request.tool_call_id,
                request_id=request.request_id,
                tool_name=request.tool_name,
                status="DENIED",
                security_decision="BLOCK",
                timestamp=_utc_now(),
                subject_id=resolved_identity.subject_id,
                resolved_role=resolved_identity.role,
                authorization_decision="ALLOW",
                argument_security_decision="ALLOW",
                execution_status="NOT_EXECUTED",
                output_security_decision="NOT_RUN",
                reason="Tool call stopped by request budget",
            )
            if raise_on_block:
                raise ToolBlockedError(request.tool_name, agent_caller, result.reason or "Tool quota", ["TOOL_QUOTA_EXCEEDED"])
            return result

        # Approval is evaluated only after the normal identity, RBAC and
        # argument checks.  The pending record is durable; no implementation
        # call can occur on this path.
        if ToolSecurityPolicy.requires_approval(request.tool_name) and not approved_execution:
            from security.hitl_approvals import HITLApprovalService

            return HITLApprovalService().create_pending(
                request=request,
                identity=resolved_identity,
                agent_caller=agent_caller,
                source_type=source,
                implementation=implementation,
                pre_event=pre_event,
            )

        try:
            execution_status = "EXECUTED"
            try:
                raw_output = selected_implementation(**safe_args)
            except Exception as exc:
                # Exception text can contain remote/tool data.  Send only a
                # neutral diagnostic through the mandatory output guard.
                raw_output = f"Tool execution failed safely ({exc.__class__.__name__})."
                execution_status = "FAILED"
            safe_output, _event = ToolGuard.post_tool_execution(
                request.tool_name,
                agent_caller,
                str(raw_output),
                pre_event,
                source_type=source,
                identity=resolved_identity,
                tool_call_id=request.tool_call_id,
                execution_status=execution_status,
                latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
            )
            if execution_status == "FAILED" and raise_on_block:
                raise ToolSecurityError("Tool execution failed safely")
            return ToolResult(
                tool_call_id=request.tool_call_id,
                request_id=request.request_id,
                tool_name=request.tool_name,
                status="FAILED" if execution_status == "FAILED" else "COMPLETED",
                output=safe_output,
                security_decision="ALLOW",
                timestamp=_utc_now(),
                subject_id=resolved_identity.subject_id,
                resolved_role=resolved_identity.role,
                authorization_decision="ALLOW",
                argument_security_decision=pre_event.argument_security_decision or "ALLOW",
                execution_status=execution_status,
                output_security_decision="ALLOW",
                approval_id=approval_id,
            )
        except ToolOutputBlockedError as exc:
            result = ToolResult(
                tool_call_id=request.tool_call_id,
                request_id=request.request_id,
                tool_name=request.tool_name,
                status="BLOCKED",
                security_decision="BLOCK",
                timestamp=_utc_now(),
                subject_id=resolved_identity.subject_id,
                resolved_role=resolved_identity.role,
                authorization_decision="ALLOW",
                argument_security_decision=pre_event.argument_security_decision or "ALLOW",
                execution_status="EXECUTED",
                output_security_decision="BLOCK",
                approval_id=approval_id,
                reason=str(exc),
            )
            if raise_on_block:
                raise
            return result
        except Exception as exc:
            # Do not expose exception text to agents or telemetry.
            from hooks.tool_guard import TOOL_EXECUTION_AUDIT_LOG

            if TOOL_EXECUTION_AUDIT_LOG and TOOL_EXECUTION_AUDIT_LOG[-1].tool_call_id == request.tool_call_id:
                TOOL_EXECUTION_AUDIT_LOG[-1].execution_status = "FAILED"
                TOOL_EXECUTION_AUDIT_LOG[-1].output_security_decision = "FAIL_CLOSED"
            return ToolResult(
                tool_call_id=request.tool_call_id,
                request_id=request.request_id,
                tool_name=request.tool_name,
                status="FAILED",
                security_decision="FAIL_CLOSED",
                timestamp=_utc_now(),
                subject_id=resolved_identity.subject_id,
                resolved_role=resolved_identity.role,
                authorization_decision="ALLOW",
                argument_security_decision=pre_event.argument_security_decision or "ALLOW",
                execution_status="FAILED",
                output_security_decision="FAIL_CLOSED",
                approval_id=approval_id,
                reason=f"Tool execution failed safely ({exc.__class__.__name__})",
            )
        finally:
            # The event's latency is set at the point where the output
            # decision is known; this finally keeps the timing measurement
            # explicit for future executor instrumentation.
            _ = round((time.perf_counter() - started) * 1000.0, 2)


ToolExecutor = SecureToolExecutor


def execute_tool_request(
    request: ToolRequest,
    *,
    identity: Identity | None = None,
    agent_caller: str = "unknown_agent",
    source_type: str | None = None,
    implementation: Callable[..., Any] | None = None,
) -> ToolResult:
    """Convenience entry point returning a structured fail-closed result."""

    return SecureToolExecutor().execute(
        request,
        identity=identity,
        agent_caller=agent_caller,
        source_type=source_type,
        implementation=implementation,
    )


__all__ = [
    "ACTIVE_TOOL_REGISTRY",
    "AuthenticatedIdentity",
    "ArgumentSecurityScanner",
    "Identity",
    "IdentityContext",
    "Role",
    "SecureToolExecutor",
    "ToolExecutor",
    "ServerIdentityResolver",
    "TestDatabase",
    "ToolArgumentError",
    "ToolQuotaError",
    "ToolDefinition",
    "ToolRequest",
    "ToolResult",
    "ToolRole",
    "ToolSandbox",
    "ToolSecurityPolicy",
    "RBACPolicy",
    "execute_tool_request",
    "get_test_database",
    "get_tool_definition",
    "get_tool_sandbox",
    "is_active_tool",
    "reset_tool_usage",
    "resolve_server_identity",
    "scan_tool_arguments",
    "validate_tool_arguments",
    "search_web_impl",
    "read_document_impl",
    "query_test_db_impl",
    "write_temp_file_impl",
    "read_temp_file_impl",
    "delete_temp_record_impl",
]
