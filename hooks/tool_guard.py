"""Mandatory pre-execution and untrusted-output guard for active tools.

Tool request validation remains a separate boundary from output trust. A tool
that executes successfully still returns *external untrusted* content until
``UntrustedContentGuard`` has evaluated it with the canonical security stack.
"""

from __future__ import annotations

import datetime
import functools
import inspect
import re
from pathlib import PureWindowsPath
from urllib.parse import unquote
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from hooks.request_context import (
    ContextAuditLog,
    current_identity,
    current_request_id,
    reset_identity,
    reset_request_id,
    set_identity,
    set_request_id,
)
from policy.sanitizer import InputSanitizer
from schema.interception import ToolExecutionEvent
from state import Decision, TrustLevel, UntrustedContent


TOOL_EXECUTION_AUDIT_LOG: ContextAuditLog[ToolExecutionEvent] = ContextAuditLog(
    "agentshield_tool_audit"
)


def set_current_request_id(request_id: str) -> None:
    """Set request correlation for tool calls made by the active workflow."""
    set_request_id(request_id)


def set_current_identity(identity: Any) -> None:
    """Set the server-resolved identity for the active workflow/request."""
    set_identity(identity)


def get_current_identity():
    """Return the current server identity, defaulting to a development USER."""
    identity = current_identity()
    if identity is None:
        from security.tool_security import resolve_server_identity

        identity = resolve_server_identity("user_default")
        set_identity(identity)
    return identity


def reset_current_identity() -> None:
    """Clear request-local identity so a later request cannot inherit a role."""
    reset_identity()


def reset_tool_audit_log() -> None:
    """Clear in-memory events without invalidating imported references."""
    TOOL_EXECUTION_AUDIT_LOG.clear()


def reset_current_request_id() -> None:
    """Reset request correlation in the active context."""
    reset_request_id()


class ToolBlockedError(RuntimeError):
    """Raised when a pre-execution or output security boundary blocks a tool."""

    def __init__(self, tool_name: str, agent_caller: str, threat: str, flags: List[str]) -> None:
        self.tool_name = tool_name
        self.agent_caller = agent_caller
        self.threat = threat
        self.flags = flags
        super().__init__(
            f"[TOOL BLOCKED] Tool '{tool_name}' blocked for agent '{agent_caller}'. "
            f"Threat: {threat} | Flags: {flags}"
        )


class ToolOutputBlockedError(ToolBlockedError):
    """A tool ran, but its untrusted output was not safe for agent consumption."""

    def __init__(self, tool_name: str, agent_caller: str, result: Any) -> None:
        self.result = result
        super().__init__(tool_name, agent_caller, result.reason, list(result.findings))


PRE_EXEC_PATTERNS: List[Tuple[re.Pattern, str, bool]] = [
    (re.compile(r"DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|--\s*$|'\\s*OR\\s*'1'='1|;\s*DROP|xp_cmdshell", re.IGNORECASE), "TOOL_INPUT:SQL_INJECTION", True),
    (re.compile(r"\.\.[/\\\\]", re.IGNORECASE), "TOOL_INPUT:PATH_TRAVERSAL", True),
    (re.compile(r"[|;&`]|\$\(|\$\{|>\s*/|<\s*/dev/|\brm\s+-rf\b|format\s+c:|del\s+/[fqs]", re.IGNORECASE), "TOOL_INPUT:SHELL_METACHARACTER", True),
    (re.compile(r"\bimport\s+(os|sys|subprocess|shutil|socket|ctypes|pickle|importlib|pty|ftplib|smtplib)\b", re.IGNORECASE), "TOOL_INPUT:UNAUTHORIZED_IMPORT", True),
    (re.compile(r"127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|::1", re.IGNORECASE), "TOOL_INPUT:SSRF_INTERNAL_IP", True),
    (re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts)|system\s+(override|bypass|disable)|jailbreak|disregard\s+(your\s+)?(rules|safety)", re.IGNORECASE), "TOOL_INPUT:PROMPT_INJECTION_ARG", False),
]


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _redact_args(args: Dict[str, Any]) -> Dict[str, Any]:
    """Keep audit telemetry useful without persisting credential-like values."""
    sensitive_tokens = ("secret", "password", "token", "api_key", "authorization")
    redacted: Dict[str, Any] = {}
    for key, value in args.items():
        if any(token in str(key).lower() for token in sensitive_tokens):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, str) and len(value) > 4096:
            redacted[key] = f"[TRUNCATED:{len(value)}]"
        else:
            redacted[key] = value
    return redacted


class ToolGuard:
    """Enforce tool-call validation and canonical indirect-output containment."""

    @classmethod
    def pre_tool_execution(
        cls,
        tool_name: str,
        agent_caller: str,
        args: Dict[str, Any],
        *,
        source_type: str = "tool_output",
        identity: Any = None,
        tool_call_id: Optional[str] = None,
        enforce_registry: bool = True,
        request_id: Optional[str] = None,
    ) -> ToolExecutionEvent:
        timestamp = _utc_now()
        flags, _sanitized_args, has_hard_block = cls._scan_args(
            args, tool_name=tool_name, enforce_schema=enforce_registry
        )
        argument_security_decision = "BLOCKED" if has_hard_block else "SANITIZED" if flags else "ALLOW"
        request_id = str(request_id or current_request_id())
        resolved_identity = identity or get_current_identity()
        from security.tool_security import ToolSecurityPolicy

        allowed, authorization_reason = ToolSecurityPolicy.authorize(
            resolved_identity, tool_name, agent_caller=agent_caller
        )
        if not enforce_registry and tool_name not in ToolSecurityPolicy.LEGACY_TOOLS:
            # Historical/development decorators remain usable in unit tests,
            # while SecureToolExecutor always enforces the active registry.
            allowed, authorization_reason = True, "DEVELOPMENT_WRAPPER"
        authorization_decision = "ALLOW" if allowed else "DENY"
        if not allowed:
            flags.append(f"TOOL_AUTH:{authorization_reason}")
            has_hard_block = True
        event = ToolExecutionEvent(
            tool_name=tool_name,
            agent_caller=agent_caller,
            timestamp=timestamp,
            raw_args=_redact_args(args),
            pre_exec_status="BLOCKED" if has_hard_block else "SANITIZED" if flags else "PASSED",
            post_exec_status="N/A" if has_hard_block else "PENDING",
            status="BLOCKED" if has_hard_block else "SANITIZED" if flags else "PASSED",
            mitigated_threat=(f"Tool security flags: {flags}" if flags else None),
            pre_exec_flags=flags,
            post_exec_flags=[],
            output_sanitized=False,
            event_id=f"tool-event-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            tool_execution_id=f"tool-{uuid.uuid4().hex[:12]}",
            source_type=source_type,
            source_name=tool_name,
            trust_level=TrustLevel.USER_CONTROLLED.value,
            tool_call_id=tool_call_id,
            subject_id=getattr(resolved_identity, "subject_id", None),
            resolved_role=getattr(getattr(resolved_identity, "role", None), "value", getattr(resolved_identity, "role", None)),
            authorization_decision=authorization_decision,
            argument_security_decision=argument_security_decision,
            execution_status="NOT_EXECUTED" if has_hard_block else "PENDING",
            output_security_decision="NOT_RUN",
        )
        if has_hard_block:
            cls._emit_audit(event)
            raise ToolBlockedError(tool_name, agent_caller, event.mitigated_threat or "Tool input blocked", flags)
        return event

    @classmethod
    def post_tool_execution(
        cls,
        tool_name: str,
        agent_caller: str,
        raw_output: str,
        pre_event: ToolExecutionEvent,
        *,
        source_type: str = "tool_output",
        identity: Any = None,
        tool_call_id: Optional[str] = None,
        execution_status: str = "EXECUTED",
        latency_ms: Optional[float] = None,
    ) -> Tuple[str, ToolExecutionEvent]:
        """Inspect raw external output before returning any text to the caller."""
        from hooks.untrusted_content_guard import UntrustedContentGuard

        content = UntrustedContent(
            content_id=f"content-{uuid.uuid4().hex[:12]}",
            request_id=pre_event.request_id or current_request_id(),
            source_type=source_type,
            source_name=tool_name,
            text=str(raw_output),
            timestamp=_utc_now(),
            provenance={"tool_execution_id": pre_event.tool_execution_id, "agent_caller": agent_caller},
            trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
        )
        result = UntrustedContentGuard.inspect(content, tool_execution_id=pre_event.tool_execution_id)
        blocked = result.decision in {Decision.BLOCK, Decision.REVIEW}
        post_status = (
            "BLOCKED" if result.decision == Decision.BLOCK else
            "REVIEW_REQUIRED" if result.decision == Decision.REVIEW else
            "SANITIZED" if result.decision == Decision.SANITIZE else "PASSED"
        )
        event = ToolExecutionEvent(
            tool_name=tool_name,
            agent_caller=agent_caller,
            timestamp=pre_event.timestamp,
            raw_args=pre_event.raw_args,
            pre_exec_status=pre_event.pre_exec_status,
            post_exec_status=post_status,
            status=("BLOCKED" if blocked else "SANITIZED" if result.decision == Decision.SANITIZE else pre_event.status),
            mitigated_threat=(result.reason if result.findings else pre_event.mitigated_threat),
            pre_exec_flags=pre_event.pre_exec_flags,
            post_exec_flags=result.findings,
            output_sanitized=result.decision == Decision.SANITIZE,
            event_id=f"tool-event-{uuid.uuid4().hex[:12]}",
            request_id=result.request_id,
            tool_execution_id=pre_event.tool_execution_id,
            content_id=result.content_id,
            source_type=result.source_type,
            source_name=result.source_name,
            trust_level=result.trust_level.value,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            decision=result.decision,
            findings=result.findings,
            transforms=result.transforms,
            latency_ms=max(result.latency_ms, float(latency_ms or 0.0)),
            tool_call_id=tool_call_id or pre_event.tool_call_id,
            subject_id=pre_event.subject_id or getattr(identity, "subject_id", None),
            resolved_role=pre_event.resolved_role or getattr(getattr(identity, "role", None), "value", getattr(identity, "role", None)),
            authorization_decision=pre_event.authorization_decision,
            argument_security_decision=pre_event.argument_security_decision,
            execution_status=execution_status,
            output_security_decision=result.decision.value,
        )
        cls._emit_audit(event)
        if blocked or not result.safe_content:
            raise ToolOutputBlockedError(tool_name, agent_caller, result)
        return result.safe_content, event

    @classmethod
    def record_pending_approval(
        cls, pre_event: ToolExecutionEvent, approval_id: str
    ) -> ToolExecutionEvent:
        """Persist a correlated guard audit entry for a paused HITL action."""

        event = pre_event.model_copy(
            update={
                "post_exec_status": "NOT_RUN",
                "status": "PENDING_APPROVAL",
                "execution_status": "REQUIRES_APPROVAL",
                "output_security_decision": "NOT_RUN",
                "mitigated_threat": f"Pending HITL approval: {approval_id}",
            }
        )
        cls._emit_audit(event)
        return event

    @classmethod
    def _scan_args(
        cls,
        args: Dict[str, Any],
        tool_name: Optional[str] = None,
        *,
        enforce_schema: bool = True,
    ) -> Tuple[List[str], Dict[str, Any], bool]:
        flags: List[str] = []
        sanitized_args: Dict[str, Any] = dict(args)
        has_hard_block = False
        # Caller-controlled role claims are never forwarded to tool code.
        # Discard them before strict validation while retaining an audit flag.
        for key in list(sanitized_args):
            if str(key).lower() in {"user_role", "role", "requested_role"}:
                flags.append("TOOL_INPUT:ROLE_OVERRIDE_IGNORED")
                sanitized_args.pop(key, None)
        if tool_name and enforce_schema:
            try:
                from security.tool_security import ToolArgumentError, validate_tool_arguments

                sanitized_args = validate_tool_arguments(tool_name, sanitized_args)
            except ToolArgumentError:
                return ["TOOL_INPUT:SCHEMA_VALIDATION"], {}, True
        for key, value in sanitized_args.items():
            if not isinstance(value, str):
                continue
            lowered_key = str(key).lower()
            if len(value) > 32_000:
                flags.append("TOOL_INPUT:ARGUMENT_TOO_LARGE")
                has_hard_block = True
            if lowered_key in {"path", "file", "filename", "document", "filepath", "target_path"}:
                decoded = value
                for _ in range(3):
                    next_value = unquote(decoded)
                    if next_value == decoded:
                        break
                    decoded = next_value
                if (
                    decoded.startswith(("/", "\\"))
                    or bool(PureWindowsPath(decoded).drive)
                    or bool(PureWindowsPath(decoded).is_absolute())
                    or re.search(r"(?:^|[/\\])\.\.(?:[/\\]|$)", decoded)
                ):
                    flags.append("TOOL_INPUT:PATH_ESCAPE")
                    has_hard_block = True
            for pattern, flag, hard in PRE_EXEC_PATTERNS:
                if pattern.search(value):
                    if flag not in flags:
                        flags.append(flag)
                    has_hard_block = has_hard_block or hard
                    if not hard:
                        sanitized_args[key] = InputSanitizer.sanitize(value)
            # Reuse the canonical bounded normalizer for encoded argument
            # representations instead of creating a second decoder/detector.
            try:
                from gateway.input_normalizer import normalize_input

                normalized = normalize_input(value)
                representations = normalized.get("metadata", {}).get("representations", [])
            except Exception:
                representations = []
            for representation in representations:
                candidate = representation.get("text", "")
                if not candidate or candidate == value:
                    continue
                for pattern, flag, hard in PRE_EXEC_PATTERNS:
                    if pattern.search(candidate):
                        encoded_flag = f"TOOL_INPUT:ENCODED_{flag.split(':', 1)[-1]}"
                        if encoded_flag not in flags:
                            flags.append(encoded_flag)
                        # An encoded instruction is not safe to forward as a
                        # search/database argument even when the ingress
                        # policy classifies the plain-language pattern as a
                        # soft sanitization finding.
                        has_hard_block = has_hard_block or hard or flag.endswith("PROMPT_INJECTION_ARG")
                        if not hard:
                            sanitized_args[key] = InputSanitizer.sanitize(value)
        return flags, sanitized_args, has_hard_block

    @classmethod
    def _emit_audit(cls, event: ToolExecutionEvent) -> None:
        TOOL_EXECUTION_AUDIT_LOG.append(event)
        try:
            from logging.alerting import AlertEngine
            from logging.event_logger import EventLogger

            EventLogger.log_tool_event(event, request_id=event.request_id or current_request_id())
            AlertEngine.evaluate_tool_event(event, request_id=event.request_id or current_request_id())
        except Exception:
            pass


def guarded_tool(tool_name: str, agent_caller: str = "unknown_agent", *, source_type: str = "tool_output") -> Callable:
    """Wrap a textual tool through the canonical secure executor.

    Unknown decorator names remain available as development fixtures for the
    historical tests; active registry names receive server-side RBAC.
    """

    def _decorator(tool_fn: Callable) -> Callable:
        @functools.wraps(tool_fn)
        def _wrapper(*args, **kwargs) -> str:
            from security.tool_security import (
                ACTIVE_TOOL_REGISTRY,
                SecureToolExecutor,
                ToolRequest,
                ToolSecurityPolicy,
            )

            caller = kwargs.pop("_agent_caller", agent_caller)
            try:
                bound = inspect.signature(tool_fn).bind(*args, **kwargs)
                bound.apply_defaults()
                call_args: Dict[str, Any] = dict(bound.arguments)
            except (TypeError, ValueError):
                call_args = {f"arg_{index}": value for index, value in enumerate(args)}
                call_args.update(kwargs)
            request = ToolRequest(
                request_id=current_request_id(),
                tool_call_id=f"call-{uuid.uuid4().hex[:12]}",
                tool_name=tool_name,
                arguments=call_args,
            )
            result = SecureToolExecutor().execute(
                request,
                identity=get_current_identity(),
                agent_caller=caller,
                source_type=source_type,
                implementation=tool_fn,
                raise_on_block=True,
                enforce_registry=(
                    tool_name in ACTIVE_TOOL_REGISTRY
                    or tool_name in ToolSecurityPolicy.LEGACY_TOOLS
                ),
            )
            return result.output or ""

        _wrapper._agentshield_guarded = True
        return _wrapper

    return _decorator
