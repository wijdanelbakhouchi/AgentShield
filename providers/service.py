"""Provider selection, bounded invocation, status and explicit fallback.

The security pipeline intentionally does not depend on this module.  This
boundary only decides how an already-approved agent prompt is generated.  A
missing or failing provider always becomes an observable demo/fallback result;
it is never reported as a successful external LLM response.
"""

from __future__ import annotations

import contextvars
import dataclasses
import json
import logging
import os
import queue
import re
import threading
import time
from typing import Any, Dict, Optional, Type


SUPPORTED_PROVIDERS = ("openai", "gemini", "groq", "ollama")
STATUS_READY = "ready"
STATUS_CONFIGURED_BUT_UNVERIFIED = "configured_but_unverified"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"
STATUS_DEMO_FALLBACK = "demo_fallback"

LOGGER = logging.getLogger("agentshield.provider")
_PACING_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0

# Structured-output contracts are provider capabilities, not agent-specific
# behavior. Groq's gpt-oss endpoint rejects forced tool calls, while its
# supported JSON mode can be locally Pydantic-validated by LangChain.
STRUCTURED_OUTPUT_METHODS: Dict[str, str] = {"groq": "json_mode"}
MAX_STRUCTURED_FORMAT_RETRIES = 1


class ProviderInvocationError(RuntimeError):
    """A provider call failed in a way safe for callers to handle."""

    def __init__(self, provider: str, reason: str, *, timeout: bool = False):
        self.provider = provider
        self.reason = reason
        self.timeout = timeout
        super().__init__(f"{provider} provider call failed ({reason})")


@dataclasses.dataclass(frozen=True)
class ProviderStatusSnapshot:
    provider: str
    status: str
    model: Optional[str] = None
    configured: bool = False
    runtime_verified: bool = False
    mode: str = "demo"
    real_llm: bool = False
    latency_ms: Optional[float] = None
    last_verified_at: Optional[float] = None
    error: Optional[str] = None
    fallback_reason: Optional[str] = None
    failed_provider: Optional[str] = None
    http_status: Optional[int] = None
    retry_after_seconds: Optional[float] = None
    provider_error_type: Optional[str] = None
    provider_error_code: Optional[str] = None
    provider_exception_types: Optional[list[str]] = None
    sanitized_error_message: Optional[str] = None
    request_diagnostics: Optional[Dict[str, Any]] = None
    timeout_seconds: float = 20.0

    def as_dict(self) -> Dict[str, Any]:
        """Return a secret-free JSON-compatible status object."""
        result: Dict[str, Any] = {
            "status": self.status,
            "configured": self.configured,
            "runtime_verified": self.runtime_verified,
            "mode": self.mode,
            "real_llm": self.real_llm,
            "timeout_seconds": self.timeout_seconds,
        }
        if self.model:
            result["model"] = self.model
        if self.latency_ms is not None:
            result["latency_ms"] = self.latency_ms
        if self.last_verified_at is not None:
            result["last_verified_at"] = self.last_verified_at
        if self.error:
            result["error"] = self.error
        if self.fallback_reason:
            result["fallback_reason"] = self.fallback_reason
        if self.http_status is not None:
            result["http_status"] = self.http_status
        if self.retry_after_seconds is not None:
            result["retry_after_seconds"] = self.retry_after_seconds
        if self.provider_error_type:
            result["provider_error_type"] = self.provider_error_type
        if self.provider_error_code:
            result["provider_error_code"] = self.provider_error_code
        if self.provider_exception_types:
            result["provider_exception_types"] = self.provider_exception_types
        if self.sanitized_error_message:
            result["sanitized_error_message"] = self.sanitized_error_message
        if self.request_diagnostics:
            result["request_diagnostics"] = self.request_diagnostics
        return result


_VERIFICATION_LOCK = threading.Lock()
_RUNTIME_PROVIDER_REGISTRY: Dict[str, Dict[str, Any]] = {}


def _record_provider_success(provider: str, model: Optional[str], latency_ms: Optional[float] = None) -> None:
    if not provider or provider == "fallback":
        return
    with _VERIFICATION_LOCK:
        _RUNTIME_PROVIDER_REGISTRY[provider] = {
            "runtime_verified": True,
            "model": model,
            "last_verified_at": time.time(),
            "last_latency_ms": latency_ms,
            "last_error": None,
            "last_error_at": None,
            "http_status": None,
            "retry_after_seconds": None,
            "provider_error_type": None,
            "provider_error_code": None,
            "sanitized_error_message": None,
        }


def _record_provider_failure(
    provider: str,
    reason: str,
    *,
    model: Optional[str] = None,
    http_status: Optional[int] = None,
    retry_after_seconds: Optional[float] = None,
    provider_error_type: Optional[str] = None,
    provider_error_code: Optional[str] = None,
    sanitized_error_message: Optional[str] = None,
) -> None:
    if not provider or provider == "fallback":
        return
    with _VERIFICATION_LOCK:
        _RUNTIME_PROVIDER_REGISTRY[provider] = {
            "runtime_verified": False,
            "model": model,
            "last_verified_at": None,
            "last_latency_ms": None,
            "last_error": reason,
            "last_error_at": time.time(),
            "http_status": http_status,
            "retry_after_seconds": retry_after_seconds,
            "provider_error_type": provider_error_type,
            "provider_error_code": provider_error_code,
            "sanitized_error_message": sanitized_error_message,
        }


def _get_provider_runtime_state(provider: str) -> Optional[Dict[str, Any]]:
    with _VERIFICATION_LOCK:
        state = _RUNTIME_PROVIDER_REGISTRY.get(provider)
        return dict(state) if state is not None else None


def reset_runtime_provider_state() -> None:
    """Clear process-level runtime verification state."""
    with _VERIFICATION_LOCK:
        _RUNTIME_PROVIDER_REGISTRY.clear()


_last_snapshot: contextvars.ContextVar[ProviderStatusSnapshot] = contextvars.ContextVar(
    "agentshield_last_provider_snapshot",
    default=ProviderStatusSnapshot(
        provider="fallback",
        status=STATUS_DEMO_FALLBACK,
        mode="demo",
        real_llm=False,
        fallback_reason="no_external_provider",
    ),
)


def _safe_exception_type_chain(exc: BaseException) -> list[str]:
    """Return bounded exception class names without retaining exception text."""
    result: list[str] = []
    current: Optional[BaseException] = exc
    while current is not None and len(result) < 4:
        name = _safe_error_token(current.__class__.__name__)
        if name and name not in result:
            result.append(name)
        next_exception = current.__cause__ or current.__context__
        current = next_exception if isinstance(next_exception, BaseException) else None
    return result


def _safe_failure_details(exc: BaseException) -> tuple[str, Optional[int], Optional[float]]:
    """Classify a provider failure without retaining response/body secrets."""
    exception_chain: list[BaseException] = []
    current: Optional[BaseException] = exc
    while current is not None and len(exception_chain) < 4:
        exception_chain.append(current)
        next_exception = current.__cause__ or current.__context__
        current = next_exception if isinstance(next_exception, BaseException) else None

    response = next((getattr(item, "response", None) for item in exception_chain if getattr(item, "response", None) is not None), None)
    status = next((getattr(item, "status_code", None) for item in exception_chain if getattr(item, "status_code", None) is not None), None)
    if status is None and response is not None:
        status = getattr(response, "status_code", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    headers = getattr(response, "headers", {}) if response is not None else {}
    try:
        retry_after = max(0.0, float(headers.get("retry-after")))
    except (AttributeError, TypeError, ValueError):
        retry_after = None
    names = " ".join(name.lower() for name in _safe_exception_type_chain(exc))
    if status == 429 or "ratelimit" in names or "rate_limit" in names:
        return "rate_limit", status, retry_after
    if status in {408, 504} or "timeout" in names or "timedout" in names:
        return "timeout", status, retry_after
    if status in {401, 403} or "auth" in names or "credential" in names or "permission" in names:
        return "authentication_error", status, retry_after
    if status == 404:
        return "model_unavailable", status, retry_after
    if status in {400, 413, 422}:
        return "invalid_request", status, retry_after
    if status is not None and 500 <= status <= 599:
        return "provider_service_error", status, retry_after
    if "proxy" in names:
        return "proxy_error", status, retry_after
    if "ssl" in names or "tls" in names or "certificate" in names:
        return "tls_error", status, retry_after
    if "dns" in names or "gaierror" in names:
        return "dns_error", status, retry_after
    if "connect" in names or "connection" in names or "reset" in names:
        return "connection_error", status, retry_after
    return "provider_error", status, retry_after


def _safe_error(exc: BaseException) -> str:
    """Compatibility wrapper exposing only the secret-free category token."""
    return _safe_failure_details(exc)[0]


def _safe_error_token(value: Any) -> Optional[str]:
    """Keep only short provider-defined category/code tokens."""
    if not isinstance(value, str):
        return None
    token = value.strip()
    if not token or len(token) > 80 or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        return None
    return token


def _sanitize_provider_message(message: Any) -> str:
    """Classify an upstream message without retaining any upstream text."""
    text = str(message or "").lower()
    if any(marker in text for marker in ("context length", "context window", "too long", "token limit")):
        return "context_length_exceeded"
    if "max token" in text or "max_tokens" in text:
        return "token_budget_rejected"
    if "schema" in text or "tool" in text or "function" in text:
        return "tool_or_schema_rejected"
    if "role" in text:
        return "invalid_message_role"
    if "content" in text:
        return "invalid_message_content"
    if "parameter" in text or "unsupported" in text:
        return "unsupported_parameter"
    return "provider_rejected_request"


def _safe_provider_error_context(exc: BaseException) -> tuple[Optional[str], Optional[str], str]:
    """Extract only non-sensitive error classification fields from an SDK error."""
    current: Optional[BaseException] = exc
    for _ in range(4):
        if current is None:
            break
        body = getattr(current, "body", None)
        if isinstance(body, dict):
            detail = body.get("error", body)
            if isinstance(detail, dict):
                return (
                    _safe_error_token(detail.get("type")),
                    _safe_error_token(detail.get("code")),
                    _sanitize_provider_message(detail.get("message")),
                )
        next_exception = current.__cause__ or current.__context__
        current = next_exception if isinstance(next_exception, BaseException) else None
    return None, None, "provider_rejected_request"


def _content_length(value: Any) -> int:
    """Measure content without serializing it into diagnostics or logs."""
    if value is None:
        return 0
    if isinstance(value, (str, bytes, bytearray)):
        return len(value)
    if isinstance(value, (list, tuple)):
        return sum(_content_length(item) for item in value)
    return len(str(value))


def _safe_request_diagnostics(
    prompt: Any,
    *,
    diagnostic_stage: str,
    schema: Optional[Type[Any]],
    structured_output_method: Optional[str],
    provider: str,
    values: Dict[str, Any],
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """Return request shape metadata only; never prompt text, values, or credentials."""
    messages = list(prompt) if isinstance(prompt, (list, tuple)) else [prompt]
    roles = []
    content_lengths = []
    for message in messages:
        if isinstance(message, dict):
            role = message.get("role", message.get("type", "unknown"))
            content = message.get("content", "")
        else:
            role = getattr(message, "type", None) or "user"
            content = getattr(message, "content", message)
        roles.append(_safe_error_token(str(role)) or "unknown")
        content_lengths.append(_content_length(content))
    total_chars = sum(content_lengths)
    schema_fields = getattr(schema, "model_fields", None)
    safe_parameters = {
        name: kwargs[name]
        for name in ("max_tokens", "max_completion_tokens", "temperature", "top_p")
        if isinstance(kwargs.get(name), (int, float)) and not isinstance(kwargs.get(name), bool)
    }
    return {
        "stage": _safe_error_token(diagnostic_stage) or "unknown",
        "model": _model_for(provider, values),
        "message_count": len(messages),
        "message_roles": roles,
        "content_lengths": content_lengths,
        "total_content_chars": total_chars,
        "estimated_input_tokens": total_chars // 4,
        "structured_output": schema is not None,
        "structured_output_method": structured_output_method,
        "schema_name": getattr(schema, "__name__", None) if schema else None,
        "schema_fields": sorted(schema_fields) if isinstance(schema_fields, dict) else [],
        "request_kwarg_names": sorted(str(name) for name in kwargs),
        "request_parameters": safe_parameters,
        "max_tokens": safe_parameters.get("max_tokens"),
        "max_completion_tokens": safe_parameters.get("max_completion_tokens"),
        "temperature": values["temperature"],
        "timeout_seconds": values["timeout"],
    }


def _is_real_value(value: str | None) -> bool:
    if not value:
        return False
    normalized = value.strip().lower()
    return normalized not in {
        "your_gemini_api_key_here",
        "your_groq_api_key_here",
        "your_openai_api_key_here",
        "changeme",
        "change-me",
        "none",
        "null",
    }


def _config_values() -> Dict[str, Any]:
    """Read config module values lazily so tests can safely monkeypatch them."""
    import config

    return {
        "provider": str(getattr(config, "LLM_PROVIDER", "auto") or "auto").strip().lower(),
        "openai_key": str(getattr(config, "OPENAI_API_KEY", "") or ""),
        "gemini_key": str(getattr(config, "GEMINI_API_KEY", "") or ""),
        "groq_key": str(getattr(config, "GROQ_API_KEY", "") or ""),
        "ollama_model": str(getattr(config, "OLLAMA_MODEL", "") or "").strip(),
        "openai_model": str(getattr(config, "OPENAI_MODEL_NAME", "gpt-4o-mini") or "gpt-4o-mini"),
        "gemini_model": str(getattr(config, "GEMINI_MODEL_NAME", "gemini-1.5-flash") or "gemini-1.5-flash"),
        "groq_model": str(getattr(config, "GROQ_MODEL_NAME", "openai/gpt-oss-20b") or "openai/gpt-oss-20b"),
        "temperature": float(getattr(config, "LLM_TEMPERATURE", 0.7)),
        "timeout": float(getattr(config, "LLM_REQUEST_TIMEOUT_SECONDS", 20.0)),
        "fallback_enabled": bool(getattr(config, "LLM_FALLBACK_ENABLED", True)),
        "max_transient_retries": max(0, min(3, int(getattr(config, "LLM_MAX_TRANSIENT_RETRIES", 0)))),
        "min_request_interval_seconds": max(0.0, min(30.0, float(getattr(config, "LLM_MIN_REQUEST_INTERVAL_SECONDS", 0.0)))),
        "ollama_base_url": str(os.getenv("OLLAMA_BASE_URL", "http://localhost:11434") or "http://localhost:11434").rstrip("/"),
    }


def _pace_provider_request(interval_seconds: float) -> None:
    """Serialize optional provider pacing across service instances."""
    if interval_seconds <= 0:
        return
    global _NEXT_REQUEST_AT
    with _PACING_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT)
        _NEXT_REQUEST_AT = scheduled + interval_seconds
    delay = scheduled - now
    if delay > 0:
        time.sleep(delay)


def _configured(provider: str, values: Dict[str, Any]) -> bool:
    if provider == "openai":
        return _is_real_value(values["openai_key"])
    if provider == "gemini":
        return _is_real_value(values["gemini_key"])
    if provider == "groq":
        return _is_real_value(values["groq_key"])
    if provider == "ollama":
        return bool(values["ollama_model"])
    return False


def _model_for(provider: str, values: Dict[str, Any]) -> Optional[str]:
    if provider == "openai":
        return values["openai_model"]
    if provider == "gemini":
        return values["gemini_model"]
    if provider == "groq":
        return values["groq_model"]
    if provider == "ollama":
        return values["ollama_model"] or None
    return None


def structured_output_method(provider: str) -> Optional[str]:
    """Return the explicit structured-output capability for a provider."""
    return STRUCTURED_OUTPUT_METHODS.get(provider)


def _candidate_provider(requested: Optional[str] = None) -> Optional[str]:
    values = _config_values()
    selected = (requested if requested is not None else values["provider"]).strip().lower()
    if selected in SUPPORTED_PROVIDERS:
        return selected
    if selected == "auto":
        # Preserve the established precedence while making it explicit.
        for candidate in ("gemini", "groq", "ollama", "openai"):
            if _configured(candidate, values):
                return candidate
        return None
    return None


def _build_client(provider: str, values: Dict[str, Any]):
    timeout = max(1.0, min(values["timeout"], 300.0))
    temperature = values["temperature"]
    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            model=values["openai_model"],
            api_key=values["openai_key"],
            temperature=temperature,
            timeout=timeout,
            max_retries=0,
        )
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=values["gemini_model"],
            google_api_key=values["gemini_key"],
            temperature=temperature,
            timeout=timeout,
            max_retries=0,
        )
    if provider == "groq":
        from langchain_groq import ChatGroq

        groq_max_tokens = int(os.getenv("GROQ_MAX_TOKENS", "1500"))
        return ChatGroq(
            model=values["groq_model"],
            groq_api_key=values["groq_key"],
            temperature=temperature,
            timeout=timeout,
            max_retries=0,
            max_tokens=groq_max_tokens,
        )
    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=values["ollama_model"] or "llama3.2",
            temperature=temperature,
            base_url=values["ollama_base_url"],
            client_kwargs={"timeout": timeout},
        )
    raise ValueError("unsupported_provider")


class _StructuredProvider:
    def __init__(self, service: "ProviderService", schema: Type[Any], diagnostic_stage: str):
        self._service = service
        self._schema = schema
        self._diagnostic_stage = diagnostic_stage

    def invoke(self, prompt: Any, **kwargs: Any):
        return self._service._invoke_structured(
            self._schema,
            prompt,
            diagnostic_stage=self._diagnostic_stage,
            **kwargs,
        )


class _GroqJsonModeRunnable:
    """Small compatibility path for Groq adapters that reject tool schemas.

    Groq's JSON-object response format is supported by the API even when a
    particular LangChain-Groq release tries to steer structured output through
    tool calling.  This runnable keeps the request schema-validated locally.
    """

    def __init__(self, client: Any, schema: Type[Any]):
        self._client = client
        self._schema = schema

    def invoke(self, prompt: Any, **kwargs: Any):
        schema = self._schema.model_json_schema() if hasattr(self._schema, "model_json_schema") else {}
        instruction = (
            f"\n\nReturn ONLY a valid JSON object instance with actual values (not the schema definition itself) conforming to this JSON schema:\n"
            f"{json.dumps(schema, ensure_ascii=False)}"
        )
        if isinstance(prompt, str):
            request = f"{prompt}{instruction}"
        elif isinstance(prompt, list) and prompt:
            request = list(prompt)
            last = request[-1]
            if isinstance(last, dict):
                last_copy = dict(last)
                last_copy["content"] = str(last_copy.get("content", "")) + instruction
                request[-1] = last_copy
            elif hasattr(last, "content"):
                from langchain_core.messages import HumanMessage
                request.append(HumanMessage(content=instruction))
            else:
                request = prompt
        else:
            request = prompt
        response = self._client.invoke(request, response_format={"type": "json_object"}, **kwargs)
        content = getattr(response, "content", response)
        if isinstance(content, dict):
            parsed = content
        elif isinstance(content, list):
            content = "".join(
                str(item.get("text", "")) if isinstance(item, dict) else str(item)
                for item in content
            )
            parsed = json.loads(content.strip())
        else:
            if not isinstance(content, str):
                content = str(content)
            content = content.strip()
            if content.startswith("```"):
                content = content.removeprefix("```").removeprefix("json").removesuffix("```").strip()
            parsed = json.loads(content)
        if hasattr(self._schema, "model_validate"):
            return self._schema.model_validate(parsed)
        return parsed


class ProviderService:
    """One provider-neutral service consumed by all LLM-backed components."""

    def __init__(self, provider: Optional[str] = None):
        values = _config_values()
        requested = (provider if provider is not None else values["provider"]).strip().lower()
        self._values = values
        self.requested_provider = requested
        self.client = None
        self.provider_name = "fallback"
        self.model_name: Optional[str] = None
        self._snapshot = ProviderStatusSnapshot(
            provider="fallback",
            status=STATUS_DEMO_FALLBACK,
            mode="demo",
            real_llm=False,
            fallback_reason=("invalid_provider" if requested not in {"auto", *SUPPORTED_PROVIDERS} else "no_external_provider"),
            timeout_seconds=max(1.0, min(values["timeout"], 300.0)),
        )

        selected = _candidate_provider(requested)
        if selected is None:
            _last_snapshot.set(self._snapshot)
            return
        self.provider_name = selected
        self.model_name = _model_for(selected, values)
        if not _configured(selected, values):
            self._snapshot = ProviderStatusSnapshot(
                provider=selected,
                status=STATUS_NOT_CONFIGURED,
                model=self.model_name,
                configured=False,
                mode="demo",
                real_llm=False,
                fallback_reason="provider_not_configured",
                timeout_seconds=self._snapshot.timeout_seconds,
            )
            self.provider_name = "fallback"
            self.model_name = None
            _last_snapshot.set(self._snapshot)
            return
        try:
            self.client = _build_client(selected, values)
            runtime_state = _get_provider_runtime_state(selected)
            if runtime_state and runtime_state.get("runtime_verified") and runtime_state.get("model") == self.model_name:
                self._snapshot = ProviderStatusSnapshot(
                    provider=selected,
                    status=STATUS_READY,
                    model=self.model_name,
                    configured=True,
                    runtime_verified=True,
                    mode="provider",
                    real_llm=True,
                    latency_ms=runtime_state.get("last_latency_ms"),
                    last_verified_at=runtime_state.get("last_verified_at"),
                    timeout_seconds=self._snapshot.timeout_seconds,
                )
            else:
                self._snapshot = ProviderStatusSnapshot(
                    provider=selected,
                    status=STATUS_CONFIGURED_BUT_UNVERIFIED,
                    model=self.model_name,
                    configured=True,
                    mode="provider",
                    real_llm=False,
                    error=(runtime_state.get("last_error") if runtime_state else None),
                    http_status=(runtime_state.get("http_status") if runtime_state else None),
                    retry_after_seconds=(runtime_state.get("retry_after_seconds") if runtime_state else None),
                    provider_error_type=(runtime_state.get("provider_error_type") if runtime_state else None),
                    provider_error_code=(runtime_state.get("provider_error_code") if runtime_state else None),
                    sanitized_error_message=(runtime_state.get("sanitized_error_message") if runtime_state else None),
                    timeout_seconds=self._snapshot.timeout_seconds,
                )
        except Exception as exc:
            self._snapshot = ProviderStatusSnapshot(
                provider=selected,
                status=STATUS_ERROR,
                model=self.model_name,
                configured=True,
                mode="demo",
                real_llm=False,
                error=_safe_error(exc),
                fallback_reason="initialization_failed",
                failed_provider=(selected if values["fallback_enabled"] else None),
                timeout_seconds=self._snapshot.timeout_seconds,
            )
            self.provider_name = "fallback"
            self.model_name = None
        _last_snapshot.set(self._snapshot)

    def __bool__(self) -> bool:
        return self.client is not None

    @property
    def mode(self) -> str:
        return self._snapshot.mode

    @property
    def status(self) -> str:
        return self._snapshot.status

    @property
    def real_llm(self) -> bool:
        return self._snapshot.real_llm

    @property
    def snapshot(self) -> ProviderStatusSnapshot:
        return self._snapshot

    def metadata(self) -> Dict[str, Any]:
        """Metadata safe to include in an API response or audit envelope."""
        metadata = {
            "provider": self._snapshot.provider,
            "model": self._snapshot.model,
            "mode": self._snapshot.mode,
            "provider_status": self._snapshot.status,
            "real_llm": self._snapshot.real_llm,
        }
        if self._snapshot.latency_ms is not None:
            metadata["latency_ms"] = self._snapshot.latency_ms
        if self._snapshot.last_verified_at is not None:
            metadata["last_verified_at"] = self._snapshot.last_verified_at
        if self._snapshot.fallback_reason:
            metadata["fallback_reason"] = self._snapshot.fallback_reason
        if self._snapshot.error:
            metadata["error"] = self._snapshot.error
        if self._snapshot.failed_provider:
            metadata["failed_provider"] = self._snapshot.failed_provider
        if self._snapshot.http_status is not None:
            metadata["http_status"] = self._snapshot.http_status
        if self._snapshot.retry_after_seconds is not None:
            metadata["retry_after_seconds"] = self._snapshot.retry_after_seconds
        if self._snapshot.provider_error_type:
            metadata["provider_error_type"] = self._snapshot.provider_error_type
        if self._snapshot.provider_error_code:
            metadata["provider_error_code"] = self._snapshot.provider_error_code
        if self._snapshot.provider_exception_types:
            metadata["provider_exception_types"] = self._snapshot.provider_exception_types
        if self._snapshot.sanitized_error_message:
            metadata["sanitized_error_message"] = self._snapshot.sanitized_error_message
        if self._snapshot.request_diagnostics:
            metadata["request_diagnostics"] = self._snapshot.request_diagnostics
        return metadata

    def with_structured_output(self, schema: Type[Any], *, diagnostic_stage: str = "structured_output"):
        if self.client is None:
            raise ProviderInvocationError("fallback", "demo_fallback")
        return _StructuredProvider(self, schema, diagnostic_stage)

    def _invoke_structured(
        self,
        schema: Type[Any],
        prompt: Any,
        *,
        diagnostic_stage: str = "structured_output",
        **kwargs: Any,
    ):
        diagnostics = _safe_request_diagnostics(
            prompt,
            diagnostic_stage=diagnostic_stage,
            schema=schema,
            structured_output_method=structured_output_method(self.provider_name),
            provider=self.provider_name,
            values=self._values,
            kwargs=kwargs,
        )
        try:
            method = structured_output_method(self.provider_name)
            if self.provider_name == "groq" and method == "json_mode":
                return self._invoke_client(
                    _GroqJsonModeRunnable(self.client, schema),
                    prompt,
                    diagnostic_stage=diagnostic_stage,
                    schema=schema,
                    structured_output_method="json_mode_native",
                    format_retry_on_json_validation=True,
                    request_diagnostics=diagnostics,
                    **kwargs,
                )
            structured = self.client.with_structured_output(
                schema,
                **({"method": method} if method else {}),
            )
            return self._invoke_client(
                structured,
                prompt,
                diagnostic_stage=diagnostic_stage,
                schema=schema,
                structured_output_method=method,
                format_retry_on_json_validation=method == "json_mode",
                request_diagnostics=diagnostics,
                **kwargs,
            )
        except ProviderInvocationError:
            raise
        except Exception as exc:
            reason, http_status, retry_after = _safe_failure_details(exc)
            error_type, error_code, safe_message = _safe_provider_error_context(exc)
            self._mark_failure(
                reason,
                http_status=http_status,
                retry_after_seconds=retry_after,
                provider_error_type=error_type,
                provider_error_code=error_code,
                provider_exception_types=_safe_exception_type_chain(exc),
                sanitized_error_message=safe_message,
                request_diagnostics=diagnostics,
            )
            raise ProviderInvocationError(self.provider_name, reason, timeout=reason == "timeout") from exc

    def _mark_failure(
        self,
        reason: str,
        *,
        http_status: Optional[int] = None,
        retry_after_seconds: Optional[float] = None,
        provider_error_type: Optional[str] = None,
        provider_error_code: Optional[str] = None,
        provider_exception_types: Optional[list[str]] = None,
        sanitized_error_message: Optional[str] = None,
        request_diagnostics: Optional[Dict[str, Any]] = None,
    ) -> None:
        failed_provider = self.provider_name
        fallback_enabled = self._values["fallback_enabled"]
        _record_provider_failure(
            failed_provider,
            reason,
            model=self.model_name,
            http_status=http_status,
            retry_after_seconds=retry_after_seconds,
            provider_error_type=provider_error_type,
            provider_error_code=provider_error_code,
            sanitized_error_message=sanitized_error_message,
        )
        self._snapshot = dataclasses.replace(
            self._snapshot,
            provider=("fallback" if fallback_enabled else self._snapshot.provider),
            model=(None if fallback_enabled else self._snapshot.model),
            status=(STATUS_UNAVAILABLE if reason == "connection_error" else STATUS_ERROR),
            runtime_verified=False,
            real_llm=False,
            error=reason,
            mode="demo" if fallback_enabled else "provider_error",
            fallback_reason="provider_call_failed",
            failed_provider=failed_provider,
            latency_ms=self._snapshot.latency_ms,
            http_status=http_status,
            retry_after_seconds=retry_after_seconds,
            provider_error_type=provider_error_type,
            provider_error_code=provider_error_code,
            provider_exception_types=provider_exception_types,
            sanitized_error_message=sanitized_error_message,
            request_diagnostics=request_diagnostics,
        )
        _last_snapshot.set(self._snapshot)
        LOGGER.warning(
            "provider_call_failed provider=%s category=%s http_status=%s retry_after_seconds=%s error_type=%s error_code=%s exception_types=%s safe_message=%s request_diagnostics=%s",
            failed_provider,
            reason,
            http_status,
            retry_after_seconds,
            provider_error_type,
            provider_error_code,
            provider_exception_types,
            sanitized_error_message,
            request_diagnostics,
        )

    def _invoke_client(
        self,
        client: Any,
        prompt: Any,
        *,
        diagnostic_stage: str = "generation",
        schema: Optional[Type[Any]] = None,
        structured_output_method: Optional[str] = None,
        format_retry_on_json_validation: bool = False,
        request_diagnostics: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        started = time.perf_counter()
        diagnostics = request_diagnostics or _safe_request_diagnostics(
            prompt,
            diagnostic_stage=diagnostic_stage,
            schema=schema,
            structured_output_method=structured_output_method,
            provider=self.provider_name,
            values=self._values,
            kwargs=kwargs,
        )
        max_retries = self._values["max_transient_retries"]
        transient_attempt = 0
        format_attempt = 0
        while True:
            result_queue: "queue.Queue[tuple[str, Any]]" = queue.Queue(maxsize=1)

            def call() -> None:
                try:
                    result_queue.put_nowait(("ok", client.invoke(prompt, **kwargs)))
                except BaseException as exc:  # marshal to the bounded caller thread
                    try:
                        result_queue.put_nowait(("error", exc))
                    except queue.Full:
                        pass

            # Client-level timeout parameters protect real HTTP calls. This
            # daemon join is an additional boundary for custom clients/tests.
            _pace_provider_request(self._values["min_request_interval_seconds"])
            worker = threading.Thread(target=call, name="agentshield-provider", daemon=True)
            worker.start()
            worker.join(max(1.0, min(self._values["timeout"], 300.0)))
            if worker.is_alive():
                kind, value = "error", TimeoutError("provider call exceeded configured timeout")
            else:
                kind, value = result_queue.get()
            try:
                if kind == "error":
                    raise value
                result = value
                break
            except Exception as exc:
                reason, http_status, retry_after = _safe_failure_details(exc)
                error_type, error_code, safe_message = _safe_provider_error_context(exc)
                retryable = reason in {
                    "rate_limit",
                    "provider_service_error",
                    "timeout",
                    "connection_error",
                }
                if retryable and transient_attempt < max_retries:
                    delay = retry_after if retry_after is not None else min(2.0 ** transient_attempt, 8.0)
                    LOGGER.warning(
                        "provider_call_retry provider=%s category=%s http_status=%s delay_seconds=%s attempt=%s",
                        self.provider_name,
                        reason,
                        http_status,
                        delay,
                        transient_attempt + 1,
                    )
                    transient_attempt += 1
                    time.sleep(delay)
                    continue
                if (
                    format_retry_on_json_validation
                    and (
                        (reason == "invalid_request" and error_code == "json_validate_failed")
                        or isinstance(exc, (json.JSONDecodeError, ValueError))
                    )
                    and format_attempt < MAX_STRUCTURED_FORMAT_RETRIES
                ):
                    format_attempt += 1
                    LOGGER.warning(
                        "provider_format_retry provider=%s method=%s category=%s attempt=%s",
                        self.provider_name,
                        structured_output_method,
                        error_code,
                        format_attempt,
                    )
                    continue
                self._snapshot = dataclasses.replace(
                    self._snapshot,
                    latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
                )
                self._mark_failure(
                    reason,
                    http_status=http_status,
                    retry_after_seconds=retry_after,
                    provider_error_type=error_type,
                    provider_error_code=error_code,
                    provider_exception_types=_safe_exception_type_chain(exc),
                    sanitized_error_message=safe_message,
                    request_diagnostics=diagnostics,
                )
                raise ProviderInvocationError(self.provider_name, reason, timeout=reason == "timeout") from exc
        now_ts = time.time()
        latency = round((time.perf_counter() - started) * 1000.0, 2)
        _record_provider_success(self.provider_name, self.model_name, latency)
        self._snapshot = dataclasses.replace(
            self._snapshot,
            status=STATUS_READY,
            runtime_verified=True,
            real_llm=True,
            latency_ms=latency,
            last_verified_at=now_ts,
            error=None,
            fallback_reason=None,
            failed_provider=None,
        )
        _last_snapshot.set(self._snapshot)
        return result

    def invoke(self, prompt: Any, **kwargs: Any):
        if self.client is None:
            raise ProviderInvocationError("fallback", self._snapshot.fallback_reason or "demo_fallback")
        return self._invoke_client(self.client, prompt, diagnostic_stage="generation", **kwargs)

    def validate(self, prompt: str = "Reply with the single word OK.") -> ProviderStatusSnapshot:
        """Perform one bounded, safe completion for explicit runtime validation."""
        if self.client is None:
            return self._snapshot
        try:
            self.invoke(prompt)
        except ProviderInvocationError:
            return self._snapshot
        return self._snapshot


def get_provider_service(provider: Optional[str] = None) -> ProviderService:
    return ProviderService(provider=provider)


def get_provider_status(*, probe: bool = False, provider: Optional[str] = None) -> Dict[str, Any]:
    """Return a complete, secret-free status map.

    Cloud providers remain ``configured_but_unverified`` until an explicit
    probe is requested.  Ollama is treated the same way to avoid claiming a
    daemon/model is reachable merely because a model name is present.
    """
    values = _config_values()
    statuses: Dict[str, ProviderStatusSnapshot] = {}
    for name in SUPPORTED_PROVIDERS:
        service = ProviderService(provider=name)
        snapshot = service.snapshot
        if probe and snapshot.configured:
            snapshot = service.validate()
        statuses[name] = snapshot

    selected = (provider if provider is not None else values["provider"]).strip().lower()
    active = _candidate_provider(selected)
    active_snapshot = statuses.get(active) if active else None
    if active_snapshot is None or active_snapshot.status in {STATUS_NOT_CONFIGURED, STATUS_ERROR, STATUS_UNAVAILABLE}:
        active_name = "fallback"
        mode = "demo"
        real_llm = False
        active_status = STATUS_DEMO_FALLBACK
    else:
        active_name = active_snapshot.provider
        mode = "provider"
        real_llm = active_snapshot.real_llm
        active_status = active_snapshot.status
    return {
        "active_provider": active_name,
        "selected_provider": active_name,
        "mode": mode,
        "real_llm": real_llm,
        "active_status": active_status,
        "providers": {name: statuses[name].as_dict() for name in SUPPORTED_PROVIDERS},
        "support_note": (
            "Provider status is configuration-only until an explicit validation probe or successful chat completion."
        ),
    }


def provider_metadata() -> Dict[str, Any]:
    snapshot = _last_snapshot.get()
    # A failed external provider must never be presented as the source of a
    # demo response. Keep the failed provider as a separate diagnostic field.
    output_provider = (
        "fallback"
        if snapshot.mode in {"demo", "provider_error"} and snapshot.fallback_reason
        else snapshot.provider
    )
    output_model = None if output_provider == "fallback" else snapshot.model
    metadata = {
        "provider": output_provider,
        "model": output_model,
        "mode": snapshot.mode,
        "provider_status": snapshot.status,
        "real_llm": snapshot.real_llm,
    }
    if snapshot.latency_ms is not None:
        metadata["latency_ms"] = snapshot.latency_ms
    if snapshot.last_verified_at is not None:
        metadata["last_verified_at"] = snapshot.last_verified_at
    if snapshot.fallback_reason:
        metadata["fallback_reason"] = snapshot.fallback_reason
    if snapshot.error:
        metadata["error"] = snapshot.error
    if snapshot.failed_provider:
        metadata["failed_provider"] = snapshot.failed_provider
    if snapshot.http_status is not None:
        metadata["http_status"] = snapshot.http_status
    if snapshot.retry_after_seconds is not None:
        metadata["retry_after_seconds"] = snapshot.retry_after_seconds
    if snapshot.provider_error_type:
        metadata["provider_error_type"] = snapshot.provider_error_type
    if snapshot.provider_error_code:
        metadata["provider_error_code"] = snapshot.provider_error_code
    if snapshot.provider_exception_types:
        metadata["provider_exception_types"] = snapshot.provider_exception_types
    if snapshot.sanitized_error_message:
        metadata["sanitized_error_message"] = snapshot.sanitized_error_message
    if snapshot.request_diagnostics:
        metadata["request_diagnostics"] = snapshot.request_diagnostics
    return metadata


def reset_provider_metadata() -> None:
    """Reset per-request provider telemetry to an explicit demo baseline."""
    _last_snapshot.set(
        ProviderStatusSnapshot(
            provider="fallback",
            status=STATUS_DEMO_FALLBACK,
            mode="demo",
            real_llm=False,
            fallback_reason="no_external_provider",
        )
    )


def validate_provider(provider: str) -> ProviderStatusSnapshot:
    return get_provider_service(provider).validate()
