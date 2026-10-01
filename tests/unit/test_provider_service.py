"""Unit coverage for provider selection, redaction-safe metadata and fallback."""

from __future__ import annotations

import time

import pytest

import config
import providers.service as provider_module
from providers.service import (
    STATUS_CONFIGURED_BUT_UNVERIFIED,
    STATUS_DEMO_FALLBACK,
    STATUS_ERROR,
    STATUS_READY,
    ProviderInvocationError,
    ProviderService,
    get_provider_status,
    provider_metadata,
    reset_provider_metadata,
)
from agents.finalizer import finalizer_node, validate_final_output

pytestmark = [pytest.mark.unit, pytest.mark.provider]


class FakeResponse:
    def __init__(self, content="OK"):
        self.content = content


class FakeClient:
    def __init__(self, response=None, error=None, delay=0.0):
        self.response = response or FakeResponse()
        self.error = error
        self.delay = delay

    def invoke(self, _prompt, **_kwargs):
        self.last_invoke_kwargs = _kwargs
        if self.delay:
            time.sleep(self.delay)
        if self.error:
            raise self.error
        return self.response

    def with_structured_output(self, _schema, **kwargs):
        self.structured_kwargs = kwargs
        return self


class FakeBadRequestError(RuntimeError):
    status_code = 400
    body = {
        "error": {
            "type": "invalid_request_error",
            "code": "tool_use_failed",
            "message": "Tool use failed; secret request content must never be retained.",
        }
    }


class FakeJSONValidationError(RuntimeError):
    status_code = 400
    body = {
        "error": {
            "type": "invalid_request_error",
            "code": "json_validate_failed",
            "message": "JSON validation failed.",
        }
    }


class FakeWrappedConnectionError(RuntimeError):
    def __init__(self):
        super().__init__("upstream wrapper omitted safe transport details")
        self.__cause__ = ConnectionError("transport reset")


class FakeHTTPResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.headers = headers or {}


class FakeRateLimitError(RuntimeError):
    def __init__(self, retry_after: str = "1.5"):
        self.response = FakeHTTPResponse(429, {"retry-after": retry_after})


class SequenceFakeClient(FakeClient):
    def __init__(self, outcomes):
        super().__init__()
        self.outcomes = list(outcomes)
        self.calls = 0

    def invoke(self, _prompt, **_kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _configure(monkeypatch, provider="openai"):
    monkeypatch.setattr(config, "LLM_PROVIDER", provider)
    monkeypatch.setattr(config, "OPENAI_API_KEY", "sk-test-provider-key")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    monkeypatch.setattr(config, "GROQ_API_KEY", "")
    monkeypatch.setattr(config, "OLLAMA_MODEL", "")
    monkeypatch.setattr(config, "LLM_REQUEST_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(config, "LLM_FALLBACK_ENABLED", True)


def test_no_provider_is_explicit_demo_fallback(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    monkeypatch.setattr(config, "GROQ_API_KEY", "")
    monkeypatch.setattr(config, "OLLAMA_MODEL", "")
    reset_provider_metadata()
    service = ProviderService()
    assert not service
    assert service.snapshot.status == STATUS_DEMO_FALLBACK
    assert service.metadata()["provider"] == "fallback"
    assert service.metadata()["mode"] == "demo"
    assert service.metadata()["real_llm"] is False


def test_finalizer_fallback_output_carries_demo_metadata(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    monkeypatch.setattr(config, "GROQ_API_KEY", "")
    monkeypatch.setattr(config, "OLLAMA_MODEL", "")
    reset_provider_metadata()
    output = finalizer_node({"user_query": "safe", "draft_response": "draft"})["final_output"]
    assert output["provider"] == "fallback"
    assert output["mode"] == "demo"
    assert output["real_llm"] is False
    assert "DEMO / FALLBACK MODE" in output["notice"]


def test_provider_client_initialization_and_success_are_distinguished(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: FakeClient())
    service = ProviderService()
    assert service.snapshot.status == STATUS_CONFIGURED_BUT_UNVERIFIED
    response = service.invoke("Reply with OK")
    assert response.content == "OK"
    assert service.snapshot.status == STATUS_READY
    assert service.snapshot.runtime_verified is True
    assert service.metadata()["provider"] == "openai"
    assert service.metadata()["model"] == "gpt-4o-mini"
    assert service.metadata()["real_llm"] is True


def test_provider_failure_becomes_controlled_demo_with_failed_provider(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(
        provider_module,
        "_build_client",
        lambda *_: FakeClient(error=RuntimeError("authorization header sk-secret")),
    )
    service = ProviderService()
    try:
        service.invoke("safe")
    except ProviderInvocationError as exc:
        assert exc.reason == "provider_error"
    else:
        raise AssertionError("provider failures must be surfaced to the caller")
    metadata = provider_metadata()
    assert metadata["provider"] == "fallback"
    assert metadata["failed_provider"] == "openai"
    assert metadata["mode"] == "demo"
    assert metadata["real_llm"] is False
    assert "sk-secret" not in str(metadata)


def test_structured_400_records_safe_request_shape_without_prompt_content(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(
        provider_module,
        "_build_client",
        lambda *_: FakeClient(error=FakeBadRequestError()),
    )
    service = ProviderService()
    with pytest.raises(ProviderInvocationError) as exc_info:
        service.with_structured_output(dict, diagnostic_stage="finalizer").invoke(
            "private-prompt-content"
        )
    assert exc_info.value.reason == "invalid_request"
    metadata = service.metadata()
    assert metadata["http_status"] == 400
    assert metadata["provider_error_type"] == "invalid_request_error"
    assert metadata["provider_error_code"] == "tool_use_failed"
    assert metadata["sanitized_error_message"] == "tool_or_schema_rejected"
    assert metadata["request_diagnostics"] == {
        "stage": "finalizer",
        "model": "gpt-4o-mini",
        "message_count": 1,
        "message_roles": ["user"],
        "content_lengths": [22],
        "total_content_chars": 22,
        "estimated_input_tokens": 5,
        "structured_output": True,
        "structured_output_method": None,
        "schema_name": "dict",
        "schema_fields": [],
        "request_kwarg_names": [],
        "request_parameters": {},
        "max_tokens": None,
        "max_completion_tokens": None,
        "temperature": 0.7,
        "timeout_seconds": 1.0,
    }
    assert "private-prompt-content" not in str(metadata)
    assert "secret request content" not in str(metadata)


def test_groq_uses_json_mode_for_structured_output(monkeypatch):
    _configure(monkeypatch, provider="groq")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "GROQ_API_KEY", "gsk-test-provider-key")
    client = FakeClient(response={"title": "T", "summary": "S", "detailed_content": "D", "sources": []})
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    service = ProviderService()
    assert service.with_structured_output(dict).invoke("safe")["title"] == "T"
    assert client.last_invoke_kwargs == {"response_format": {"type": "json_object"}}


def test_openai_keeps_existing_structured_output_default(monkeypatch):
    _configure(monkeypatch, provider="openai")
    client = FakeClient(response={"title": "T", "summary": "S", "detailed_content": "D", "sources": []})
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    service = ProviderService()
    assert service.with_structured_output(dict).invoke("safe")["title"] == "T"
    assert client.structured_kwargs == {}


def test_groq_json_mode_retries_one_provider_json_validation_failure(monkeypatch):
    _configure(monkeypatch, provider="groq")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "GROQ_API_KEY", "gsk-test-provider-key")
    client = SequenceFakeClient([FakeJSONValidationError(), {"title": "T"}])
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    service = ProviderService()
    assert service.with_structured_output(dict).invoke("safe") == {"title": "T"}
    assert client.calls == 2
    assert service.metadata()["real_llm"] is True


def test_groq_json_mode_retries_one_malformed_json_response(monkeypatch):
    _configure(monkeypatch, provider="groq")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "")
    monkeypatch.setattr(config, "GROQ_API_KEY", "gsk-test-provider-key")
    client = SequenceFakeClient([FakeResponse("not-json"), {"title": "T"}])
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    service = ProviderService()
    assert service.with_structured_output(dict).invoke("safe") == {"title": "T"}
    assert client.calls == 2


def test_final_output_validation_rejects_malformed_or_incomplete_payloads():
    with pytest.raises(ValueError, match="invalid_finalizer_structured_response"):
        validate_final_output("not-json")
    with pytest.raises(Exception):
        validate_final_output({"title": "only title"})


def test_rate_limit_honors_retry_after_and_recovers_within_retry_ceiling(monkeypatch):
    _configure(monkeypatch)
    client = SequenceFakeClient([FakeRateLimitError(), FakeResponse()])
    sleeps = []
    monkeypatch.setattr(config, "LLM_MAX_TRANSIENT_RETRIES", 2)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    monkeypatch.setattr(provider_module, "_pace_provider_request", lambda _interval: None)
    monkeypatch.setattr(provider_module.time, "sleep", lambda delay: sleeps.append(delay))
    service = ProviderService()
    assert service.invoke("safe").content == "OK"
    assert client.calls == 2
    assert sleeps == [1.5]
    assert service.snapshot.status == STATUS_READY


def test_rate_limit_retry_ceiling_fails_closed_after_configured_attempts(monkeypatch):
    _configure(monkeypatch)
    client = SequenceFakeClient([FakeRateLimitError("0"), FakeRateLimitError("0"), FakeRateLimitError("0")])
    monkeypatch.setattr(config, "LLM_MAX_TRANSIENT_RETRIES", 2)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    monkeypatch.setattr(provider_module, "_pace_provider_request", lambda _interval: None)
    monkeypatch.setattr(provider_module.time, "sleep", lambda _delay: None)
    service = ProviderService()
    with pytest.raises(ProviderInvocationError, match="rate_limit"):
        service.invoke("safe")
    assert client.calls == 3
    assert service.snapshot.real_llm is False
    assert service.metadata()["provider"] == "fallback"


def test_wrapped_connection_error_is_diagnosed_and_retried(monkeypatch):
    _configure(monkeypatch)
    client = SequenceFakeClient([FakeWrappedConnectionError(), FakeResponse()])
    sleeps = []
    monkeypatch.setattr(config, "LLM_MAX_TRANSIENT_RETRIES", 1)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    monkeypatch.setattr(provider_module, "_pace_provider_request", lambda _interval: None)
    monkeypatch.setattr(provider_module.time, "sleep", lambda delay: sleeps.append(delay))
    service = ProviderService()
    assert service.invoke("safe").content == "OK"
    assert client.calls == 2
    assert sleeps == [1.0]
    assert provider_module._safe_exception_type_chain(FakeWrappedConnectionError()) == [
        "FakeWrappedConnectionError",
        "ConnectionError",
    ]


def test_unknown_provider_error_is_not_retried(monkeypatch):
    _configure(monkeypatch)
    client = SequenceFakeClient([RuntimeError("unknown provider failure")])
    monkeypatch.setattr(config, "LLM_MAX_TRANSIENT_RETRIES", 3)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: client)
    monkeypatch.setattr(provider_module, "_pace_provider_request", lambda _interval: None)
    service = ProviderService()
    with pytest.raises(ProviderInvocationError, match="provider_error"):
        service.invoke("safe")
    assert client.calls == 1
    assert service.metadata()["provider_exception_types"] == ["RuntimeError"]


def test_global_pacing_reserves_a_shared_interval(monkeypatch):
    sleeps = []
    monkeypatch.setattr(provider_module, "_NEXT_REQUEST_AT", 0.0)
    monkeypatch.setattr(provider_module.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(provider_module.time, "sleep", lambda delay: sleeps.append(delay))
    provider_module._pace_provider_request(2.0)
    provider_module._pace_provider_request(2.0)
    assert sleeps == [2.0]


def test_unavailable_provider_has_distinct_status(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(
        provider_module,
        "_build_client",
        lambda *_: FakeClient(error=ConnectionError("http://localhost:11434")),
    )
    service = ProviderService()
    with pytest.raises(ProviderInvocationError):
        service.invoke("safe")
    assert service.snapshot.status == "unavailable"


def test_invalid_provider_selection_falls_back_without_echoing_value(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "AGENTSHIELD_TEST_SECRET_123")
    monkeypatch.setattr(config, "OPENAI_API_KEY", "sk-test-provider-key")
    service = ProviderService()
    assert not service
    assert service.snapshot.status == STATUS_DEMO_FALLBACK
    assert "AGENTSHIELD_TEST_SECRET_123" not in str(service.metadata())


def test_provider_timeout_is_bounded_and_not_silently_swallowed(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(
        provider_module,
        "_build_client",
        lambda *_: FakeClient(delay=2.0),
    )
    service = ProviderService()
    started = time.perf_counter()
    try:
        service.invoke("safe")
    except ProviderInvocationError as exc:
        assert exc.timeout is True
    else:
        raise AssertionError("a hanging client must produce a timeout error")
    assert time.perf_counter() - started < 1.8
    assert service.snapshot.status == STATUS_ERROR


def test_status_endpoint_data_is_secret_free_and_unverified_until_probe(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: FakeClient())
    status = get_provider_status(provider="openai")
    assert status["active_provider"] == "openai"
    assert status["mode"] == "provider"
    assert status["providers"]["openai"]["status"] == STATUS_CONFIGURED_BUT_UNVERIFIED
    assert "sk-test-provider-key" not in str(status)


def test_explicit_probe_marks_only_successful_provider_ready(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: FakeClient())
    status = get_provider_status(probe=True, provider="openai")
    assert status["providers"]["openai"]["status"] == STATUS_READY
    assert status["providers"]["openai"]["runtime_verified"] is True
    assert status["active_status"] == STATUS_READY


def test_successful_invocation_retains_verified_status_across_subsequent_reads(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: FakeClient())
    
    # 1. Initially configured but unverified
    initial_status = get_provider_status(probe=False, provider="openai")
    assert initial_status["providers"]["openai"]["status"] == STATUS_CONFIGURED_BUT_UNVERIFIED
    assert initial_status["providers"]["openai"]["runtime_verified"] is False
    assert initial_status["active_status"] == STATUS_CONFIGURED_BUT_UNVERIFIED

    # 2. Invoke provider successfully
    service = ProviderService()
    assert service.invoke("Say hello").content == "OK"

    # 3. Subsequent reads without probe must retain verified status
    subsequent_status = get_provider_status(probe=False, provider="openai")
    assert subsequent_status["providers"]["openai"]["status"] == STATUS_READY
    assert subsequent_status["providers"]["openai"]["runtime_verified"] is True
    assert subsequent_status["providers"]["openai"]["real_llm"] is True
    assert subsequent_status["active_status"] == STATUS_READY
    assert subsequent_status["providers"]["openai"]["last_verified_at"] is not None

    # 4. A newly created ProviderService instance starts verified
    new_service = ProviderService()
    assert new_service.snapshot.status == STATUS_READY
    assert new_service.snapshot.runtime_verified is True
    assert new_service.snapshot.real_llm is True


def test_model_change_requires_new_verification(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: FakeClient())
    
    # Verify with gpt-4o-mini
    service = ProviderService()
    service.invoke("test")
    assert get_provider_status(probe=False, provider="openai")["active_status"] == STATUS_READY

    # Switch model to gpt-4o
    monkeypatch.setattr(config, "OPENAI_MODEL_NAME", "gpt-4o")
    switched_status = get_provider_status(probe=False, provider="openai")
    assert switched_status["providers"]["openai"]["status"] == STATUS_CONFIGURED_BUT_UNVERIFIED
    assert switched_status["providers"]["openai"]["runtime_verified"] is False
