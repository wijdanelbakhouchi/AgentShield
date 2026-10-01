"""Provider errors must remain execution failures, never security blocks."""

from api.server import _annotate_provider_output, _execution_summary


def test_provider_error_is_separate_from_security_decision() -> None:
    execution = _execution_summary(
        "COMPLETED",
        {
            "provider_metadata": {
                "provider": "groq",
                "model": "qwen/qwen3.6-27b",
                "mode": "provider_error",
                "real_llm": False,
                "error": "invalid_request",
            }
        },
    )
    assert execution.status == "PROVIDER_ERROR"
    assert execution.provider == "groq"
    assert execution.error == "invalid_request"


def test_security_stop_is_not_reported_as_provider_error() -> None:
    execution = _execution_summary("BLOCKED", {}, security_terminal=True)
    assert execution.status == "NOT_EXECUTED"


def test_provider_failure_wins_over_legacy_blocked_workflow_status() -> None:
    execution = _execution_summary(
        "BLOCKED",
        {"provider_metadata": {"mode": "provider_error", "provider": "groq"}},
    )
    assert execution.status == "PROVIDER_ERROR"


def test_finalizer_provider_disposition_is_not_overwritten_by_stale_context() -> None:
    output = _annotate_provider_output(
        {
            "detailed_content": "Conservative fallback response.",
            "provider": "fallback",
            "mode": "demo",
            "real_llm": False,
            "fallback_reason": "provider_call_failed",
            "failed_provider": "groq",
        }
    )
    assert output["provider"] == "fallback"
    assert output["real_llm"] is False
    assert output["provider_metadata"]["failed_provider"] == "groq"
