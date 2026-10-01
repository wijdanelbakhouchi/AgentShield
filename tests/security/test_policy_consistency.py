"""Regression tests for the separation of risk and enforcement semantics."""

from policy.policy_engine import PolicyEngine
from state import Decision, RiskLevel, RiskScoreResult, SecurityAnalysisResult


def _analysis(**kwargs) -> SecurityAnalysisResult:
    return SecurityAnalysisResult(
        request_id="req-policy-consistency",
        timestamp="2026-01-01T00:00:00+00:00",
        normalized_input="safe educational question",
        **kwargs,
    )


def test_zero_risk_benign_request_is_allowed() -> None:
    risk = RiskScoreResult(score=0.0, level=RiskLevel.LOW)
    decision = PolicyEngine.evaluate(_analysis(), risk)
    assert decision.action == Decision.ALLOW
    assert decision.risk_metrics.score == 0.0
    assert decision.risk_metrics.level == RiskLevel.LOW


def test_independent_critical_signal_is_explicit_when_score_is_low() -> None:
    analysis = _analysis(rule_flags=["PROMPT_INJECTION:SYSTEM_OVERRIDE"])
    risk = RiskScoreResult(score=0.0, level=RiskLevel.LOW)
    decision = PolicyEngine.evaluate(analysis, risk)
    assert decision.action == Decision.BLOCK
    assert "critical security signal" in decision.reason.lower()

