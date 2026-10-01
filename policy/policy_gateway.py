"""Compatibility adapter for the pre-Phase-3 policy gateway.

The public ``PolicyGateway`` name is retained for research scripts and older
integrations, but it no longer owns normalization, threat evaluation, or a
second threshold table. Active application routes use ``SecurityPipeline``
directly; this adapter only converts legacy dictionaries into canonical model
inputs and returns canonical decision values.
"""

import datetime
from typing import Any, Dict

from policy.policy_engine import PolicyEngine
from config import POLICY_BLOCK_THRESHOLD
from scoring.risk_scorer import RiskScorer
from security.pipeline import SecurityPipeline
from state import Decision, RiskScoreResult, SecurityAnalysisResult, SecurityPayload

try:
    from logging.dashboard_sync import TelemetryLogger
except (ImportError, AttributeError):
    import importlib.util
    import os

    _dash_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "logging", "dashboard_sync.py")
    )
    _spec = importlib.util.spec_from_file_location("dashboard_sync", _dash_path)
    _dash_mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_dash_mod)
    TelemetryLogger = _dash_mod.TelemetryLogger


def _status_for_action(action: Decision) -> str:
    return {
        Decision.ALLOW: "ALLOWED",
        Decision.SANITIZE: "SANITIZED",
        Decision.REVIEW: "REVIEW",
        Decision.BLOCK: "BLOCKED",
    }[action]


def _enforcement_from_models(payload, analysis, risk, policy) -> Dict[str, Any]:
    """Serialize canonical models in the shape expected by legacy callers."""
    is_blocked = policy.action == Decision.BLOCK
    return {
        "status": _status_for_action(policy.action),
        "action": policy.action.value,
        "risk_score": risk.score,
        "threat_level": risk.level.value,
        "reason": policy.reason,
        "blocked_at_timestamp": (
            datetime.datetime.now(datetime.timezone.utc).isoformat()
            if is_blocked
            else None
        ),
        "response": (
            "AgentShield Security Gate: Request blocked due to detected security policy violation."
            if is_blocked
            else None
        ),
        "modified_input": policy.modified_input,
        "policy_decision": policy.model_dump(mode="json"),
        "request_id": payload.request_id,
    }


class PolicyGateway:
    """Legacy facade delegating policy semantics to the canonical engine."""

    @classmethod
    def enforce_policy(
        cls,
        threat_report: Dict[str, Any],
        normalized_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Convert an old report into canonical models and evaluate once.

        This method exists only for compatibility with archived benchmark code;
        it deliberately does not recreate the old ``HARD_BLOCK``/
        ``SANITIZE_PIVOT`` threshold path.
        """
        score = max(0.0, min(1.0, float(threat_report.get("unified_risk_score", 0.0))))
        vectors = [str(value) for value in threat_report.get("detected_threat_vectors", [])]
        threat_level = str(threat_report.get("threat_level", "LOW")).upper()
        rule_flags = [f"THREAT_VECTOR:{vector}" for vector in vectors]
        if not rule_flags and threat_level in {"HIGH", "CRITICAL"}:
            rule_flags.append(f"THREAT_LEVEL:{threat_level}")

        normalized_input = normalized_payload.get(
            "augmented_eval_prompt",
            normalized_payload.get("normalized_input", normalized_payload.get("raw_input", "")),
        )
        analysis = SecurityAnalysisResult(
            request_id=str(normalized_payload.get("request_id", "legacy-policy-gateway")),
            timestamp=str(normalized_payload.get("timestamp", "")),
            normalized_input=normalized_input,
            rule_flags=rule_flags,
            raw_signals={"threat_evaluator": threat_report},
            risk_score=score,
            is_flagged=bool(rule_flags or score >= POLICY_BLOCK_THRESHOLD),
        )
        risk = RiskScoreResult(
            score=score,
            level=RiskScorer.level_for_score(score),
            contributing_factors=[f"Legacy threat vector: {vector}" for vector in vectors],
        )
        policy = PolicyEngine.evaluate(analysis, risk)
        payload = SecurityPayload(
            request_id=analysis.request_id,
            timestamp=analysis.timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            source="legacy_policy_gateway",
            target="agent_orchestrator",
            raw_input=str(normalized_payload.get("raw_input", normalized_input)),
            normalized_input=normalized_input,
            normalization_metadata=normalized_payload.get("metadata", {}),
        )
        enforcement = _enforcement_from_models(payload, analysis, risk, policy)
        TelemetryLogger.log_telemetry_event(threat_report, enforcement, normalized_payload)
        return enforcement


def agentshield_interceptor_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Compatibility LangGraph node backed by the canonical pipeline."""
    user_query = state.get("user_query", "")
    result = SecurityPipeline.evaluate(
        user_query,
        source="inter_agent",
        target="agent_orchestrator",
    )
    enforcement = _enforcement_from_models(
        result.payload, result.analysis, result.risk, result.policy
    )
    threat_report = result.analysis.raw_signals.get("canonical_pipeline", {})

    if result.policy.action == Decision.BLOCK:
        return {
            "status": "BLOCKED",
            "is_blocked": True,
            "policy_decision": enforcement,
            "threat_report": threat_report,
            "user_query": None,
            "final_output": {
                "error": "Execution BLOCK by AgentShield Security Gate",
                "reason": result.policy.reason,
            },
        }

    return {
        "status": enforcement["status"],
        "is_blocked": False,
        "policy_decision": enforcement,
        "threat_report": threat_report,
        "user_query": result.policy.modified_input or result.payload.normalized_input,
    }
