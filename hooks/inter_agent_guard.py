"""Canonical zero-trust security boundary for LangGraph agent handoffs.

The guard is deliberately the only component that evaluates inter-agent
content. Graph nodes create a server-owned :class:`AgentHandoff`, call this
service, and route on the resulting policy decision. Agent-produced fields
are never used as security or graph-control metadata.
"""

from __future__ import annotations

import datetime
import time
import uuid
from typing import Any, Callable, Dict, Optional

from config import (
    PROVENANCE_BONUS_PER_DEPTH,
    PROVENANCE_BONUS_PRIVILEGED_TARGET,
    PROVENANCE_BONUS_UNTRUSTED,
    PROVENANCE_ENABLED,
    PROVENANCE_MAX_DEPTH_BONUS,
)
from hooks.request_context import ContextAuditLog, current_request_id, set_request_id, reset_request_id
from policy.policy_engine import PolicyEngine
from policy.sanitizer import InputSanitizer
from schema.interception import AgentHandoffEvent
from scoring.risk_scorer import RiskScorer
from security.pipeline import SecurityPipeline
from security.provenance import provenance_adjustment
from state import AgentHandoff, AgentState, Decision, HandoffSecurityResult, RiskLevel, RiskScoreResult


AGENT_HANDOFF_AUDIT_LOG: ContextAuditLog[AgentHandoffEvent] = ContextAuditLog(
    "agentshield_handoff_audit"
)


def set_current_request_id(request_id: str) -> None:
    """Set the request correlation value used by legacy callers."""
    set_request_id(request_id)


def reset_current_request_id() -> None:
    """Reset request correlation in the active context."""
    reset_request_id()


def reset_handoff_audit_log() -> None:
    """Clear the shared audit list without invalidating imported references."""
    AGENT_HANDOFF_AUDIT_LOG.clear()


class HandoffBlockedError(RuntimeError):
    """Backward-compatible exception for direct (non-graph) guard callers."""

    def __init__(
        self,
        from_agent: str,
        to_agent: str,
        reason: str,
        risk_score: float,
        request_id: str = "",
        handoff_id: str = "",
    ) -> None:
        self.from_agent = from_agent
        self.to_agent = to_agent
        self.reason = reason
        self.risk_score = risk_score
        self.request_id = request_id
        self.handoff_id = handoff_id
        super().__init__(
            f"[HANDOFF BLOCKED] {from_agent} → {to_agent} | "
            f"Risk: {risk_score:.2f} | Reason: {reason}"
        )


HANDOFF_FIELD_MAP: Dict[tuple[str, str], str] = {
    ("researcher", "planner"): "research_data",
    ("planner", "writer"): "plan",
    ("writer", "finalizer"): "draft_response",
}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _decision_value(decision: Any) -> str:
    return decision.value if hasattr(decision, "value") else str(decision)


class InterAgentGuard:
    """One authoritative zero-trust handoff evaluator."""

    @classmethod
    def evaluate_handoff(
        cls,
        handoff: AgentHandoff,
        *,
        intercepted_field: str = "",
    ) -> HandoffSecurityResult:
        """Inspect one handoff through the canonical normalize-to-policy stack.

        Unexpected detector, model, or telemetry errors fail closed and still
        emit a structured event, so a transient security failure can never
        route uninspected content to the next agent.
        """
        started = time.perf_counter()
        try:
            pipeline_result = SecurityPipeline.evaluate(
                handoff.content,
                source="inter_agent",
                target=handoff.target_agent,
                request_id=handoff.request_id,
            )
            analysis = pipeline_result.analysis
            semantic = analysis.semantic_similarity or {}
            semantic_findings = [
                "SEMANTIC_SIMILARITY:{category}:{similarity:.3f}".format(
                    category=item.get("category", "UNKNOWN"),
                    similarity=float(item.get("similarity", 0.0)),
                )
                for item in semantic.get("findings", [])
            ]
            flags = list(analysis.rule_flags) + list(analysis.context_flags)
            flags.extend(semantic_findings)
            if (analysis.llm_classification or {}).get("is_malicious"):
                category = (analysis.llm_classification or {}).get(
                    "category", "MALICIOUS_CONTENT"
                )
                flags.append(f"LLM_CLASSIFICATION:{category}")

            policy = pipeline_result.policy

            # Phase 19 provenance-aware enforcement.  When the handed-off
            # content carries message-level provenance and a bonus is
            # configured, the effective score is recomputed and the policy
            # re-evaluated on that adjusted score.  All bonuses default to 0,
            # preserving the frozen calibrated operating point exactly.
            provenance_info = dict(handoff.provenance or {})
            provenance_flags: list[str] = []
            base_score = float(pipeline_result.risk.score)
            effective_score = base_score
            adjustment_record: dict[str, Any] = {}
            if PROVENANCE_ENABLED and provenance_info:
                tainted = bool(provenance_info.get("tainted"))
                depth = int(provenance_info.get("propagation_depth") or 0)
                origins = [str(item) for item in provenance_info.get("origins", [])]
                if tainted:
                    provenance_flags.append("PROVENANCE:TAINTED")
                if depth:
                    provenance_flags.append(f"PROVENANCE:DEPTH:{depth}")
                for origin in origins:
                    provenance_flags.append(f"PROVENANCE:ORIGIN:{origin.upper()}")
                adjustment_record = provenance_adjustment(
                    base_score=base_score,
                    tainted=tainted,
                    propagation_depth=depth,
                    target_agent=handoff.target_agent,
                    bonus_untrusted=PROVENANCE_BONUS_UNTRUSTED,
                    bonus_per_depth=PROVENANCE_BONUS_PER_DEPTH,
                    bonus_privileged_target=PROVENANCE_BONUS_PRIVILEGED_TARGET,
                    max_depth_bonus=PROVENANCE_MAX_DEPTH_BONUS,
                )
                if adjustment_record.get("applied"):
                    effective_score = float(adjustment_record["effective_score"])
                    adjusted_risk = RiskScoreResult(
                        score=effective_score,
                        level=RiskScorer.level_for_score(effective_score),
                        contributing_factors=(
                            list(pipeline_result.risk.contributing_factors)
                            + [
                                "Provenance-aware adjustment: "
                                + ", ".join(adjustment_record.get("contributions", []))
                            ]
                        ),
                    )
                    policy = PolicyEngine.evaluate(pipeline_result.analysis, adjusted_risk)

            decision_value = _decision_value(policy.action)
            try:
                decision = Decision(decision_value)
            except ValueError:
                # Unknown policy actions must never become an implicit allow.
                decision = Decision.BLOCK

            safe_content: Optional[str] = None
            sanitized = decision == Decision.SANITIZE
            if decision in {Decision.ALLOW, Decision.SANITIZE}:
                safe_content = (
                    policy.modified_input or pipeline_result.payload.normalized_input
                )
                if decision == Decision.SANITIZE and not safe_content:
                    safe_content = InputSanitizer.sanitize(handoff.content)

            flags.extend(provenance_flags)
            result = HandoffSecurityResult(
                request_id=handoff.request_id,
                handoff_id=handoff.handoff_id,
                source_agent=handoff.source_agent,
                target_agent=handoff.target_agent,
                risk_score=effective_score,
                risk_level=policy.risk_metrics.level,
                decision=decision,
                flags=flags,
                findings=list(flags),
                original_content=handoff.content,
                safe_content=safe_content,
                timestamp=_utc_now(),
                latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
                sanitized=sanitized,
                blocked=decision == Decision.BLOCK,
                reason=policy.reason,
                semantic_available=bool(semantic.get("semantic_similarity_enabled")),
                provenance={
                    key: provenance_info.get(key)
                    for key in (
                        "message_id",
                        "field",
                        "source_agent",
                        "origins",
                        "trust_level",
                        "tainted",
                        "propagation_depth",
                        "attack_id",
                    )
                },
                base_risk_score=base_score,
                provenance_adjustment=adjustment_record,
            )
        except Exception as exc:  # fail closed at the security boundary
            result = HandoffSecurityResult(
                request_id=handoff.request_id,
                handoff_id=handoff.handoff_id,
                source_agent=handoff.source_agent,
                target_agent=handoff.target_agent,
                risk_score=1.0,
                risk_level=RiskLevel.CRITICAL,
                decision=Decision.BLOCK,
                flags=["SECURITY_ERROR"],
                findings=["SECURITY_ERROR"],
                original_content=handoff.content,
                safe_content=None,
                timestamp=_utc_now(),
                latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
                blocked=True,
                reason=f"Inter-agent security evaluation failed closed: {exc.__class__.__name__}",
                semantic_available=None,
            )

        cls._emit_audit(
            result,
            intercepted_field=intercepted_field
            or HANDOFF_FIELD_MAP.get(
                (handoff.source_agent, handoff.target_agent), "unknown"
            ),
        )
        return result

    @classmethod
    def inspect_handoff(
        cls,
        from_agent: str,
        to_agent: str,
        state: AgentState,
        field_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compatibility adapter returning a state delta for direct callers."""
        intercepted_field = field_override or HANDOFF_FIELD_MAP.get(
            (from_agent, to_agent), "unknown_field"
        )
        raw_payload = str(state.get(intercepted_field, "") or "")
        request_id = str(state.get("request_id") or current_request_id())
        if not request_id or request_id == "req-default":
            request_id = f"req-{uuid.uuid4().hex[:12]}"
        handoff = AgentHandoff(
            handoff_id=f"handoff-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            source_agent=from_agent,
            target_agent=to_agent,
            content=raw_payload,
            timestamp=_utc_now(),
        )
        result = cls.evaluate_handoff(handoff, intercepted_field=intercepted_field)
        if result.decision in {Decision.BLOCK, Decision.REVIEW}:
            raise HandoffBlockedError(
                from_agent=from_agent,
                to_agent=to_agent,
                reason=result.reason or result.decision.value,
                risk_score=result.risk_score,
                request_id=result.request_id,
                handoff_id=result.handoff_id,
            )
        return {intercepted_field: result.safe_content or ""}

    @classmethod
    def _emit_audit(cls, result: HandoffSecurityResult, *, intercepted_field: str) -> None:
        event = AgentHandoffEvent(
            source_agent=result.source_agent,
            target_agent=result.target_agent,
            request_id=result.request_id,
            handoff_id=result.handoff_id,
            timestamp=result.timestamp,
            intercepted_field=intercepted_field,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            decision=result.decision,
            sanitized=result.sanitized,
            flags=result.flags,
            findings=result.findings,
            latency_ms=result.latency_ms,
            blocked=result.blocked,
            reason=result.reason,
        )
        AGENT_HANDOFF_AUDIT_LOG.append(event)
        # Persistence/alerting is best-effort; failure cannot turn a block into
        # an allow because the security decision was already made.
        try:
            from logging.alerting import AlertEngine
            from logging.event_logger import EventLogger

            EventLogger.log_handoff_event(event, request_id=result.request_id)
            AlertEngine.evaluate_handoff_event(event, request_id=result.request_id)
        except Exception:
            pass
        try:
            icon = {
                "ALLOW": "[ALLOW]",
                "SANITIZE": "[CLEAN]",
                "REVIEW": "[REVIEW]",
                "BLOCK": "[BLOCK]",
            }.get(result.decision.value, "[INFO]")
            print(
                f"  {icon} [HANDOFF GUARD] {result.source_agent.upper()} -> "
                f"{result.target_agent.upper()} | Risk: {result.risk_score:.2f} "
                f"[{result.risk_level.value}] | Action: {result.decision.value}"
            )
        except Exception:
            pass


def guarded_node(
    from_agent: str,
    to_agent: str,
    node_fn: Callable[[AgentState], dict],
    intercepted_field: Optional[str] = None,
) -> Callable[[AgentState], dict]:
    """Legacy wrapper retained for direct integrations.

    The active Phase 7 graph uses explicit guard nodes and conditional edges;
    this adapter delegates to the same canonical service and cannot bypass it.
    """

    def _guarded_wrapper(state: AgentState) -> dict:
        node_output = dict(node_fn(state) or {})
        merged_state = dict(state)
        merged_state.update(node_output)
        guard_result = InterAgentGuard.inspect_handoff(
            from_agent=from_agent,
            to_agent=to_agent,
            state=merged_state,
            field_override=intercepted_field,
        )
        node_output.update(guard_result)
        return node_output

    _guarded_wrapper.__name__ = f"guarded_{node_fn.__name__}"
    return _guarded_wrapper
