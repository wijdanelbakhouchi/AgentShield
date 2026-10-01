"""Canonical normalize -> analyze -> score -> policy orchestration.

This module is intentionally small: the gateway, analyzer, scorer, and policy
engine remain independently testable, while every entry point gets one
authoritative sequence and one result contract.
"""

import time
from typing import Optional, Union

from analyzer.risk_analyzer import RiskAnalyzer
from gateway.interceptor import SecurityGateway
from policy.policy_engine import PolicyEngine
from scoring.risk_scorer import RiskScorer
from state import SecurityPipelineResult


class SecurityPipeline:
    """Run the canonical AgentShield security pipeline exactly once."""

    @classmethod
    def evaluate(
        cls,
        payload_input: Union[str, dict],
        *,
        source: str = "user",
        target: str = "agent_orchestrator",
        context_text: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> SecurityPipelineResult:
        """Normalize, aggregate detections, score risk, and enforce policy."""
        started = time.perf_counter()
        gateway_kwargs = {
            "payload_input": payload_input,
            "source": source,
            "target": target,
        }
        # The ingress creates the request ID.  Internal handoffs pass that same
        # server-owned ID back through the canonical gateway; legacy callers
        # that omit it retain the existing UUID generation behavior.
        if request_id is not None:
            gateway_kwargs["request_id"] = request_id
        payload = SecurityGateway.process(**gateway_kwargs)
        analysis = RiskAnalyzer.analyze(payload=payload, context_text=context_text)
        risk = RiskScorer.calculate_score(analysis)
        # Expose the single canonical score to the shared analysis contract and
        # to compatibility response envelopes after scoring has completed.
        analysis.risk_score = risk.score
        semantic_flags = [
            "SEMANTIC_SIMILARITY:"
            f"{finding.get('category', 'UNKNOWN')}:"
            f"{float(finding.get('similarity', 0.0)):.3f}"
            for finding in (analysis.semantic_similarity or {}).get("findings", [])
        ]
        analysis.raw_signals["canonical_pipeline"] = {
            "risk_score": risk.score,
            "risk_level": risk.level.value,
            "detected_flags": analysis.rule_flags + analysis.context_flags + semantic_flags,
            "component_values": RiskScorer.component_values(analysis),
            "contributing_factors": risk.contributing_factors,
        }
        policy = PolicyEngine.evaluate(analysis, risk)
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)

        return SecurityPipelineResult(
            payload=payload,
            analysis=analysis,
            risk=risk,
            policy=policy,
            latency_ms=latency_ms,
        )
