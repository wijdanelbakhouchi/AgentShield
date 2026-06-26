from __future__ import annotations

from time import perf_counter

from app.models.schemas import AgentMessage, Decision, SecurityDecision, SecuritySignal
from app.security.classifier import HeuristicSecurityClassifier
from app.security.detector import RuleBasedDetector
from app.security.monitor import SecurityMonitor
from app.security.policy_engine import PolicyEngine
from app.security.risk_engine import RiskEngine


class SecurityGateway:
    """Intercepts messages and applies the complete AgentShield security pipeline."""

    def __init__(self, monitor: SecurityMonitor | None = None) -> None:
        self.detector = RuleBasedDetector()
        self.classifier = HeuristicSecurityClassifier()
        self.risk_engine = RiskEngine()
        self.policy_engine = PolicyEngine()
        self.monitor = monitor or SecurityMonitor()

    def inspect(self, message: AgentMessage) -> SecurityDecision:
        started = perf_counter()
        signals = self.detector.analyze(message)
        signals.extend(self.classifier.classify(message))

        risk_score = self.risk_engine.score(signals)
        risk_level = self.risk_engine.level(risk_score)
        decision = self.policy_engine.decide(risk_level, signals=signals, message=message)
        sanitized = self.policy_engine.sanitize(message) if decision == Decision.SANITIZE else None
        latency_ms = (perf_counter() - started) * 1000

        result = SecurityDecision(
            message_id=message.message_id,
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            signals=signals,
            sanitized_content=sanitized,
            explanation=self._explain(decision, risk_score, signals),
            policy_reasons=self.policy_engine.reasons(decision, risk_level, signals),
            recommended_action=self.policy_engine.recommended_action(decision),
            latency_ms=round(latency_ms, 3),
        )
        self.monitor.record(message, result)
        return result

    def guarded_content(self, message: AgentMessage) -> tuple[bool, str, SecurityDecision]:
        result = self.inspect(message)
        if result.decision == Decision.BLOCK:
            return False, "", result
        if result.decision == Decision.SANITIZE and result.sanitized_content:
            return True, result.sanitized_content, result
        return True, message.content, result

    def _explain(self, decision: Decision, risk_score: float, signals: list[SecuritySignal]) -> str:
        if not signals:
            return "No attack indicators were found."
        categories = self.risk_engine.top_categories(signals)
        return f"Decision={decision.value} because risk={risk_score:.2f}; strongest signals={', '.join(categories)}."
