from __future__ import annotations

from app.models.schemas import RiskLevel, SecuritySignal


class RiskEngine:
    weights = {
        "prompt_injection": 1.0,
        "data_leakage": 1.0,
        "tool_misuse": 0.95,
        "tool_abuse": 0.9,
        "indirect_injection": 0.95,
        "role_hijacking": 0.86,
        "malicious_intent": 0.74,
        "policy_bypass": 0.82,
        "obfuscation": 0.55,
        "prompt_boundary_smuggling": 0.92,
        "reasoning_extraction": 0.72,
        "credential_literal": 0.88,
    }

    def score(self, signals: list[SecuritySignal]) -> float:
        if not signals:
            return 0.0

        category_scores: dict[str, float] = {}
        detector_names = set()
        high_confidence_signals = 0

        for signal in signals:
            weighted = signal.score * self.weights.get(signal.category, 0.5)
            category_scores[signal.category] = max(category_scores.get(signal.category, 0.0), weighted)
            detector_names.add(signal.detector)
            high_confidence_signals += int(signal.confidence >= 0.8)

        strongest = max(category_scores.values())
        pressure = sum(category_scores.values()) * 0.16
        diversity_bonus = max(0, len(category_scores) - 1) * 0.04
        corroboration_bonus = 0.05 if len(detector_names) >= 2 and high_confidence_signals >= 2 else 0.0

        return round(min(1.0, strongest + pressure + diversity_bonus + corroboration_bonus), 4)

    def top_categories(self, signals: list[SecuritySignal], limit: int = 3) -> list[str]:
        category_scores: dict[str, float] = {}
        for signal in signals:
            weighted = signal.score * self.weights.get(signal.category, 0.5)
            category_scores[signal.category] = max(category_scores.get(signal.category, 0.0), weighted)
        return [
            category
            for category, _ in sorted(category_scores.items(), key=lambda item: item[1], reverse=True)[:limit]
        ]

    def legacy_score(self, signals: list[SecuritySignal]) -> float:
        if not signals:
            return 0.0

        strongest = 0.0
        total_pressure = 0.0
        for signal in signals:
            weighted = signal.score * self.weights.get(signal.category, 0.5)
            strongest = max(strongest, weighted)
            total_pressure += weighted * 0.16

        return round(min(1.0, strongest + total_pressure), 4)

    def level(self, score: float) -> RiskLevel:
        if score >= 0.8:
            return RiskLevel.CRITICAL
        if score >= 0.6:
            return RiskLevel.HIGH
        if score >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
