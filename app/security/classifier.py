from __future__ import annotations

from app.models.schemas import AgentMessage, SecuritySignal


class HeuristicSecurityClassifier:
    """Explainable stand-in for a future local Llama/Mistral classifier."""

    name = "heuristic_classifier"

    def classify(self, message: AgentMessage) -> list[SecuritySignal]:
        text = message.content.lower()
        signals: list[SecuritySignal] = []

        suspicious_intent = count_matches(
            text,
            ["ignore", "override", "bypass", "hidden", "secret", "system prompt", "developer", "jailbreak"],
        )
        if suspicious_intent >= 2:
            signals.append(
                SecuritySignal(
                    detector=self.name,
                    category="malicious_intent",
                    severity=min(1.0, 0.35 + suspicious_intent * 0.12),
                    confidence=0.74,
                    evidence=f"{suspicious_intent} suspicious intent terms found",
                )
            )

        if message.channel in {"document", "file"} and count_matches(text, ["instruction", "ignore", "do not", "new rules"]) >= 2:
            signals.append(
                SecuritySignal(
                    detector=self.name,
                    category="indirect_injection",
                    severity=0.86,
                    confidence=0.82,
                    evidence="document contains instructions aimed at the agent",
                )
            )

        tool_name = str(message.metadata.get("tool", "")).lower()
        if tool_name and count_matches(text, ["delete", "exfiltrate", "disable", "download", "credentials"]) >= 1:
            signals.append(
                SecuritySignal(
                    detector=self.name,
                    category="tool_misuse",
                    severity=0.9,
                    confidence=0.8,
                    evidence=f"dangerous intent with requested tool '{tool_name}'",
                )
            )

        return signals


def count_matches(text: str, terms: list[str]) -> int:
    return sum(1 for term in terms if term in text)

