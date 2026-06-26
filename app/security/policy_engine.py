from __future__ import annotations

import re

from app.models.schemas import AgentMessage, Decision, RiskLevel, SecuritySignal


class PolicyEngine:
    def decide(
        self,
        level: RiskLevel,
        signals: list[SecuritySignal] | None = None,
        message: AgentMessage | None = None,
    ) -> Decision:
        categories = {signal.category for signal in signals or []}
        requested_tool = str((message.metadata if message else {}).get("tool", "")).lower()

        if level == RiskLevel.CRITICAL:
            return Decision.BLOCK
        if requested_tool in {"shell", "powershell", "cmd", "database"} and categories & {"tool_abuse", "tool_misuse"}:
            return Decision.BLOCK
        if level == RiskLevel.HIGH:
            return Decision.SANITIZE
        if level == RiskLevel.MEDIUM:
            return Decision.WARN
        return Decision.ALLOW

    def sanitize(self, message: AgentMessage) -> str:
        content = message.content
        dangerous_patterns: list[tuple[str, str]] = [
            (
                r"(?i)\b(ignore|forget|override|disable)\b.{0,90}\b(previous|above|system|developer|policy|rules|instructions)\b",
                "[removed instruction override]",
            ),
            (r"(?i)\b(reveal|print|show|leak|dump)\b.{0,90}\b(system prompt|developer message|hidden prompt)\b", "[removed data leakage request]"),
            (r"(?i)\b(api[_ -]?key|token|password|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}", "[redacted credential]"),
            (r"(?i)\bexfiltrate\b.{0,80}\b(secrets?|credentials?|tokens?|data)\b", "[removed exfiltration request]"),
            (r"(?i)\b(run|execute|call|use)\b.{0,80}\b(shell|cmd|powershell|terminal|database)\b", "[removed unsafe tool request]"),
            (r"(?i)\bdelete\b.{0,60}\b(safety logs?|logs?|files?|database records?)\b", "[removed destructive request]"),
            (r"(?i)\byou are now\b.{0,70}\b(admin|root|developer|unrestricted)\b", "[removed role hijack]"),
            (r"(?i)\b(act as|pretend to be|switch role|become)\b.{0,70}\b(admin|root|developer|unrestricted)\b", "[removed role hijack]"),
            (r"(?i)\b(bypass all safety rules|do not refuse|without restrictions|jailbreak)\b", "[removed policy bypass]"),
            (r"(?i)\b(show|reveal|print|dump)\b.{0,60}\b(chain of thought|hidden reasoning|scratchpad|private reasoning)\b", "[removed hidden reasoning request]"),
        ]
        for pattern, replacement in dangerous_patterns:
            content = re.sub(pattern, replacement, content)
        return content

    def reasons(self, decision: Decision, level: RiskLevel, signals: list[SecuritySignal]) -> list[str]:
        if not signals:
            return ["No attack indicators were found."]

        categories = sorted({signal.category for signal in signals})
        reasons = [f"Risk level is {level.value}.", f"Detected categories: {', '.join(categories)}."]
        if decision == Decision.BLOCK:
            reasons.append("Content should not be delivered to the target agent.")
        elif decision == Decision.SANITIZE:
            reasons.append("Unsafe spans should be removed before the message continues.")
        elif decision == Decision.WARN:
            reasons.append("Message can proceed, but it should be monitored.")
        return reasons

    def recommended_action(self, decision: Decision) -> str:
        actions = {
            Decision.ALLOW: "Allow the message to continue unchanged.",
            Decision.WARN: "Allow with monitoring and keep the event in the audit log.",
            Decision.SANITIZE: "Forward only sanitized_content to the target agent.",
            Decision.BLOCK: "Stop the message and ask for a safe restatement.",
        }
        return actions[decision]
