from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

from app.models.schemas import AgentMessage, SecuritySignal


@dataclass(frozen=True)
class DetectionRule:
    category: str
    pattern: str
    severity: float
    confidence: float
    evidence: str


class RuleBasedDetector:
    """Detects known prompt-injection patterns with transparent rules."""

    name = "rule_detector"
    decoded_name = "decoded_payload_detector"

    RULES: tuple[DetectionRule, ...] = (
        DetectionRule(
            "prompt_injection",
            r"\b(ignore|forget|override|disable)\b.{0,90}\b(previous|above|system|developer|policy|rules)\b",
            0.95,
            0.92,
            "attempt to override trusted instructions",
        ),
        DetectionRule(
            "data_leakage",
            r"\b(reveal|print|show|leak|exfiltrate|dump)\b.{0,90}\b(system prompt|developer message|hidden prompt|secret|token|api key|password)\b",
            1.0,
            0.93,
            "attempt to extract sensitive information",
        ),
        DetectionRule(
            "role_hijacking",
            r"\b(act as|you are now|pretend to be|switch role|become)\b.{0,80}\b(admin|root|developer|security bypass|unrestricted)\b",
            0.82,
            0.82,
            "attempt to change agent role",
        ),
        DetectionRule(
            "tool_abuse",
            r"\b(run|execute|call|use)\b.{0,80}\b(shell|cmd|powershell|terminal|delete|download|database|file system)\b",
            0.84,
            0.78,
            "unsafe tool execution request",
        ),
        DetectionRule(
            "policy_bypass",
            r"\b(no safety|bypass|jailbreak|without restrictions|do not refuse|ignore safety)\b",
            0.88,
            0.78,
            "policy bypass language",
        ),
        DetectionRule(
            "obfuscation",
            r"\b(base64|rot13|unicode|zero width|encoded|decode this)\b",
            0.66,
            0.72,
            "possible obfuscation",
        ),
        DetectionRule(
            "prompt_boundary_smuggling",
            r"(^|\n)\s*(system|developer|admin)\s*[:#-].{0,80}\b(ignore|override|bypass|new rules)\b",
            0.86,
            0.76,
            "message appears to inject a trusted prompt boundary",
        ),
        DetectionRule(
            "reasoning_extraction",
            r"\b(show|reveal|print|dump)\b.{0,60}\b(chain of thought|hidden reasoning|scratchpad|private reasoning)\b",
            0.72,
            0.78,
            "attempt to extract hidden reasoning",
        ),
        DetectionRule(
            "credential_literal",
            r"\b(api[_ -]?key|token|password|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}",
            0.82,
            0.84,
            "message contains a credential-like literal",
        ),
    )

    def analyze(self, message: AgentMessage) -> list[SecuritySignal]:
        normalized = normalize(message.content)
        signals: list[SecuritySignal] = []
        self._apply_rules(normalized, signals, detector=self.name)
        self._detect_indirect_injection(message, normalized, signals)
        self._detect_encoded_payloads(normalized, signals)
        return signals

    def _apply_rules(
        self,
        text: str,
        signals: list[SecuritySignal],
        *,
        detector: str,
        evidence_prefix: str = "",
    ) -> None:
        for rule in self.RULES:
            if re.search(rule.pattern, text, flags=re.IGNORECASE | re.DOTALL):
                signals.append(
                    SecuritySignal(
                        detector=detector,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        evidence=evidence_prefix + rule.evidence,
                    )
                )

    def _detect_indirect_injection(
        self,
        message: AgentMessage,
        normalized: str,
        signals: list[SecuritySignal],
    ) -> None:
        if message.channel not in {"document", "file", "web", "retrieval"}:
            return

        has_instruction_marker = re.search(
            r"\b(new instructions?|follow these instructions?|system prompt|developer note)\b",
            normalized,
            flags=re.IGNORECASE,
        )
        has_agent_directive = re.search(
            r"\b(ignore|override|do not summarize|do not tell|send|exfiltrate)\b",
            normalized,
            flags=re.IGNORECASE,
        )
        if has_instruction_marker and has_agent_directive:
            signals.append(
                SecuritySignal(
                    detector=self.name,
                    category="indirect_injection",
                    severity=0.9,
                    confidence=0.86,
                    evidence=f"{message.channel} content contains instructions aimed at the agent",
                )
            )

    def _detect_encoded_payloads(self, normalized: str, signals: list[SecuritySignal]) -> None:
        for candidate in find_base64_candidates(normalized):
            decoded = decode_base64_candidate(candidate)
            if not decoded:
                continue
            before = len(signals)
            self._apply_rules(
                normalize(decoded),
                signals,
                detector=self.decoded_name,
                evidence_prefix="decoded payload: ",
            )
            if len(signals) > before:
                signals.append(
                    SecuritySignal(
                        detector=self.decoded_name,
                        category="obfuscation",
                        severity=0.78,
                        confidence=0.82,
                        evidence="base64 payload decoded to unsafe instructions",
                    )
                )
                return


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = translate_common_homoglyphs(text)
    text = re.sub(r"[\u200b-\u200f\ufeff]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def translate_common_homoglyphs(text: str) -> str:
    replacements = str.maketrans(
        {
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "х": "x",
            "у": "y",
            "і": "i",
            "А": "A",
            "Е": "E",
            "О": "O",
            "Р": "P",
            "С": "C",
            "Х": "X",
            "У": "Y",
            "І": "I",
        }
    )
    return text.translate(replacements)


def find_base64_candidates(text: str) -> list[str]:
    return re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text)


def decode_base64_candidate(candidate: str) -> str | None:
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None

    if not decoded or sum(32 <= byte <= 126 or byte in {9, 10, 13} for byte in decoded) / len(decoded) < 0.85:
        return None
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
