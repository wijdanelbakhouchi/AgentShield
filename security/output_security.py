"""Final user-visible output security boundary.

The finalizer's structured-model validation only establishes shape.  This
module is the independent, deterministic boundary that examines the *actual*
formatted content returned by an LLM before it leaves AgentShield.  It is not
a factuality guarantee; it enforces leakage, instruction-echo, and metadata
containment rules.
"""

from __future__ import annotations

import re
from typing import Iterable

from pydantic import BaseModel, Field

from policy.sanitizer import InputSanitizer
from state import Decision, FinalOutputModel


class OutputSecurityResult(BaseModel):
    """Auditable disposition for the final user-visible answer."""

    decision: Decision
    findings: list[str] = Field(default_factory=list)
    sanitized: bool = False
    safe_output: FinalOutputModel | None = None
    reason: str


class FinalOutputSecurityValidator:
    """DLP and instruction-echo checks for the final response boundary."""

    _BLOCK_PATTERNS: tuple[tuple[str, str], ...] = (
        (r"(?i)\bsk-[a-z0-9]{20,}\b", "OUTPUT_DLP:OPENAI_KEY"),
        (r"\bAIzaSy[a-zA-Z0-9_-]{33}\b", "OUTPUT_DLP:GEMINI_KEY"),
        (r"\bAKIA[0-9A-Z]{16}\b", "OUTPUT_DLP:AWS_ACCESS_KEY"),
        (r"(?i)\b(?:gsk|xox[baprs])_[a-z0-9_-]{16,}\b", "OUTPUT_DLP:API_TOKEN"),
        (r"(?i)\bbearer\s+[a-z0-9._~+/-]{16,}\b", "OUTPUT_DLP:BEARER_TOKEN"),
        (r"(?i)\b(?:password|secret|api[_ -]?key)\s*[:=]\s*[^\s]{8,}", "OUTPUT_DLP:SECRET_VALUE"),
        # Educational answers commonly say "a system prompt is ...". Only
        # treat possessive disclosures or instruction-like assignments as
        # leakage; a generic definition must remain answerable.
        (r"(?i)\b(?:my|our)\s+(?:system|developer|internal)\s+(?:prompt|instructions?|policy)\s*(?:(?:is|are)\b|[:=])", "OUTPUT_LEAKAGE:INTERNAL_INSTRUCTIONS"),
        (r"(?i)\b(?:system|developer|internal)\s+(?:prompt|instructions?|policy)\s*(?:is|are|[:=])\s*(?:you\s+(?:are|must|should)|ignore\b|disregard\b|bypass\b|reveal\b|do\s+not\b|never\b)", "OUTPUT_LEAKAGE:INTERNAL_INSTRUCTIONS"),
        (r"(?i)\b(?:here is|below is|reveal|dump)\b.{0,80}\b(?:my |the )?(?:system|developer|internal)\s+(?:prompt|instructions?|policy)\b", "OUTPUT_LEAKAGE:INTERNAL_INSTRUCTIONS"),
        (r"(?i)\b(?:tool_execution_id|handoff_id|provenance_by_field|security_analysis)\b\s*[:=]", "OUTPUT_LEAKAGE:INTERNAL_METADATA"),
    )
    _SANITIZE_PATTERNS: tuple[tuple[str, str], ...] = (
        (r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?|directions?)\b", "OUTPUT_ECHO:INJECTION_OVERRIDE"),
        (r"(?i)\b(?:disregard|bypass)\b.{0,50}\b(?:safety|guardrails?|instructions?|policy)\b", "OUTPUT_ECHO:SAFETY_BYPASS"),
        (r"(?i)</?(?:system|developer|agent_data|external_data|untrusted_data)[^>]*>", "OUTPUT_ECHO:INTERNAL_DELIMITER"),
        (r"(?i)\b(?:raw retrieved content|untrusted tool output)\s*:", "OUTPUT_ECHO:UNTRUSTED_CONTENT"),
    )

    @classmethod
    def _text(cls, output: FinalOutputModel) -> str:
        return "\n".join(
            [output.title, output.summary, output.detailed_content, *output.sources]
        )

    @classmethod
    def _sanitize_fields(cls, output: FinalOutputModel) -> FinalOutputModel:
        def clean(value: str) -> str:
            sanitized = InputSanitizer.sanitize(value)
            for pattern, _finding in cls._SANITIZE_PATTERNS:
                sanitized = re.sub(pattern, "[REDACTED_UNTRUSTED_INSTRUCTION]", sanitized)
            return sanitized

        return FinalOutputModel(
            title=clean(output.title)[:200] or "Response withheld for security review",
            summary=clean(output.summary)[:1_000],
            detailed_content=clean(output.detailed_content),
            sources=[clean(source)[:500] for source in output.sources],
        )

    @classmethod
    def evaluate(cls, output: FinalOutputModel) -> OutputSecurityResult:
        text = cls._text(output)
        block_findings = [finding for pattern, finding in cls._BLOCK_PATTERNS if re.search(pattern, text)]
        if block_findings:
            return OutputSecurityResult(
                decision=Decision.BLOCK,
                findings=block_findings,
                reason="Final output blocked because it contains sensitive internal data or credentials.",
            )

        sanitize_findings = [finding for pattern, finding in cls._SANITIZE_PATTERNS if re.search(pattern, text)]
        if sanitize_findings:
            safe = cls._sanitize_fields(output)
            if not safe.detailed_content.strip():
                return OutputSecurityResult(
                    decision=Decision.REVIEW,
                    findings=sanitize_findings,
                    reason="Final output requires review because unsafe content could not be safely preserved.",
                )
            return OutputSecurityResult(
                decision=Decision.SANITIZE,
                findings=sanitize_findings,
                sanitized=True,
                safe_output=safe,
                reason="Unsafe instruction-like content was redacted from the final output.",
            )

        return OutputSecurityResult(
            decision=Decision.ALLOW,
            safe_output=output,
            reason="Final output passed leakage and instruction-echo validation.",
        )


def safe_output_response(decision: Decision, findings: Iterable[str]) -> FinalOutputModel:
    """Return a non-sensitive response for blocked/reviewed final output."""

    label = "review" if decision == Decision.REVIEW else "blocked"
    return FinalOutputModel(
        title="Response withheld by AgentShield",
        summary=f"The generated response was {label} by final-output security validation.",
        detailed_content="AgentShield did not return generated content because it triggered final-output security controls.",
        sources=[],
    )
