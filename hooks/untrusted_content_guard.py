"""Canonical containment boundary for externally supplied textual content.

This service is intentionally source-agnostic.  Web, database, document, and
generic tool results use the same normalize -> analyze -> score -> policy
sequence before an agent can consume them.
"""

from __future__ import annotations

import datetime
import time
from typing import Any, List

from config import MAX_INPUT_LENGTH
from hooks.context_isolator import isolate_external_content
from policy.sanitizer import InputSanitizer
from security.pipeline import SecurityPipeline
from state import (
    Decision,
    RiskLevel,
    TrustLevel,
    UntrustedContent,
    UntrustedContentSecurityResult,
)


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class UntrustedContentGuard:
    """Inspect untrusted content through the frozen canonical security stack."""

    # The normalizer is bounded at MAX_INPUT_LENGTH.  Tool output is inspected
    # in at most two overlapping chunks; output beyond that bound is blocked
    # rather than partially trusted.  This is a resource guard, not a score or
    # detector calibration change.
    MAX_INSPECTION_CHUNKS = 2
    CHUNK_OVERLAP = 1024

    @classmethod
    def inspect(
        cls,
        content: UntrustedContent,
        *,
        tool_execution_id: str | None = None,
    ) -> UntrustedContentSecurityResult:
        """Return an ALLOW/SANITIZE/REVIEW/BLOCK result for one content envelope."""
        started = time.perf_counter()
        try:
            chunks = cls._inspection_chunks(content.text)
            if chunks is None:
                return cls._failed_closed(
                    content,
                    tool_execution_id,
                    "UNTRUSTED_CONTENT_TOO_LARGE",
                    "Tool output exceeded the bounded inspection capacity.",
                    started,
                )

            results = [
                SecurityPipeline.evaluate(
                    chunk,
                    source="external_untrusted",
                    target="untrusted_content_guard",
                    context_text=chunk,
                    request_id=content.request_id,
                )
                for chunk in chunks
            ]
            priority = {Decision.ALLOW: 0, Decision.SANITIZE: 1, Decision.REVIEW: 2, Decision.BLOCK: 3}
            selected = max(results, key=lambda result: (priority[result.policy.action], result.risk.score))
            decision = Decision(selected.policy.action.value)
            findings = cls._findings(selected)
            transforms = cls._transforms(selected)
            safe_content = None

            if decision == Decision.ALLOW:
                # The full text is safe only after every bounded chunk passed
                # canonical inspection.  Delimiters are additional mitigation,
                # never the security decision itself.
                safe_content = isolate_external_content(
                    content.text,
                    source_type=content.source_type,
                    source_name=content.source_name,
                    trust_level=TrustLevel.INSPECTED_SAFE.value,
                )
            elif decision == Decision.SANITIZE:
                if len(chunks) > 1:
                    return cls._failed_closed(content, tool_execution_id,
                        "UNTRUSTED_CONTENT_MULTICHUNK_SANITIZE",
                        "Multi-chunk content requires review instead of forwarding a partial sanitized result.", started)
                candidate = selected.policy.modified_input or InputSanitizer.sanitize(content.text)
                # A SANITIZE decision must never forward the untouched raw
                # value.  If meaningful sanitization is unavailable, contain.
                if not candidate or candidate == content.text:
                    return cls._failed_closed(
                        content,
                        tool_execution_id,
                        "UNTRUSTED_CONTENT_SANITIZATION_UNSAFE",
                        "Canonical policy requested sanitization without a distinct safe output.",
                        started,
                    )
                safe_content = isolate_external_content(
                    candidate,
                    source_type=content.source_type,
                    source_name=content.source_name,
                    trust_level=TrustLevel.INSPECTED_SAFE.value,
                )

            semantic = selected.analysis.semantic_similarity or {}
            return UntrustedContentSecurityResult(
                content_id=content.content_id,
                request_id=content.request_id,
                source_type=content.source_type,
                source_name=content.source_name,
                tool_execution_id=tool_execution_id,
                risk_score=float(selected.risk.score),
                risk_level=selected.risk.level,
                decision=decision,
                findings=findings,
                transforms=transforms,
                original_content=content.text,
                safe_content=safe_content,
                inspected=True,
                trust_level=(TrustLevel.INSPECTED_SAFE if safe_content is not None else TrustLevel.EXTERNAL_UNTRUSTED),
                timestamp=_utc_now(),
                latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
                reason=selected.policy.reason,
                semantic_available=bool(semantic.get("semantic_similarity_enabled")),
            )
        except Exception as exc:
            return cls._failed_closed(
                content,
                tool_execution_id,
                "UNTRUSTED_CONTENT_SECURITY_ERROR",
                f"Untrusted-content inspection failed closed: {exc.__class__.__name__}",
                started,
            )

    @classmethod
    def _inspection_chunks(cls, text: str) -> List[str] | None:
        value = str(text or "")
        if len(value) <= MAX_INPUT_LENGTH:
            return [value]
        stride = MAX_INPUT_LENGTH - cls.CHUNK_OVERLAP
        chunks = [value[start : start + MAX_INPUT_LENGTH] for start in range(0, len(value), stride)]
        if len(chunks) > cls.MAX_INSPECTION_CHUNKS:
            return None
        return chunks

    @staticmethod
    def _findings(result: Any) -> List[str]:
        semantic = result.analysis.semantic_similarity or {}
        semantic_findings = [
            "SEMANTIC_SIMILARITY:{category}:{similarity:.3f}".format(
                category=item.get("category", "UNKNOWN"),
                similarity=float(item.get("similarity", 0.0)),
            )
            for item in semantic.get("findings", [])
        ]
        return list(dict.fromkeys(
            list(result.analysis.rule_flags)
            + list(result.analysis.context_flags)
            + semantic_findings
        ))

    @staticmethod
    def _transforms(result: Any) -> List[str]:
        return list(dict.fromkeys(
            transform
            for representation in result.payload.normalization_metadata.get("representations", [])
            for transform in representation.get("provenance", [])
        ))

    @classmethod
    def _failed_closed(
        cls,
        content: UntrustedContent,
        tool_execution_id: str | None,
        finding: str,
        reason: str,
        started: float,
    ) -> UntrustedContentSecurityResult:
        return UntrustedContentSecurityResult(
            content_id=content.content_id,
            request_id=content.request_id,
            source_type=content.source_type,
            source_name=content.source_name,
            tool_execution_id=tool_execution_id,
            risk_score=1.0,
            risk_level=RiskLevel.CRITICAL,
            decision=Decision.BLOCK,
            findings=[finding],
            transforms=[],
            original_content=content.text,
            safe_content=None,
            inspected=False,
            trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
            timestamp=_utc_now(),
            latency_ms=round((time.perf_counter() - started) * 1000.0, 2),
            reason=reason,
            semantic_available=None,
        )
