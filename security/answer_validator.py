"""Output relevance, evidence-presence, and leakage validation component.

Performs multi-dimensional evaluation of final generated answers before they
reach the user:
1. Semantic Question-Answer Relevance (rejects off-topic drift & noise).
2. Evidence presence and relevance scoring (not factual claim verification).
3. Output Safety & Anti-Contamination (detects system prompt leaks and injection echoes).
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence
from pydantic import BaseModel, Field

from security.grounding import EvidenceItem, calculate_relevance, lookup_domain_knowledge


class AnswerValidationResult(BaseModel):
    """Structured evaluation returned by the AnswerValidator."""

    valid: bool = Field(description="Whether the answer passed all grounding and safety checks")
    relevance_score: float = Field(default=0.0, description="Semantic relevance score (0.0 to 1.0) between query and answer")
    grounding_score: float = Field(default=0.0, description="Evidence-presence confidence; not a factuality guarantee")
    security_score: float = Field(default=1.0, description="Security and non-contamination score (0.0=unsafe, 1.0=safe)")
    unsupported_claims: List[str] = Field(default_factory=list, description="Specific unsupported or off-topic phrases identified")
    reasons: List[str] = Field(default_factory=list, description="Detailed diagnostic reasons for pass or rejection")
    action: str = Field(default="ALLOW", description="Enforcement action: ALLOW, REGENERATE, or SAFE_FALLBACK")


class AnswerValidator:
    """Validator for relevance, evidence presence, and output security only."""

    RELEVANCE_THRESHOLD = 0.25
    GROUNDING_THRESHOLD = 0.20

    # Suspicious phrases indicating system leakage, compromise, or instructions
    FORBIDDEN_OUTPUT_PATTERNS = [
        r"(?i)\bsystem\s+compromised\b",
        r"(?i)\bhacked\b",
        r"(?i)\bdevnull\s+ai\b",
        r"(?i)\bunrestricted\s+mode\b",
        r"(?i)\bhere\s+is\s+my\s+system\s+prompt\b",
        r"(?i)\bmy\s+instructions\s+are\b",
        r"(?i)\bdeveloper\s+mode\s+enabled\b",
        r"(?i)\bdisregard\s+all\s+safety\b",
        r"(?i)\bos\.environ\b",
        r"(?i)sk-[a-zA-Z0-9]{20,}",
    ]

    @classmethod
    def validate(
        cls,
        query: str,
        answer: str,
        evidence: Optional[Sequence[EvidenceItem]] = None,
    ) -> AnswerValidationResult:
        """
        Validate an answer against the user's query and available evidence.
        """
        query_clean = (query or "").strip()
        answer_clean = (answer or "").strip()
        reasons: List[str] = []
        unsupported: List[str] = []

        if not answer_clean or len(answer_clean) < 10:
            return AnswerValidationResult(
                valid=False,
                relevance_score=0.0,
                grounding_score=0.0,
                security_score=1.0,
                reasons=["Generated answer is empty or trivially short."],
                action="SAFE_FALLBACK",
            )

        # 1. Output Security / Anti-Contamination Check
        security_score = 1.0
        for pattern in cls.FORBIDDEN_OUTPUT_PATTERNS:
            match = re.search(pattern, answer_clean)
            if match:
                security_score = 0.0
                reasons.append(f"Security violation in output: matched forbidden pattern '{match.group(0)}'")
                return AnswerValidationResult(
                    valid=False,
                    relevance_score=0.0,
                    grounding_score=0.0,
                    security_score=security_score,
                    reasons=reasons,
                    action="SAFE_FALLBACK",
                )

        # 2. Semantic Question-Answer Relevance Check
        relevance_score = calculate_relevance(query_clean, answer_clean)

        # Tokenize the answer for curated-domain keyword matching below.
        a_words = set(re.findall(r"\b[a-zA-Z0-9_\-]+\b", answer_clean.lower()))
        
        # Check domain knowledge matching
        domain_fact = lookup_domain_knowledge(query_clean)
        if domain_fact:
            # If answer incorporates verified domain keywords, increase relevance
            domain_kws = set(domain_fact.get("keywords", []))
            if domain_kws.intersection(a_words):
                relevance_score = max(relevance_score, 0.75)

        if relevance_score < cls.RELEVANCE_THRESHOLD:
            reasons.append(
                f"Low semantic relevance ({relevance_score:.3f} < {cls.RELEVANCE_THRESHOLD:.3f}) between question and answer."
            )
            return AnswerValidationResult(
                valid=False,
                relevance_score=relevance_score,
                grounding_score=0.0,
                security_score=security_score,
                unsupported_claims=["Output appears completely off-topic or derived from unrelated search noise."],
                reasons=reasons,
                action="REGENERATE" if domain_fact else "SAFE_FALLBACK",
            )

        # 3. Evidence presence.  No evidence is never represented as factual
        # grounding; a relevant response may still be returned with explicit
        # zero evidence confidence for this limited prototype layer.
        grounding_score = 0.0
        if evidence:
            combined_evidence_text = " ".join(ev.content for ev in evidence)
            ev_relevance = calculate_relevance(answer_clean, combined_evidence_text)
            grounding_score = max(grounding_score, ev_relevance)
            reasons.append(f"Answer has relevance-aligned support from {len(evidence)} external evidence items.")
        elif domain_fact:
            grounding_score = 0.95
            reasons.append(f"Answer matched curated local reference material for '{domain_fact['title']}'.")
        else:
            reasons.append("No external evidence was available; factual grounding was not established.")

        reasons.append("Answer passed limited relevance and output-security validation.")
        return AnswerValidationResult(
            valid=True,
            relevance_score=relevance_score,
            grounding_score=grounding_score,
            security_score=security_score,
            unsupported_claims=unsupported,
            reasons=reasons,
            action="ALLOW",
        )
