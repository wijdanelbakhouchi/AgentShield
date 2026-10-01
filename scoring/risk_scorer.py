from typing import List

from config import (
    CLASSIFIER_WEIGHT,
    CONTEXT_WEIGHT,
    RISK_HIGH_MAX,
    RISK_LOW_MAX,
    RISK_MEDIUM_MAX,
    RULE_WEIGHT,
    SEMANTIC_SIMILARITY_THRESHOLD,
    SIMILARITY_WEIGHT,
)
from state import RiskLevel, RiskScoreResult, SecurityAnalysisResult


class RiskScorer:
    """
    Risk Scoring Engine (Phase 3):
    Aggregates security signals from Phase 2/6 (Rule Based Detector, semantic
    similarity detector, LLM Security Classifier, Context Analyzer)
    using a weighted signal aggregation algorithm to compute a normalized overall Risk Score (0.0 to 1.0)
    and assign a Risk Severity Level (LOW, MEDIUM, HIGH, CRITICAL).
    """

    # Configurable Signal Weights
    RULE_TRIGGER_WEIGHT = RULE_WEIGHT
    SEMANTIC_SIMILARITY_WEIGHT = SIMILARITY_WEIGHT
    LLM_CLASSIFICATION_WEIGHT = CLASSIFIER_WEIGHT
    CONTEXT_FLAG_WEIGHT = CONTEXT_WEIGHT

    @staticmethod
    def component_values(analysis_result: SecurityAnalysisResult) -> dict[str, float]:
        """Expose normalized detector components for calibration and auditing."""
        llm_class = analysis_result.llm_classification or {}
        semantic = analysis_result.semantic_similarity or {}
        return {
            "rule": min(1.0, len(analysis_result.rule_flags) * 0.5),
            "classifier": (
                float(llm_class.get("confidence", 0.0))
                if llm_class.get("is_malicious", False)
                else 0.0
            ),
            "context": min(1.0, len(analysis_result.context_flags) * 0.60),
            # Semantic evidence is threshold-gated before entering the global
            # score.  The frozen Phase 6 detector threshold is not retuned by
            # this scorer; below-threshold cosine values contribute zero.
            "semantic_similarity": (
                max(0.0, min(1.0, float((semantic.get("top_match") or {}).get("similarity", 0.0))))
                if semantic.get("semantic_similarity_enabled")
                and semantic.get("flagged")
                and float((semantic.get("top_match") or {}).get("similarity", 0.0)) >= SEMANTIC_SIMILARITY_THRESHOLD
                else 0.0
            ),
        }

    @staticmethod
    def level_for_score(score: float) -> RiskLevel:
        """Map a normalized score using the canonical severity thresholds."""
        if score <= RISK_LOW_MAX:
            return RiskLevel.LOW
        if score <= RISK_MEDIUM_MAX:
            return RiskLevel.MEDIUM
        if score <= RISK_HIGH_MAX:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    @classmethod
    def calculate_score(
        cls, analysis_result: SecurityAnalysisResult
    ) -> RiskScoreResult:
        """
        Evaluates SecurityAnalysisResult and produces a normalized RiskScoreResult.
        """
        score_components = 0.0
        contributing_factors: List[str] = []

        rule_flags = analysis_result.rule_flags
        llm_class = analysis_result.llm_classification
        context_flags = analysis_result.context_flags
        semantic = analysis_result.semantic_similarity or {}

        components = cls.component_values(analysis_result)

        # 1. Evaluate Rule-based Triggers (calibrated weight)
        if rule_flags:
            rule_score = cls.RULE_TRIGGER_WEIGHT * components["rule"]
            score_components += rule_score
            for flag in rule_flags:
                contributing_factors.append(f"Rule Triggered: {flag}")
        else:
            contributing_factors.append("No rule-based security flags triggered")

        # 2. Evaluate LLM Semantic Classification (calibrated weight)
        if llm_class.get("is_malicious", False):
            category = llm_class.get("category", "Unknown Malicious")
            confidence = float(llm_class.get("confidence", 0.85))
            llm_score = cls.LLM_CLASSIFICATION_WEIGHT * components["classifier"]
            score_components += llm_score
            contributing_factors.append(
                f"LLM Classification: {category} (Confidence: {confidence:.2f})"
            )
        else:
            contributing_factors.append("LLM Classification: Benign / Safe")

        # 3. Evaluate Context Anomaly Flags (calibrated weight)
        if context_flags:
            context_score = cls.CONTEXT_FLAG_WEIGHT * components["context"]
            score_components += context_score
            for c_flag in context_flags:
                contributing_factors.append(f"Context Anomaly: {c_flag}")
        else:
            contributing_factors.append("No context anomalies detected")

        # 4. Evaluate real semantic similarity evidence (post-hardening weight)
        semantic_signal = components["semantic_similarity"]
        if semantic_signal > 0.0:
            top = semantic.get("top_match") or {}
            semantic_score = cls.SEMANTIC_SIMILARITY_WEIGHT * semantic_signal
            score_components += semantic_score
            contributing_factors.append(
                "Semantic Similarity: "
                f"{top.get('category', 'UNKNOWN')} similarity={semantic_signal:.3f} "
                f"contribution={semantic_score:.3f}"
            )
        elif semantic.get("status") in {"unavailable", "disabled"}:
            contributing_factors.append(
                f"Semantic Similarity: {semantic.get('status')} (no lexical fallback)"
            )
        else:
            contributing_factors.append("No semantic similarity threshold finding")

        # Normalize score between 0.0 and 1.0.  The validated simplex means the
        # unclipped result is already bounded, while clipping protects callers
        # that construct legacy analysis objects with malformed values.
        final_score = round(min(1.0, max(0.0, score_components)), 2)

        # Categorize Risk Level
        risk_level = cls.level_for_score(final_score)

        return RiskScoreResult(
            score=final_score,
            level=risk_level,
            contributing_factors=contributing_factors,
        )
