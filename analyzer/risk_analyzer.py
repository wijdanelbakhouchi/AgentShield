from typing import Optional

from analyzer.context_analyzer import ContextAnalyzer
from analyzer.llm_classifier import LLMSecurityClassifier
from analyzer.rule_detector import RuleBasedDetector
from analyzer.semantic_similarity import get_semantic_detector
from state import SecurityAnalysisResult, SecurityPayload


class RiskAnalyzer:
    """
    Risk Analyzer (Facade Layer Phase 2):
    Aggregates the active RuleBasedDetector, LLMSecurityClassifier, and
    ContextAnalyzer to produce unified security signal evidence.
    """

    @classmethod
    def analyze(
        cls,
        payload: SecurityPayload,
        context_text: Optional[str] = None,
    ) -> SecurityAnalysisResult:
        """
        Runs the active sub-detectors and returns their evidence. Risk scoring is
        deliberately owned by ``RiskScorer``; this class does not calculate a
        second composite score.
        """
        normalized_input = payload.normalized_input
        representations = payload.normalization_metadata.get("representations", [])

        # 1. Sub-detector 2.1: Rule-based Detector
        rule_result = RuleBasedDetector.scan(representations or normalized_input)
        rule_flags = rule_result.get("flags", [])

        # 2. Sub-detector 2.2: LLM Security Classifier
        llm_classification = LLMSecurityClassifier.classify(normalized_input)

        # 3. Sub-detector 2.3: Context Analyzer
        context_result = ContextAnalyzer.analyze_context(context_text or "")
        context_flags = context_result.get("flags", [])
        # The generic hardened detector is also capable of recognizing
        # instruction-like content when it arrives in untrusted context. This
        # augments (rather than rewires) the existing ContextAnalyzer/tool
        # guard boundary; full indirect containment remains a later phase.
        context_rule_result = RuleBasedDetector.scan(context_text or "")
        for flag in context_rule_result.get("flags", []):
            context_flag = f"CONTEXT_CONTENT:{flag}"
            if context_flag not in context_flags:
                context_flags.append(context_flag)

        # Phase 6 real sentence-embedding evidence.  The detector is lazy and
        # process-local; unavailable model state is explicit and never falls
        # back to the legacy lexical matcher.
        semantic_similarity = get_semantic_detector().detect(
            normalized_input, representations
        )

        semantic_unavailable = bool(
            semantic_similarity.get("status") == "unavailable"
            and not semantic_similarity.get("semantic_similarity_enabled")
        )

        raw_signals = {
            "rule_detector": rule_result,
            "llm_classifier": llm_classification,
            "context_analyzer": context_result,
            "context_rule_detector": context_rule_result,
            "semantic_similarity": semantic_similarity,
            "security_mode": "DEGRADED" if semantic_unavailable else "NORMAL",
            "degraded_controls": ["SEMANTIC_SIMILARITY"] if semantic_unavailable else [],
        }

        return SecurityAnalysisResult(
            request_id=payload.request_id,
            timestamp=payload.timestamp,
            normalized_input=normalized_input,
            rule_flags=rule_flags,
            llm_classification=llm_classification,
            context_flags=context_flags,
            semantic_similarity=semantic_similarity,
            raw_signals=raw_signals,
            # The canonical scorer fills this field after aggregation. Keeping
            # the default here avoids implying that RiskAnalyzer scores risk.
            risk_score=0.0,
            is_flagged=bool(
                rule_flags
                or context_flags
                or llm_classification.get("is_malicious", False)
                or semantic_similarity.get("flagged", False)
            ),
        )
