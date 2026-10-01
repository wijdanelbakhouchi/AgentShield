"""Phase 6.5 regression and research-integrity checks."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from config import (
    CLASSIFIER_WEIGHT,
    CONTEXT_WEIGHT,
    POLICY_BLOCK_THRESHOLD,
    POLICY_FLAG_OVERRIDE,
    RISK_HIGH_MAX,
    RISK_LOW_MAX,
    RISK_MEDIUM_MAX,
    RULE_WEIGHT,
    SEMANTIC_SIMILARITY_THRESHOLD,
    SIMILARITY_WEIGHT,
)
from experiments.post_hardening_calibration import run_calibration
from policy.policy_engine import PolicyEngine
from scoring.risk_scorer import RiskScorer
from security.pipeline import SecurityPipeline
from state import Decision, RiskLevel, RiskScoreResult, SecurityAnalysisResult


def _semantic_analysis(score: float = 0.70) -> SecurityAnalysisResult:
    return SecurityAnalysisResult(
        request_id="phase65-test",
        timestamp="2026-01-01T00:00:00Z",
        normalized_input="paraphrase",
        semantic_similarity={
            "semantic_similarity_enabled": True,
            "flagged": score >= SEMANTIC_SIMILARITY_THRESHOLD,
            "status": "ready",
            "top_match": {"similarity": score, "category": "DIRECT_INJECTION"},
        },
    )


def test_semantic_weight_is_active_and_increases_score():
    analysis = _semantic_analysis()
    with_semantic = RiskScorer.calculate_score(analysis)
    without_semantic = RiskScorer.calculate_score(
        analysis.model_copy(update={"semantic_similarity": {}})
    )
    assert SIMILARITY_WEIGHT > 0
    assert with_semantic.score > without_semantic.score
    assert any("contribution=" in factor for factor in with_semantic.contributing_factors)


def test_component_contributions_are_bounded_and_simplex_is_loaded():
    analysis = SecurityAnalysisResult(
        request_id="phase65-components",
        timestamp="2026-01-01T00:00:00Z",
        normalized_input="test",
        rule_flags=["RULE_A", "RULE_B"],
        context_flags=["CONTEXT_A"],
        llm_classification={"is_malicious": True, "confidence": 0.9},
        semantic_similarity={
            "semantic_similarity_enabled": True,
            "flagged": True,
            "top_match": {"similarity": 0.8},
        },
    )
    components = RiskScorer.component_values(analysis)
    assert all(0.0 <= value <= 1.0 for value in components.values())
    assert abs(RULE_WEIGHT + SIMILARITY_WEIGHT + CLASSIFIER_WEIGHT + CONTEXT_WEIGHT - 1.0) < 1e-9
    assert 0.0 <= RiskScorer.calculate_score(analysis).score <= 1.0


def test_missing_classifier_is_zero_not_fabricated():
    analysis = _semantic_analysis()
    result = RiskScorer.calculate_score(analysis)
    assert RiskScorer.component_values(analysis)["classifier"] == 0.0
    assert result.score == round(SIMILARITY_WEIGHT * 0.7, 2)


def test_canonical_pipeline_surfaces_recalibrated_semantic_contribution(monkeypatch):
    analysis = _semantic_analysis(0.70)
    monkeypatch.setattr(
        "security.pipeline.RiskAnalyzer.analyze",
        classmethod(lambda cls, payload, context_text=None: analysis),
    )
    result = SecurityPipeline.evaluate("safe")
    assert result.risk.score == round(SIMILARITY_WEIGHT * 0.70, 2)
    assert result.analysis.raw_signals["canonical_pipeline"]["component_values"]["semantic_similarity"] == 0.70
    assert any("Semantic Similarity" in factor for factor in result.risk.contributing_factors)


def test_policy_boundary_and_selected_score_only_override():
    clean = SecurityAnalysisResult(
        request_id="phase65-policy",
        timestamp="2026-01-01T00:00:00Z",
        normalized_input="safe",
    )
    below = RiskScoreResult(score=round(POLICY_BLOCK_THRESHOLD - 0.01, 2), level=RiskLevel.MEDIUM)
    at = RiskScoreResult(score=POLICY_BLOCK_THRESHOLD, level=RiskLevel.HIGH)
    assert PolicyEngine.evaluate(clean, below).action == Decision.ALLOW
    assert PolicyEngine.evaluate(clean, at).action == Decision.BLOCK
    assert POLICY_FLAG_OVERRIDE is False
    assert RISK_LOW_MAX < RISK_MEDIUM_MAX < RISK_HIGH_MAX < POLICY_BLOCK_THRESHOLD


def test_calibration_runner_has_protected_path_guard_and_reproducible_artifacts():
    source = inspect.getsource(run_calibration)
    assert "held_out_test.json" in source
    assert "benchmark_dataset.json" in source
    assert "final_test_used" in source
    metadata_path = Path(__file__).resolve().parents[1] / "experiments/post_hardening_calibration/results/calibration_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["heldout_used"] is False
    assert metadata["final_test_used"] is False
    assert metadata["model"]["threshold"] == 0.51
    assert metadata["selected"]["weights"]["semantic"] > 0
