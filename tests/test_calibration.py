"""Regression tests for the Phase 4 calibration contract."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

from config import (
    CLASSIFIER_WEIGHT,
    CONTEXT_WEIGHT,
    POLICY_BLOCK_THRESHOLD,
    RISK_HIGH_MAX,
    RISK_LOW_MAX,
    RISK_MEDIUM_MAX,
    RULE_WEIGHT,
    SIMILARITY_WEIGHT,
    validate_security_configuration,
)
from experiments.calibration.calculate_metrics import compute_metrics
from experiments.calibration import run_calibration
from scoring.risk_scorer import RiskScorer
from state import Decision, RiskLevel, SecurityAnalysisResult, RiskScoreResult


def test_calibrated_weights_and_thresholds_have_one_source_of_truth():
    assert (RULE_WEIGHT, SIMILARITY_WEIGHT, CLASSIFIER_WEIGHT, CONTEXT_WEIGHT) == (0.4, 0.3, 0.0, 0.3)
    assert abs(RULE_WEIGHT + SIMILARITY_WEIGHT + CLASSIFIER_WEIGHT + CONTEXT_WEIGHT - 1.0) < 1e-9
    assert RiskScorer.RULE_TRIGGER_WEIGHT == RULE_WEIGHT
    assert RiskScorer.SEMANTIC_SIMILARITY_WEIGHT == SIMILARITY_WEIGHT
    assert RiskScorer.LLM_CLASSIFICATION_WEIGHT == CLASSIFIER_WEIGHT
    assert RiskScorer.CONTEXT_FLAG_WEIGHT == CONTEXT_WEIGHT
    assert 0.0 <= POLICY_BLOCK_THRESHOLD <= 1.0
    assert RISK_LOW_MAX < RISK_MEDIUM_MAX < RISK_HIGH_MAX < 1.0
    validate_security_configuration()


def test_scores_and_risk_bands_remain_valid():
    analysis = SecurityAnalysisResult(
        request_id="calibration-test",
        timestamp="2026-01-01T00:00:00Z",
        normalized_input="test",
        rule_flags=["TEST"],
        llm_classification={"is_malicious": True, "confidence": 1.0},
        context_flags=["TEST_CONTEXT"],
    )
    result = RiskScorer.calculate_score(analysis)
    assert 0.0 <= result.score <= 1.0
    assert result.level == RiskScorer.level_for_score(result.score)
    assert RiskScorer.level_for_score(RISK_LOW_MAX) == RiskLevel.LOW
    assert RiskScorer.level_for_score(RISK_MEDIUM_MAX) == RiskLevel.MEDIUM


def test_policy_uses_calibrated_block_boundary():
    clean = SecurityAnalysisResult(
        request_id="calibration-policy-test",
        timestamp="2026-01-01T00:00:00Z",
        normalized_input="safe",
    )
    below = RiskScoreResult(
        score=max(0.0, round(POLICY_BLOCK_THRESHOLD - 0.01, 2)),
        level=RiskScorer.level_for_score(max(0.0, round(POLICY_BLOCK_THRESHOLD - 0.01, 2))),
    )
    at = RiskScoreResult(
        score=POLICY_BLOCK_THRESHOLD,
        level=RiskScorer.level_for_score(POLICY_BLOCK_THRESHOLD),
    )
    from policy.policy_engine import PolicyEngine

    assert PolicyEngine.evaluate(clean, below).action == Decision.ALLOW
    assert PolicyEngine.evaluate(clean, at).action == Decision.BLOCK


def test_metric_recalculation_fixture_is_deterministic():
    rows = [
        {"true_label": 1, "rule_flags": ["R"], "context_flags": [], "llm_classification": {}, "detected": True, "baseline_component_scores": {"rule": 1.0, "classifier": 0.0, "context": 0.0}, "category": "ATTACK"},
        {"true_label": 1, "rule_flags": [], "context_flags": [], "llm_classification": {}, "detected": False, "baseline_component_scores": {"rule": 0.0, "classifier": 0.0, "context": 0.0}, "category": "ATTACK"},
        {"true_label": 0, "rule_flags": [], "context_flags": [], "llm_classification": {}, "detected": False, "baseline_component_scores": {"rule": 0.0, "classifier": 0.0, "context": 0.0}, "category": "BENIGN"},
    ]
    metrics = compute_metrics(
        rows,
        threshold=0.5,
        weights={"rule": 1.0, "classifier": 0.0, "context": 0.0},
        policy_mode="score_only",
    )
    assert metrics["confusion_matrix"] == {"TP": 1, "TN": 1, "FP": 0, "FN": 1}
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.5
    assert round(metrics["f1"], 6) == round(2 / 3, 6)
    assert metrics["fpr"] == 0.0
    assert metrics["fnr"] == 0.5


def test_calibration_runner_evaluates_calibration_role_only():
    source = inspect.getsource(run_calibration.run)
    assert "_collect_raw_predictions(calibration)" in source
    assert "_collect_raw_predictions(held_out)" not in source
    assert "held_out_used_for_tuning" in source


def test_raw_artifact_contains_no_held_out_ids():
    root = Path(__file__).resolve().parents[1]
    calibration = json.loads(
        (root / "experiments/calibration/datasets/calibration.json").read_text(encoding="utf-8")
    )
    raw_ids = {
        json.loads(line)["sample_id"]
        for line in (root / "experiments/calibration/raw/calibration_predictions.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert raw_ids == {item["id"] for item in calibration}
    # The regression protects the historical raw artifact without opening the
    # final held-out file during routine test execution.
    assert not any("held" in sample_id.casefold() for sample_id in raw_ids)
