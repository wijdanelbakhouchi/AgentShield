"""Focused integrity and formula tests for the Phase 15 framework."""

from __future__ import annotations

import json

import pytest

from experiments.final_evaluation.config import load_config
from experiments.final_evaluation.metrics import calculate_metrics, grouped_bootstrap_ci
from experiments.final_evaluation.validate_dataset import DATASET_PATH, freeze_dataset, validate_dataset
from experiments.final_evaluation.workflow import evaluate_sample


def test_final_dataset_validates_with_grouped_transformations():
    summary = validate_dataset(DATASET_PATH)
    assert summary["total_samples"] == 52
    assert summary["effective_groups"] == 50
    assert summary["labels"] == {"benign": 16, "malicious": 36}


def test_dataset_validator_rejects_casefolded_duplicate(tmp_path):
    rows = [{
        "sample_id": "one", "label": "benign", "category": "NORMAL_BENIGN", "group_id": "one",
        "text": "A unique request", "source": "manual", "provenance": {"method": "manual"},
        "expected_security_outcome": "ALLOW", "requires_tool": False, "requires_agent_workflow": False,
        "notes": "test",
    }, {
        "sample_id": "two", "label": "benign", "category": "NORMAL_BENIGN", "group_id": "two",
        "text": " a   UNIQUE   request ", "source": "manual", "provenance": {"method": "manual"},
        "expected_security_outcome": "ALLOW", "requires_tool": False, "requires_agent_workflow": False,
        "notes": "test",
    }]
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        validate_dataset(path)


def test_frozen_manifest_cannot_be_overwritten_with_changed_content(tmp_path):
    source = tmp_path / "corpus.json"
    manifest = tmp_path / "manifest.json"
    rows = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    source.write_text(json.dumps(rows), encoding="utf-8")
    freeze_dataset(source, manifest)
    rows[0]["text"] = "A changed request"
    source.write_text(json.dumps(rows), encoding="utf-8")
    with pytest.raises(ValueError, match="Frozen dataset"):
        freeze_dataset(source, manifest)


def test_config_flags_are_explicit_and_baseline_is_not_allow_all():
    full = load_config("full")
    baseline = load_config("baseline_no_agentshield")
    assert all(getattr(full, name) for name in ("normalization", "rules", "tool_output_guard", "inter_agent_guard", "context_isolation"))
    assert not baseline.agent_shield
    assert not any(getattr(baseline, name) for name in ("normalization", "rules", "semantic_similarity", "tool_output_guard", "inter_agent_guard", "context_isolation"))


def test_metric_formulas_and_attack_success_rate():
    rows = [
        {"label": "malicious", "decision": "BLOCK", "attack_success": False, "group_id": "a", "category": "DIRECT_INJECTION"},
        {"label": "malicious", "decision": "ALLOW", "attack_success": True, "group_id": "b", "category": "DIRECT_INJECTION"},
        {"label": "benign", "decision": "ALLOW", "attack_success": False, "group_id": "c", "category": "NORMAL_BENIGN"},
        {"label": "benign", "decision": "BLOCK", "attack_success": False, "group_id": "d", "category": "NORMAL_BENIGN"},
    ]
    result = calculate_metrics(rows)["overall"]
    assert result["TP"] == result["TN"] == result["FP"] == result["FN"] == 1
    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(0.5)
    assert result["f1"] == pytest.approx(0.5)
    assert result["f2"] == pytest.approx(0.5)
    assert result["attack_success_rate"] == pytest.approx(0.5)
    assert result["mitigation_rate"] == pytest.approx(0.5)


def test_grouped_bootstrap_is_reproducible():
    rows = [
        {"label": "malicious", "decision": "BLOCK", "attack_success": False, "group_id": "same", "category": "OBFUSCATION"},
        {"label": "malicious", "decision": "ALLOW", "attack_success": True, "group_id": "same", "category": "OBFUSCATION"},
        {"label": "benign", "decision": "ALLOW", "attack_success": False, "group_id": "benign", "category": "NORMAL_BENIGN"},
    ]
    first = grouped_bootstrap_ci(rows, "attack_success_rate", replicates=50, seed=17)
    second = grouped_bootstrap_ci(rows, "attack_success_rate", replicates=50, seed=17)
    assert first == second
    assert first["effective_group_count"] == 2


def test_baseline_and_full_use_same_sample_and_traceable_raw_fields():
    sample = json.loads(DATASET_PATH.read_text(encoding="utf-8"))[0]
    baseline = evaluate_sample(sample, load_config("baseline_no_agentshield"))
    full = evaluate_sample(sample, load_config("full"))
    assert baseline["sample_id"] == full["sample_id"] == sample["sample_id"]
    assert baseline["configuration"] != full["configuration"]
    assert baseline["decision"] == "ALLOW"
    assert baseline["attack_success"] is True
    assert full["decision"] == "BLOCK"
    assert full["attack_success"] is False
    assert {"sample_id", "group_id", "configuration", "run_id", "decision", "risk_score", "findings", "attack_success", "mitigated", "request_id"} <= full.keys()


def test_processed_metrics_trace_to_committed_raw_results():
    raw_path = DATASET_PATH.parent.parent / "raw_results" / "FULL_AGENTSHIELD.jsonl"
    processed_path = DATASET_PATH.parent.parent / "processed_results" / "FULL_AGENTSHIELD.json"
    if not raw_path.exists():
        pytest.skip("raw evaluation outputs are generated artifacts and are not committed")
    raw = [json.loads(line) for line in raw_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    processed = json.loads(processed_path.read_text(encoding="utf-8"))
    assert processed["metrics"]["overall"]["sample_count"] == len(raw) == 52
    assert {row["sample_id"] for row in raw} == {row["sample_id"] for row in json.loads(DATASET_PATH.read_text(encoding="utf-8"))}


def test_final_test_freeze_is_explicitly_read_only():
    freeze_path = DATASET_PATH.parent / "system_freeze.json"
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
    assert freeze["final_test_read_only"] is True
