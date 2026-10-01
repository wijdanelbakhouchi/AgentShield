"""Integration tests for the propagation evaluation harness."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.propagation.config import load_all_configs, load_config
from experiments.propagation.metrics import calculate_metrics, mcnemar
from experiments.propagation.workflow import evaluate_sample

ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / "experiments" / "propagation" / "datasets" / "benchmark_v2_all.json"


@pytest.fixture(scope="module")
def rows():
    with DATASET_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def configs():
    return load_all_configs()


def _records_for(rows, config):
    return [evaluate_sample(row, config) for row in rows]


def test_baseline_asr_is_one(rows, configs):
    config = load_config("baseline_no_agentshield")
    records = _records_for(rows, config)
    metrics = calculate_metrics(records)
    assert metrics["overall"]["attack_success_rate"] == 1.0
    assert metrics["propagation"]["mean_depth"] == 4.0
    assert metrics["propagation"]["privileged_reach_rate"] == 1.0


def test_full_reduces_asr_vs_baseline(rows, configs):
    baseline = calculate_metrics(_records_for(rows, load_config("baseline_no_agentshield")))
    full = calculate_metrics(_records_for(rows, load_config("full_no_provenance")))
    assert full["overall"]["attack_success_rate"] < baseline["overall"]["attack_success_rate"]
    assert full["overall"]["mitigation_rate"] > 0.0


def test_gateway_only_is_weaker_than_message_level(rows, configs):
    gateway = calculate_metrics(_records_for(rows, load_config("gateway_only")))
    full = calculate_metrics(_records_for(rows, load_config("full_no_provenance")))
    assert gateway["overall"]["mitigation_rate"] < full["overall"]["mitigation_rate"]


def test_provenance_adjustment_improves_containment(rows, configs):
    no_prov = _records_for(rows, load_config("full_no_provenance"))
    with_prov = _records_for(rows, load_config("full_provenance"))
    test = mcnemar(no_prov, with_prov)
    assert test["paired_samples"] > 0
    assert test["p_value"] <= 1.0
    no_prov_asr = calculate_metrics(no_prov)["overall"]["attack_success_rate"]
    with_prov_asr = calculate_metrics(with_prov)["overall"]["attack_success_rate"]
    assert with_prov_asr <= no_prov_asr


def test_alert_only_records_detection_without_mitigation(rows, configs):
    config = load_config("alert_only_detection")
    records = _records_for(rows, config)
    metrics = calculate_metrics(records)
    assert metrics["overall"]["mitigation_rate"] == 0.0
    detection = metrics["detection"]
    assert detection["TP"] + detection["FN"] == metrics["overall"]["malicious_count"]


def test_provenance_flags_present_in_provenance_config(rows, configs):
    records = _records_for(rows, load_config("full_provenance"))
    stages_with_taint = 0
    for record in records:
        for stage in record.get("stages", []):
            if "PROVENANCE:TAINTED" in stage.get("flags", []):
                stages_with_taint += 1
    assert stages_with_taint > 0


def test_stage_guard_labels_are_valid(rows, configs):
    allowed_guards = {"gateway", "tool_security", "researcher", "inter_agent"}
    for config in configs:
        records = _records_for(rows, config)
        for record in records:
            blocked_at = record.get("blocked_at")
            if blocked_at is not None:
                assert blocked_at in allowed_guards, f"unexpected guard {blocked_at}"