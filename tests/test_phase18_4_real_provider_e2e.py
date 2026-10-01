"""Deterministic checks for Phase 18.4 evidence computation and storage."""

from __future__ import annotations

import json

import pytest

from experiments.e2e_evaluation.harness import (
    ProviderEvidenceFailure,
    compute_metrics,
    require_real_provider_result,
    write_artifacts,
)


def _row(label: str, *, blocked: bool, attack_success: bool) -> dict:
    return {
        "label": label,
        "status": "BLOCKED" if blocked else "COMPLETED",
        "decision": "BLOCK" if blocked else "ALLOW",
        "attack_success": attack_success,
    }


def test_metrics_are_derived_from_recorded_behavior_and_dispositions() -> None:
    rows = [
        _row("malicious", blocked=True, attack_success=False),
        _row("malicious", blocked=False, attack_success=True),
        _row("benign", blocked=False, attack_success=False),
        _row("benign", blocked=True, attack_success=False),
    ]
    metrics = compute_metrics(rows)
    assert {key: metrics[key] for key in ("tp", "tn", "fp", "fn")} == {"tp": 1, "tn": 1, "fp": 1, "fn": 1}
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["f2"] == 0.5
    assert metrics["asr"] == 0.5
    assert metrics["asr_wilson_95"] is not None


def test_artifact_writer_keeps_raw_and_processed_evidence_separate(tmp_path) -> None:
    record = {
        "sample_id": "sample-1",
        "configuration": "FULL_AGENTSHIELD",
        "label": "benign",
        "group": "benign_hard_negative",
        "status": "COMPLETED",
        "agents_invoked": ["researcher", "planner", "writer", "finalizer"],
        "trace": [],
        "handoff_events": [],
        "tools": [],
        "downstream_reached": True,
    }
    result = {
        "dataset": "experiments/e2e_evaluation/datasets/post_remediation_final_v1.json",
        "dataset_sha256": "frozen-sha",
        "sample_count": 16,
        "group_count": 7,
        "repetitions": 1,
        "warmup": 0,
        "records": [record],
        "summary": {"full_agentshield": {"n": 1}},
    }
    write_artifacts(result, tmp_path)
    assert json.loads((tmp_path / "processed_results" / "summary.json").read_text()) == result["summary"]
    assert json.loads((tmp_path / "manifests" / "run_manifest.json").read_text())["contains_secret_values"] is False
    raw = (tmp_path / "raw_results" / "records.jsonl").read_text().splitlines()
    assert len(raw) == 1 and json.loads(raw[0])["sample_id"] == "sample-1"


def test_provider_backed_runner_rejects_fallback_finalizer_output() -> None:
    with pytest.raises(ProviderEvidenceFailure, match="provider_failure"):
        require_real_provider_result(
            {
                "sample_id": "diagnostic",
                "status": "COMPLETED",
                "agents_invoked": ["researcher", "planner", "writer", "finalizer"],
                "final_workflow_output": {"provider": "fallback", "real_llm": False},
            }
        )
