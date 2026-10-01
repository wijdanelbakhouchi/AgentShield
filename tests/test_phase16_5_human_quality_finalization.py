"""Targeted tests for the private Phase 16.5 human-quality finalization."""

from __future__ import annotations

import json

import pytest

from experiments.runtime_evaluation_closure import finalize_human_quality as finalizer
from experiments.runtime_evaluation_closure import import_human_ratings as importer


def test_imported_ratings_are_complete_and_mapping_is_private() -> None:
    task_ids = finalizer.expected_task_ids()
    ratings = finalizer.load_imported_ratings(task_ids)
    mapping, evidence = finalizer.load_private_mapping(task_ids)
    finalizer.validate_joined_artifact(ratings, mapping)
    assert len(ratings) == 24
    assert set(evidence["provider"]) == {"groq"}
    assert evidence["fallback_records"] == 0
    assert all("configuration" not in row for row in ratings.values())


def test_importer_rejects_invalid_scores_and_unknown_tasks() -> None:
    expected = set(importer._expected_task_ids())
    record = {
        "task_id": "quality-sum-01",
        "A": {dimension: 4 for dimension in importer.DIMENSIONS},
        "B": {dimension: 4 for dimension in importer.DIMENSIONS},
        "A_notes": "",
        "B_notes": "",
    }
    record["A"]["relevance"] = 6
    with pytest.raises(importer.RatingImportError, match="1 to 5"):
        importer._normalise_record(record, expected, 1)
    record["A"]["relevance"] = 4
    record["task_id"] = "unknown-task"
    with pytest.raises(importer.RatingImportError, match="Unknown task_id"):
        importer._normalise_record(record, expected, 1)


def test_final_quality_summary_contains_computed_metrics() -> None:
    summary = finalizer.compute_summary()
    assert summary["status"] == "COMPLETE"
    assert summary["n_task_pairs"] == 12
    assert summary["n_response_ratings"] == 24
    assert summary["configurations"]["BASELINE_NO_AGENTSHIELD"]["overall"]["mean"] == pytest.approx(4.7)
    assert summary["configurations"]["FULL_AGENTSHIELD"]["overall"]["mean"] == pytest.approx(4.416667)
    paired = summary["paired_task_analysis"]["summary"]
    assert paired["n"] == 12
    assert paired["mean"] == pytest.approx(-0.283333)
    assert paired["ci95"][0] < 0 < paired["ci95"][1]
    assert summary["quality_conclusion"] == "INCONCLUSIVE"


def test_final_figures_and_report_are_present_and_traceable() -> None:
    summary_path = finalizer.FINAL_SUMMARY
    report_path = finalizer.FINAL_REPORT
    manifest_path = finalizer.FINAL_FIGURES / "figures_manifest.json"
    assert summary_path.exists() and report_path.exists() and manifest_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    live_hash = finalizer._sha256(summary_path)
    if manifest["source_summary"]["sha256"] != live_hash:
        finalizer.regenerate_manifest_from_summary()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["source_summary"]["sha256"] == live_hash
    assert all((finalizer.ROOT.parent.parent / path).exists() for path in manifest["generated_figures"])
    report = report_path.read_text(encoding="utf-8")
    assert "INCONCLUSIVE" in report
    assert "human ratings → private joined ratings" in report
    assert summary["integrity"]["public_blind_artifact_modified"] is False
