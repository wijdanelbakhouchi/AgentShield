"""Focused Phase 16 reproducibility and no-fabrication tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.performance_quality import compute_performance, compute_quality
from experiments.performance_quality.config import CONFIGS_DIR, QUALITY_DATASET, QUALITY_RUBRIC, load_all_configs
from experiments.performance_quality.run_quality import blinded_order
from experiments.performance_quality.timing import paired_overhead, percentile, summarize
from experiments.performance_quality.workflow import run_request


def test_percentile_and_summary_are_deterministic() -> None:
    assert percentile([1, 2, 3, 4], 0.50) == 2.5
    summary = summarize([1, 2, 3, 4])
    assert summary["count"] == 4
    assert summary["p95"] == 3.85
    assert summary["p99"] == 3.97


def test_missing_stage_is_explicitly_unmeasured() -> None:
    summary = summarize([])
    assert summary["count"] == 0
    assert summary["mean"] is None
    assert summary["p95"] is None


def test_paired_overhead_matches_by_sample_and_run() -> None:
    baseline = [{"sample_id": "s1", "run_number": 1, "total_ms": 10.0}]
    protected = [{"sample_id": "s1", "run_number": 1, "total_ms": 12.5}]
    result = paired_overhead(baseline, protected)
    assert result["count"] == 1
    assert result["mean"] == 2.5
    assert result["absolute_overhead_ms"] == 2.5
    assert result["relative_overhead_percent"] == 25.0


def test_request_total_includes_measured_persistence(tmp_path: Path) -> None:
    sample = {
        "sample_id": "perf-test",
        "category": "NORMAL_BENIGN",
        "kind": "benign",
        "text": "Summarize this safe test task.",
        "untrusted_context": "",
        "source_metadata": {"type": "user", "name": "test"},
        "requires_tool": False,
        "requires_agent_workflow": True,
    }
    config = next(config for config in load_all_configs() if config.name == "FULL_AGENTSHIELD")
    record = run_request(sample, config, run_number=1, semantic_ready=False, sandbox_db=tmp_path / "sandbox.sqlite3")
    measured = [float(record[name]) for name in ("normalization_ms", "rules_ms", "scoring_ms", "policy_ms", "database_ms", "agent_workflow_ms") if record.get(name) is not None]
    assert record["total_ms"] >= max(measured)
    assert record["database_ms"] is not None


def test_baseline_and_full_configurations_are_explicit() -> None:
    configs = {config.name: config for config in load_all_configs()}
    assert configs["BASELINE_NO_AGENTSHIELD"].agent_shield is False
    assert configs["FULL_AGENTSHIELD"].agent_shield is True
    assert json.loads((CONFIGS_DIR / "baseline_no_agentshield.json").read_text())["agent_shield"] is False


def test_quality_dataset_and_rubric_are_benign_and_parseable() -> None:
    tasks = json.loads(QUALITY_DATASET.read_text(encoding="utf-8"))
    rubric = json.loads(QUALITY_RUBRIC.read_text(encoding="utf-8"))
    assert len(tasks) >= 10
    assert all("task_id" in task and "success_criteria" in task for task in tasks)
    assert rubric["method"] == "human_blinded_ab_comparison"
    assert set(rubric["dimensions"]) == set(compute_quality.DIMENSIONS)


def test_blinded_order_is_reproducible_and_comparable() -> None:
    first = blinded_order("quality-sum-01", seed=20250916)
    second = blinded_order("quality-sum-01", seed=20250916)
    assert first == second
    assert set(first) == {"BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD"}


def test_quality_scores_reject_demo_fallback(tmp_path: Path) -> None:
    path = tmp_path / "quality_results.jsonl"
    row = {
        "sample_id": "q1",
        "configuration": "FULL_AGENTSHIELD",
        "provider": "fallback",
        "model": None,
        "real_llm": False,
        "run_number": 1,
        **{dimension: 4 for dimension in compute_quality.DIMENSIONS},
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(compute_quality, "RAW_DIR", tmp_path)
    monkeypatch.setattr(compute_quality, "SYSTEM_FREEZE", tmp_path / "freeze.json")
    monkeypatch.setattr(compute_quality, "QUALITY_DATASET", QUALITY_DATASET)
    monkeypatch.setattr(compute_quality, "QUALITY_RUBRIC", QUALITY_RUBRIC)
    freeze = {
        "quality_dataset": {"sha256": compute_quality.sha256_file(QUALITY_DATASET)},
        "quality_rubric": {"sha256": compute_quality.sha256_file(QUALITY_RUBRIC)},
    }
    (tmp_path / "freeze.json").write_text(json.dumps(freeze), encoding="utf-8")
    with pytest.raises(ValueError, match="Fallback/demo"):
        compute_quality.compute_summary()
    monkeypatch.undo()


def test_phase16_freeze_metadata_exists_and_is_read_only() -> None:
    freeze = Path("experiments/performance_quality/datasets/system_freeze_phase16.json")
    assert freeze.exists()
    data = json.loads(freeze.read_text(encoding="utf-8"))
    assert data["final_test_read_only"] is True
    assert data["phase15"]["dataset_sha256"]
    assert data["security_configuration"]["policy_block_threshold"] == 0.17


def test_processed_summaries_and_figures_are_artifact_backed() -> None:
    root = Path("experiments/performance_quality")
    performance = json.loads((root / "processed_results/performance_summary.json").read_text(encoding="utf-8"))
    quality = json.loads((root / "processed_results/quality_summary.json").read_text(encoding="utf-8"))
    figures = json.loads((root / "figures/figures_manifest.json").read_text(encoding="utf-8"))
    assert performance["baseline"]["count"] == performance["protected"]["count"]
    assert performance["overhead"]["count"] == performance["baseline"]["count"]
    assert quality["status"] == "PENDING"
    assert figures["generated_figures"]
    assert all(Path(path).exists() for path in figures["generated_figures"])


def test_raw_performance_rows_trace_to_computed_summary() -> None:
    root = Path("experiments/performance_quality")
    baseline_path = root / "raw_results/BASELINE_NO_AGENTSHIELD.jsonl"
    protected_path = root / "raw_results/FULL_AGENTSHIELD.jsonl"
    if not baseline_path.exists() or not protected_path.exists():
        pytest.skip("raw performance outputs are generated artifacts and are not committed")
    baseline_rows = compute_performance.read_records(baseline_path)
    protected_rows = compute_performance.read_records(protected_path)
    summary = compute_performance.compute_summary()
    assert len(baseline_rows) == summary["baseline"]["count"]
    assert len(protected_rows) == summary["protected"]["count"]
    assert summary["raw_files"]["baseline"]["sha256"]


def test_report_contains_no_fallback_quality_scores() -> None:
    report = Path("experiments/performance_quality/reports/performance_quality_report.md").read_text(encoding="utf-8")
    assert "Response Quality" in report
    assert "PENDING" in report
    assert "real provider response and human scores are pending" in report
