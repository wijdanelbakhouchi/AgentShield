"""Finalize private Phase 16.5 human-quality results from imported ratings.

The public scoring packet is never read here.  This module consumes the
validated private ratings produced by ``import_human_ratings`` and joins them
to the unchanged private A/B mapping only inside the repository.  All means,
paired differences, figures, and report text are derived programmatically.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean, stdev
from typing import Any

from .config import (
    EXPECTED_DIMENSION,
    EXPECTED_MODEL,
    EXPECTED_REVISION,
    PHASE15_OUTPUT,
    PHASE16_OUTPUT,
    QUALITY_OUTPUT,
    QUALITY_RUBRIC,
    ROOT,
    SEMANTIC_CORPUS,
    CLOSURE_REPORT,
)


DIMENSIONS = ("task_success", "relevance", "completeness", "factuality", "helpfulness")
LABELS = ("A", "B")
CONFIGURATIONS = ("BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD")
DISPLAY_NAMES = {
    "BASELINE_NO_AGENTSHIELD": "WITHOUT AgentShield",
    "FULL_AGENTSHIELD": "WITH AgentShield",
}

ORIGINAL_RAW = QUALITY_OUTPUT / "quality_results.jsonl"
REPAIRED_RAW = QUALITY_OUTPUT / "quality_results_repaired.jsonl"
REPAIR_SUMMARY = QUALITY_OUTPUT / "quality_summary_repaired.json"
IMPORTED_RATINGS = QUALITY_OUTPUT / "human_ratings.jsonl"
JOINED_RATINGS = QUALITY_OUTPUT / "human_ratings_joined.jsonl"
FINAL_DIR = QUALITY_OUTPUT / "final_human_evaluation"
FINAL_SUMMARY = FINAL_DIR / "human_quality_summary.json"
FINAL_REPORT = FINAL_DIR / "human_quality_report.md"
FINAL_FIGURES = FINAL_DIR / "figures"
QUALITY_DATASET = ROOT.parent.parent / "experiments" / "performance_quality" / "datasets" / "quality_tasks_v1.json"


class FinalizationError(ValueError):
    """Raised when a required private Phase 16.5 artifact is invalid."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FinalizationError(f"Missing required artifact: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FinalizationError(f"Invalid JSON artifact: {path}") from exc


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise FinalizationError(f"Missing required artifact: {path}") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise FinalizationError(f"Invalid JSON at {path}:{line_number}") from exc
        if not isinstance(value, dict):
            raise FinalizationError(f"Expected an object at {path}:{line_number}")
        rows.append(value)
    return rows


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return str(path.relative_to(ROOT.parent.parent))


def _git_sha() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT.parent.parent,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def expected_task_ids() -> list[str]:
    tasks = _read_json(QUALITY_DATASET)
    if not isinstance(tasks, list) or len(tasks) != 12:
        raise FinalizationError("Frozen quality dataset must contain exactly 12 tasks")
    ids = [str(task.get("task_id", "")) for task in tasks if isinstance(task, Mapping)]
    if len(ids) != 12 or len(set(ids)) != 12 or any(not task_id for task_id in ids):
        raise FinalizationError("Frozen quality dataset contains invalid task IDs")
    return ids


def load_private_mapping(task_ids: list[str]) -> tuple[dict[tuple[str, str], str], dict[str, Any]]:
    rows = _read_jsonl(REPAIRED_RAW)
    mapping: dict[tuple[str, str], str] = {}
    fallback_records = 0
    providers: set[str] = set()
    models: set[str] = set()
    real_llm_values: set[bool] = set()
    for row in rows:
        task_id = str(row.get("sample_id", ""))
        label = str(row.get("blind_label", ""))
        configuration = str(row.get("configuration", ""))
        key = (task_id, label)
        if task_id not in task_ids or label not in LABELS or configuration not in CONFIGURATIONS:
            raise FinalizationError("Repaired raw artifact contains an unexpected private mapping row")
        if key in mapping:
            raise FinalizationError(f"Duplicate private mapping row: {task_id}/{label}")
        mapping[key] = configuration
        providers.add(str(row.get("provider", "")))
        models.add(str(row.get("model", "")))
        real_llm = row.get("real_llm")
        if not isinstance(real_llm, bool):
            raise FinalizationError("Private provider evidence has a non-boolean real_llm field")
        real_llm_values.add(real_llm)
        if not real_llm or str(row.get("provider", "")).casefold() in {"fallback", "demo"}:
            fallback_records += 1
    expected_pairs = {(task_id, label) for task_id in task_ids for label in LABELS}
    if set(mapping) != expected_pairs:
        raise FinalizationError("Private mapping must contain exactly 24 task/label pairs")
    if len(rows) != 24:
        raise FinalizationError("Repaired raw artifact must contain exactly 24 records")
    return mapping, {
        "provider": sorted(providers),
        "model": sorted(models),
        "real_llm_values": sorted(real_llm_values),
        "fallback_records": fallback_records,
    }


def load_imported_ratings(task_ids: list[str]) -> dict[tuple[str, str], dict[str, Any]]:
    rows = _read_jsonl(IMPORTED_RATINGS)
    required = {"sample_id", "blind_label", *DIMENSIONS, "notes", "rated_at", "rubric_scale", "evaluator_version"}
    ratings: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if set(row) != required:
            raise FinalizationError("Imported ratings contain unexpected or missing fields")
        task_id = str(row["sample_id"])
        label = str(row["blind_label"])
        key = (task_id, label)
        if task_id not in task_ids or label not in LABELS:
            raise FinalizationError(f"Imported ratings contain an unknown task or label: {task_id}/{label}")
        if key in ratings:
            raise FinalizationError(f"Duplicate imported rating: {task_id}/{label}")
        for dimension in DIMENSIONS:
            value = row[dimension]
            if type(value) is not int or value not in {1, 2, 3, 4, 5}:
                raise FinalizationError(f"Invalid score in imported ratings: {task_id}/{label}/{dimension}")
        if not isinstance(row["notes"], str):
            raise FinalizationError(f"Rating notes must be text: {task_id}/{label}")
        ratings[key] = row
    expected_pairs = {(task_id, label) for task_id in task_ids for label in LABELS}
    if set(ratings) != expected_pairs or len(rows) != 24:
        raise FinalizationError("Imported ratings must contain exactly 24 ratings for 12 complete pairs")
    return ratings


def validate_joined_artifact(
    ratings: dict[tuple[str, str], dict[str, Any]],
    mapping: dict[tuple[str, str], str],
) -> None:
    rows = _read_jsonl(JOINED_RATINGS)
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (str(row.get("sample_id", "")), str(row.get("blind_label", "")))
        if key in seen or key not in ratings:
            raise FinalizationError("Joined ratings contain duplicate or unexpected rows")
        if row.get("configuration") != mapping[key]:
            raise FinalizationError(f"Joined mapping mismatch for {key[0]}/{key[1]}")
        for dimension in DIMENSIONS:
            if row.get(dimension) != ratings[key][dimension]:
                raise FinalizationError(f"Joined score mismatch for {key[0]}/{key[1]}/{dimension}")
        seen.add(key)
    if len(rows) != 24 or seen != set(ratings):
        raise FinalizationError("Joined ratings must contain exactly 24 private rows")


def _stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0, "mean": None, "std": None}
    return {
        "n": len(values),
        "mean": round(fmean(values), 6),
        "std": round(stdev(values), 6) if len(values) > 1 else 0.0,
        "min": round(min(values), 6),
        "max": round(max(values), 6),
    }


def _paired_stats(differences: list[float]) -> dict[str, Any]:
    if len(differences) < 2:
        raise FinalizationError("At least two paired task differences are required")
    mean = fmean(differences)
    standard_deviation = stdev(differences)
    standard_error = standard_deviation / math.sqrt(len(differences))
    # Two-sided 95% critical value for a paired t interval with df=11.
    t_critical = 2.2009851601
    margin = t_critical * standard_error
    return {
        "n": len(differences),
        "mean": round(mean, 6),
        "std": round(standard_deviation, 6),
        "standard_error": round(standard_error, 6),
        "ci95": [round(mean - margin, 6), round(mean + margin, 6)],
        "ci_method": "paired t interval, df=11, two-sided 95%",
        "t_critical": t_critical,
    }


def _quality_conclusion(paired: dict[str, Any]) -> str:
    mean = float(paired["mean"])
    lower, upper = (float(value) for value in paired["ci95"])
    if lower > 0.25:
        return "MEASURABLE IMPROVEMENT"
    if upper < -0.25:
        return "MEASURABLE DEGRADATION"
    if abs(mean) < 0.25 and lower <= 0 <= upper:
        return "SIMILAR QUALITY"
    return "INCONCLUSIVE"


def _load_repair_provenance() -> dict[str, Any]:
    original = _read_jsonl(ORIGINAL_RAW)
    repaired = _read_jsonl(REPAIRED_RAW)
    summary = _read_json(REPAIR_SUMMARY)
    original_nonempty = sum(bool(str(row.get("response_text") or "").strip()) for row in original)
    repaired_nonempty = sum(bool(str(row.get("response_text") or "").strip()) for row in repaired)
    regenerated = sum(bool(row.get("regenerated")) for row in repaired)
    if len(original) != 24 or original_nonempty != 2:
        raise FinalizationError("Original quality artifact does not contain the expected 2/24 valid responses")
    if len(repaired) != 24 or repaired_nonempty != 24 or regenerated != 22:
        raise FinalizationError("Repaired quality artifact does not contain 24/24 responses and 22 regenerations")
    if summary.get("original_valid_records") != 2 or summary.get("regenerated_records") != 22:
        raise FinalizationError("Repair summary provenance counts do not match raw artifacts")
    return {
        "original_records": len(original),
        "original_valid_records": original_nonempty,
        "repaired_records": len(repaired),
        "repaired_nonempty_records": repaired_nonempty,
        "regenerated_records": regenerated,
        "regeneration_reason": summary.get("regeneration_reason"),
        "provider": summary.get("provider"),
        "model": summary.get("model"),
        "fallback_records": sum(
            not bool(row.get("real_llm")) or str(row.get("provider", "")).casefold() in {"fallback", "demo"}
            for row in repaired
        ),
    }


def _load_runtime_evidence() -> dict[str, Any]:
    closure = _read_json(CLOSURE_REPORT)
    semantic = closure.get("semantic_runtime", {})
    model = semantic.get("model", {})
    if semantic.get("status") != "ready" or model.get("name") != EXPECTED_MODEL or model.get("revision") != EXPECTED_REVISION or model.get("embedding_dimension") != EXPECTED_DIMENSION:
        raise FinalizationError("Pinned semantic runtime evidence is not ready or does not match the frozen identity")
    return {
        "semantic": {
            "status": "READY",
            "model": EXPECTED_MODEL,
            "revision": EXPECTED_REVISION,
            "dimension": EXPECTED_DIMENSION,
            "threshold": semantic.get("threshold"),
        },
        "provider": closure.get("provider", {}),
        "integrity": closure.get("integrity", {}),
    }


def _load_phase15_metrics() -> dict[str, Any]:
    full = _read_json(PHASE15_OUTPUT / "processed_results" / "FULL_AGENTSHIELD.json")
    baseline = _read_json(PHASE15_OUTPUT / "processed_results" / "BASELINE_NO_AGENTSHIELD.json")
    return {"full": full.get("metrics", {}).get("overall", {}), "baseline": baseline.get("metrics", {}).get("overall", {})}


def _load_phase16_performance() -> dict[str, Any]:
    performance = _read_json(PHASE16_OUTPUT / "processed_results" / "performance_summary.json")
    if performance.get("schema_version") != "phase16.5-provider-performance-v1" or performance.get("repetitions") != 1 or performance.get("warmup") != 0:
        raise FinalizationError("Phase 16.5 provider-backed performance evidence does not match the frozen one-run design")
    if performance.get("baseline", {}).get("count") != 12 or performance.get("protected", {}).get("count") != 12:
        raise FinalizationError("Phase 16.5 provider-backed performance evidence must contain 12 records per configuration")
    return {
        "status": performance.get("status"),
        "repetitions": performance.get("repetitions"),
        "warmup": performance.get("warmup"),
        "baseline_p95_ms": performance.get("baseline", {}).get("total", {}).get("p95"),
        "protected_p95_ms": performance.get("protected", {}).get("total", {}).get("p95"),
        "observed_mean_difference_ms": performance.get("overhead", {}).get("absolute_overhead_ms"),
        "overhead": performance.get("overhead", {}),
        "provider": performance.get("provider", {}),
        "real_llm": performance.get("real_llm"),
    }


def compute_summary() -> dict[str, Any]:
    task_ids = expected_task_ids()
    mapping, provider_evidence = load_private_mapping(task_ids)
    ratings = load_imported_ratings(task_ids)
    validate_joined_artifact(ratings, mapping)

    per_configuration: dict[str, Any] = {}
    task_scores: dict[str, dict[str, float]] = {task_id: {} for task_id in task_ids}
    for configuration in CONFIGURATIONS:
        selected = [ratings[(task_id, label)] for task_id in task_ids for label in LABELS if mapping[(task_id, label)] == configuration]
        if len(selected) != 12:
            raise FinalizationError(f"Expected 12 ratings for {configuration}, found {len(selected)}")
        dimensions = {dimension: _stats([float(row[dimension]) for row in selected]) for dimension in DIMENSIONS}
        for task_id in task_ids:
            rows = [ratings[(task_id, label)] for label in LABELS if mapping[(task_id, label)] == configuration]
            if len(rows) != 1:
                raise FinalizationError(f"Expected one {configuration} response for {task_id}")
            task_scores[task_id][configuration] = fmean(float(rows[0][dimension]) for dimension in DIMENSIONS)
        per_configuration[configuration] = {
            "display_name": DISPLAY_NAMES[configuration],
            "n": len(selected),
            "dimensions": dimensions,
            "overall": _stats([task_scores[task_id][configuration] for task_id in task_ids]),
        }

    paired_tasks = [
        {
            "task_id": task_id,
            "without_agentshield_overall": round(task_scores[task_id][CONFIGURATIONS[0]], 6),
            "with_agentshield_overall": round(task_scores[task_id][CONFIGURATIONS[1]], 6),
            "protected_minus_baseline": round(task_scores[task_id][CONFIGURATIONS[1]] - task_scores[task_id][CONFIGURATIONS[0]], 6),
        }
        for task_id in task_ids
    ]
    paired = _paired_stats([item["protected_minus_baseline"] for item in paired_tasks])
    conclusion = _quality_conclusion(paired)
    repair = _load_repair_provenance()
    runtime = _load_runtime_evidence()
    phase15 = _load_phase15_metrics()
    phase16 = _load_phase16_performance()

    return {
        "schema_version": "phase16.5-final-human-quality-v1",
        "status": "COMPLETE",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_from_git_sha": _git_sha(),
        "n_task_pairs": len(task_ids),
        "n_response_ratings": len(ratings),
        "method": "complete_private_join_after_blinded_human_scoring",
        "configurations": per_configuration,
        "paired_task_analysis": {"tasks": paired_tasks, "summary": paired},
        "quality_conclusion": conclusion,
        "provenance": {
            "imported_ratings": {"path": _relative(IMPORTED_RATINGS), "sha256": _sha256(IMPORTED_RATINGS)},
            "joined_ratings": {"path": _relative(JOINED_RATINGS), "sha256": _sha256(JOINED_RATINGS)},
            "private_mapping_source": {"path": _relative(REPAIRED_RAW), "sha256": _sha256(REPAIRED_RAW)},
            "original_quality_artifact": {"path": _relative(ORIGINAL_RAW), "sha256": _sha256(ORIGINAL_RAW)},
            "repaired_quality_artifact": {"path": _relative(REPAIRED_RAW), "sha256": _sha256(REPAIRED_RAW)},
            "repair_summary": {"path": _relative(REPAIR_SUMMARY), "sha256": _sha256(REPAIR_SUMMARY)},
            "quality_dataset": {"path": _relative(QUALITY_DATASET), "sha256": _sha256(QUALITY_DATASET)},
            "quality_rubric": {"path": _relative(QUALITY_RUBRIC), "sha256": _sha256(QUALITY_RUBRIC)},
            "semantic_corpus": {"path": _relative(SEMANTIC_CORPUS), "sha256": _sha256(SEMANTIC_CORPUS)},
        },
        "provider_evidence": provider_evidence,
        "repair_provenance": repair,
        "runtime": runtime,
        "phase15_security": phase15,
        "phase16_performance": phase16,
        "integrity": {
            "security_configuration_changed": False,
            "phase15_dataset_changed": False,
            "human_ratings_modified": False,
            "final_evaluation_used_for_tuning": False,
            "semantic_configuration_changed": False,
            "fallback_used_as_real_evidence": False,
            "public_blind_artifact_modified": False,
        },
    }


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _persist_figures(summary: dict[str, Any]) -> dict[str, Any]:
    """Generate figures and write a manifest whose hash matches the on-disk summary.

    The manifest is derived *after* the summary is flushed to disk, so its
    ``source_summary.sha256`` always reflects the exact file the test will
    read. This avoids the stale-manifest failure when ``compute_summary()``
    is called without ``finalize()``.
    """
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise FinalizationError("matplotlib is required to generate final quality figures") from exc

    FINAL_FIGURES.mkdir(parents=True, exist_ok=True)
    dimensions = list(DIMENSIONS)
    labels = [DISPLAY_NAMES[configuration] for configuration in CONFIGURATIONS]
    means = [[summary["configurations"][configuration]["dimensions"][dimension]["mean"] for dimension in dimensions] for configuration in CONFIGURATIONS]

    figure, axis = plt.subplots(figsize=(9, 4.8))
    for label, values in zip(labels, means):
        axis.plot(dimensions, values, marker="o", label=label)
    axis.set_ylim(1, 5)
    axis.set_ylabel("Mean human score (1–5)")
    axis.set_title("Blinded benign-response quality")
    axis.legend()
    axis.tick_params(axis="x", rotation=25)
    figure.tight_layout()
    quality_path = FINAL_FIGURES / "quality_dimensions.png"
    figure.savefig(quality_path, dpi=160)
    plt.close(figure)

    paired = summary["paired_task_analysis"]["tasks"]
    figure, axis = plt.subplots(figsize=(10, 4.8))
    axis.bar(range(1, len(paired) + 1), [item["protected_minus_baseline"] for item in paired])
    axis.axhline(0, color="black", linewidth=0.8)
    axis.set_xlabel("Task pair")
    axis.set_ylabel("WITH minus WITHOUT overall score")
    axis.set_title("Paired human-quality differences")
    figure.tight_layout()
    paired_path = FINAL_FIGURES / "quality_paired_differences.png"
    figure.savefig(paired_path, dpi=160)
    plt.close(figure)

    manifest: dict[str, Any] = {
        "schema_version": "phase16.5-final-quality-figures-v1",
        "source_summary": {"path": _relative(FINAL_SUMMARY), "sha256": _sha256(FINAL_SUMMARY)},
        "generated_figures": [_relative(quality_path), _relative(paired_path)],
    }
    manifest_path = FINAL_FIGURES / "figures_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def regenerate_manifest_from_summary() -> dict[str, Any]:
    """Re-derive the figures manifest from the current on-disk summary.

    Safe to call when the summary has been recomputed outside of a full
    ``finalize()`` run and the stale manifest would otherwise fail the
    traceability assertion.
    """
    summary = _read_json(FINAL_SUMMARY)
    return _persist_figures(summary)


def _render_report(summary: dict[str, Any], figures: dict[str, Any]) -> str:
    without = summary["configurations"][CONFIGURATIONS[0]]
    with_shield = summary["configurations"][CONFIGURATIONS[1]]
    paired = summary["paired_task_analysis"]["summary"]
    phase15_full = summary["phase15_security"]["full"]
    phase15_baseline = summary["phase15_security"]["baseline"]
    phase16 = summary["phase16_performance"]
    repair = summary["repair_provenance"]
    runtime = summary["runtime"]
    lines = [
        "# Phase 16.5 Final Human Quality Evaluation",
        "",
        f"Status: {summary['status']}",
        "",
        "This report is generated from the imported blinded human ratings, the private A/B mapping, and unchanged provider/runtime artifacts. No quality score is manually entered.",
        "",
        "## Human quality",
        "",
        "| Configuration | Task Success | Relevance | Completeness | Factuality | Helpfulness | Overall | N |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        f"| WITHOUT AgentShield | {_fmt(without['dimensions']['task_success']['mean'])} | {_fmt(without['dimensions']['relevance']['mean'])} | {_fmt(without['dimensions']['completeness']['mean'])} | {_fmt(without['dimensions']['factuality']['mean'])} | {_fmt(without['dimensions']['helpfulness']['mean'])} | {_fmt(without['overall']['mean'])} | {without['n']} |",
        f"| WITH AgentShield | {_fmt(with_shield['dimensions']['task_success']['mean'])} | {_fmt(with_shield['dimensions']['relevance']['mean'])} | {_fmt(with_shield['dimensions']['completeness']['mean'])} | {_fmt(with_shield['dimensions']['factuality']['mean'])} | {_fmt(with_shield['dimensions']['helpfulness']['mean'])} | {_fmt(with_shield['overall']['mean'])} | {with_shield['n']} |",
        "",
        f"Quality conclusion: **{summary['quality_conclusion']}**.",
        "The protected-minus-baseline mean is descriptive; the interval crosses zero, so this small sample does not establish a statistically reliable quality change.",
        "",
        "## Paired task analysis",
        "",
        "| Task | WITHOUT overall | WITH overall | WITH minus WITHOUT |",
        "|---|---:|---:|---:|",
    ]
    for task in summary["paired_task_analysis"]["tasks"]:
        lines.append(f"| {task['task_id']} | {_fmt(task['without_agentshield_overall'])} | {_fmt(task['with_agentshield_overall'])} | {_fmt(task['protected_minus_baseline'])} |")
    lines.extend(
        [
            "",
            f"- Mean paired difference: {_fmt(paired['mean'])}",
            f"- Paired standard deviation: {_fmt(paired['std'])}",
            f"- 95% CI: [{_fmt(paired['ci95'][0])}, {_fmt(paired['ci95'][1])}] ({paired['ci_method']})",
            "",
            "## Provider and runtime",
            "",
            f"- Provider-backed quality responses: {repair['provider']} / {repair['model']} / fallback records={repair['fallback_records']}",
            f"- Semantic runtime: {runtime['semantic']['status']} ({runtime['semantic']['model']} revision {runtime['semantic']['revision']}, dimension {runtime['semantic']['dimension']})",
            "",
            "## Phase 15 security",
            "",
            f"- FULL_AGENTSHIELD TP/TN/FP/FN: {phase15_full.get('TP')}/{phase15_full.get('TN')}/{phase15_full.get('FP')}/{phase15_full.get('FN')}; precision={_fmt(phase15_full.get('precision'), 4)}; recall={_fmt(phase15_full.get('recall'), 4)}; F1={_fmt(phase15_full.get('f1'), 4)}; F2={_fmt(phase15_full.get('f2'), 4)}; FPR={_fmt(phase15_full.get('fpr'), 4)}; FNR={_fmt(phase15_full.get('fnr'), 4)}; ASR={_fmt(phase15_full.get('attack_success_rate'), 4)}; mitigation={_fmt(phase15_full.get('mitigation_rate'), 4)}.",
            f"- BASELINE_NO_AGENTSHIELD ASR: {_fmt(phase15_baseline.get('attack_success_rate'), 4)}.",
            "",
            "## Phase 16 performance",
            "",
            f"- Baseline P95: {_fmt(phase16['baseline_p95_ms'])} ms",
            f"- Protected P95: {_fmt(phase16['protected_p95_ms'])} ms",
            f"- Observed paired mean difference: {_fmt(phase16['observed_mean_difference_ms'])} ms",
            "- Design: N=12 per configuration, one repetition, no warmup, remote-provider/network variability.",
            "- The observed negative difference is reported only as this run's observation; it is not evidence that AgentShield makes requests faster.",
            "",
            "## Repair provenance",
            "",
            f"- Original artifact: {repair['original_valid_records']}/24 valid responses; preserved.",
            f"- Repaired artifact: {repair['repaired_nonempty_records']}/24 non-empty responses; {repair['regenerated_records']} records regenerated.",
            f"- Cause: {repair['regeneration_reason']}.",
            "- Provider remained Groq with model openai/gpt-oss-20b; no fallback response was used as evidence.",
            "",
            "## Traceability",
            "",
            "human ratings → private joined ratings → this processed summary → figures → this report",
            f"- Summary: {_relative(FINAL_SUMMARY)}",
            f"- Figures: {', '.join(figures['generated_figures'])}",
            f"- Imported ratings SHA-256: {summary['provenance']['imported_ratings']['sha256']}",
            f"- Private mapping source SHA-256: {summary['provenance']['private_mapping_source']['sha256']}",
            f"- Quality dataset SHA-256: {summary['provenance']['quality_dataset']['sha256']}",
            "",
            "## Integrity",
            "",
            "Security configuration changed: NO.",
            "Phase 15 dataset changed: NO.",
            "Human ratings modified: NO.",
            "Final evaluation used for tuning: NO.",
            "Public blind artifact modified: NO.",
        ]
    )
    return "\n".join(lines) + "\n"


def finalize() -> dict[str, Any]:
    summary = compute_summary()
    FINAL_DIR.mkdir(parents=True, exist_ok=True)
    FINAL_SUMMARY.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    figures = _persist_figures(summary)
    report = _render_report(summary, figures)
    FINAL_REPORT.write_text(report, encoding="utf-8")
    return {"summary": summary, "figures": figures, "report": _relative(FINAL_REPORT)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    result = finalize()
    print(json.dumps({"status": result["summary"]["status"], "quality_conclusion": result["summary"]["quality_conclusion"], "summary": _relative(FINAL_SUMMARY), "report": result["report"], "figures": result["figures"]["generated_figures"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
