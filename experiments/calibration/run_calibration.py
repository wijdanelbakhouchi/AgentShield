"""Run the reproducible Phase 4 scoring/threshold calibration.

The runner evaluates only ``datasets/calibration.json``.  The grouped
``held_out_test.json`` is written and schema-checked, but never passed to the
pipeline and never used in a tuning decision.

Reproduce with::

    python -m experiments.calibration.run_calibration
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer import llm_classifier  # noqa: E402
from experiments.calibration.calculate_metrics import (  # noqa: E402
    bootstrap_confidence_intervals,
    compute_metrics,
    score_from_row,
)
from experiments.calibration.dataset import (  # noqa: E402
    SEED,
    build_splits,
    write_split_artifacts,
)
from security.pipeline import SecurityPipeline  # noqa: E402
from providers.service import provider_metadata, reset_provider_metadata  # noqa: E402


SOURCE_DATASET = ROOT / "tests" / "benchmark_dataset.json"
SPLIT_DIR = ROOT / "experiments" / "calibration" / "datasets"
RAW_DIR = ROOT / "experiments" / "calibration" / "raw"
RESULT_DIR = ROOT / "experiments" / "calibration" / "results"
RAW_PATH = RAW_DIR / "calibration_predictions.jsonl"
METRICS_PATH = RESULT_DIR / "calibration_metrics.json"
METADATA_PATH = RESULT_DIR / "calibration_metadata.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _weight_grid(step: float = 0.10) -> List[Dict[str, float]]:
    """Return a coarse, non-negative simplex grid (66 candidates at 0.1)."""
    points = int(round(1.0 / step))
    values: List[Dict[str, float]] = []
    for rule_units in range(points + 1):
        for classifier_units in range(points - rule_units + 1):
            context_units = points - rule_units - classifier_units
            values.append(
                {
                    "rule": round(rule_units * step, 2),
                    "classifier": round(classifier_units * step, 2),
                    "context": round(context_units * step, 2),
                }
            )
    return values


def _threshold_grid(step: float = 0.01) -> List[float]:
    return [round(index * step, 2) for index in range(int(round(1.0 / step)) + 1)]


def _best_threshold(
    rows: Sequence[Mapping[str, Any]],
    weights: Mapping[str, float],
    *,
    policy_mode: str,
    objective: str = "f1",
    max_fpr: float = 0.05,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], bool]:
    threshold_results = [
        compute_metrics(
            rows,
            threshold=threshold,
            weights=weights,
            policy_mode=policy_mode,
        )
        for threshold in _threshold_grid()
    ]
    constrained = [metric for metric in threshold_results if metric["fpr"] <= max_fpr]
    constraint_met = bool(constrained)
    pool = constrained or threshold_results
    # The objective is declared before running the search.  Exact ties use the
    # higher threshold as a conservative/stability tie-breaker.
    selected = max(
        pool,
        key=lambda metric: (
            float(metric[objective]),
            float(metric["f2"]),
            float(metric["threshold"]),
        ),
    )
    return selected, threshold_results, constraint_met


def _candidate_summary(
    rows: Sequence[Mapping[str, Any]],
    candidates: Iterable[Tuple[str, Mapping[str, float]]],
    *,
    policy_mode: str,
    max_fpr: float,
) -> List[Dict[str, Any]]:
    output = []
    for name, weights in candidates:
        selected, _, constraint_met = _best_threshold(
            rows,
            weights,
            policy_mode=policy_mode,
            objective="f1",
            max_fpr=max_fpr,
        )
        output.append(
            {
                "configuration": name,
                "weights": dict(weights),
                "selected_threshold": selected["threshold"],
                "constraint_fpr_limit_met": constraint_met,
                "strict_fpr_le_5pct": selected["fpr"] <= 0.05,
                "precision": selected["precision"],
                "recall": selected["recall"],
                "f1": selected["f1"],
                "f2": selected["f2"],
                "fpr": selected["fpr"],
                "fnr": selected["fnr"],
            }
        )
    return output


def _compact_threshold_metrics(metric: Mapping[str, Any]) -> Dict[str, Any]:
    """Keep the grid artifact small while retaining every threshold metric."""
    return {
        "threshold": metric["threshold"],
        "confusion_matrix": metric["confusion_matrix"],
        "precision": metric["precision"],
        "recall": metric["recall"],
        "f1": metric["f1"],
        "f2": metric["f2"],
        "fpr": metric["fpr"],
        "fnr": metric["fnr"],
    }


def _derive_risk_bands(rows: Sequence[Mapping[str, Any]], weights: Mapping[str, float], block: float) -> Dict[str, float]:
    scores = sorted(score_from_row(row, weights) for row in rows)
    if not scores:
        return {"low_max": 0.0, "medium_max": 0.01, "high_max": round(max(0.02, block - 0.01), 2)}

    def percentile(percent: float) -> float:
        position = (len(scores) - 1) * percent
        low = int(position)
        high = min(len(scores) - 1, low + 1)
        return scores[low] + (scores[high] - scores[low]) * (position - low)

    low = round(percentile(0.25), 2)
    medium = round(percentile(0.50), 2)
    low = min(low, 0.98)
    medium = max(medium, round(low + 0.01, 2))
    medium = min(medium, 0.98)
    high = round(max(percentile(0.75), block - 0.01), 2)
    high = max(high, round(medium + 0.01, 2))
    high = min(high, 0.99)
    # If a threshold is at the upper edge, maintain valid ordered bands.
    if high <= medium:
        medium = max(0.0, round(high - 0.01, 2))
    if medium <= low:
        low = max(0.0, round(medium - 0.01, 2))
    return {"low_max": low, "medium_max": medium, "high_max": high}


def _collect_raw_predictions(samples: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    original_get_llm = llm_classifier.get_llm
    # Deterministic fallback is the verified available stack in this checkout.
    # It prevents accidental network calls and does not invent external LLM data.
    llm_classifier.get_llm = lambda: None
    try:
        rows: List[Dict[str, Any]] = []
        for item in samples:
            reset_provider_metadata()
            result = SecurityPipeline.evaluate(
                item["prompt"],
                source="phase4-calibration",
                target="calibration",
                context_text=item.get("context"),
            )
            classification = result.analysis.llm_classification or {}
            llm_runtime = provider_metadata()
            rows.append(
                {
                    "sample_id": item["id"],
                    "group_id": item["group_id"],
                    "true_label": int(bool(item["is_attack"])),
                    "category": item["category"],
                    "prompt": item["prompt"],
                    "context": item.get("context"),
                    "source": item.get("source", "unknown"),
                    "rule_flags": list(result.analysis.rule_flags),
                    "context_flags": list(result.analysis.context_flags),
                    "llm_classification": classification,
                    "llm_runtime": {
                        "provider": llm_runtime.get("provider"),
                        "model": llm_runtime.get("model"),
                        "mode": llm_runtime.get("mode"),
                        "provider_status": llm_runtime.get("provider_status"),
                        "real_llm": bool(llm_runtime.get("real_llm", False)),
                    },
                    "benchmark_validity": "VALID" if llm_runtime.get("real_llm") else "DEMO_FALLBACK",
                    "baseline_component_scores": {
                        "rule": min(1.0, len(result.analysis.rule_flags) * 0.5),
                        "classifier": (
                            float(classification.get("confidence", 0.0))
                            if classification.get("is_malicious", False)
                            else 0.0
                        ),
                        "context": min(1.0, len(result.analysis.context_flags) * 0.5),
                    },
                    "baseline_risk_score": result.risk.score,
                    "baseline_risk_level": result.risk.level.value,
                    "baseline_policy_decision": result.policy.action.value,
                    "detected": bool(
                        result.analysis.rule_flags
                        or result.analysis.context_flags
                        or classification.get("is_malicious", False)
                    ),
                }
            )
        return rows
    finally:
        llm_classifier.get_llm = original_get_llm


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def run() -> Dict[str, Any]:
    calibration, held_out, split_metadata = build_splits(SOURCE_DATASET, seed=SEED)
    write_split_artifacts(calibration, held_out, split_metadata, SPLIT_DIR)

    # The held-out file is checked for loadability/schema only.  No score or
    # policy call is made for these rows, preserving the evaluation boundary.
    held_out_schema_ok = all(
        isinstance(item.get("id"), str)
        and isinstance(item.get("prompt"), str)
        and isinstance(item.get("is_attack"), bool)
        for item in json.loads((SPLIT_DIR / "held_out_test.json").read_text(encoding="utf-8"))
    )
    rows = _collect_raw_predictions(calibration)
    _write_jsonl(RAW_PATH, rows)

    strict_fpr_limit = 0.05
    benign_count = sum(int(not row["true_label"]) for row in rows)
    # With 18 benign rows, one false positive is 5.56%; a literal 5% grid
    # constraint would reject the single-observation operating point.  We use
    # the smallest empirically resolvable limit and report the strict result
    # separately rather than pretending the sample supports finer precision.
    effective_fpr_limit = max(strict_fpr_limit, 1.0 / benign_count) if benign_count else strict_fpr_limit
    grid = _weight_grid()
    optimized: List[Dict[str, Any]] = []
    for weights in grid:
        selected, _, constraint_met = _best_threshold(
            rows,
            weights,
            policy_mode="score_only",
            objective="f1",
            max_fpr=effective_fpr_limit,
        )
        optimized.append(
            {
                "weights": weights,
                "constraint_fpr_limit_met": constraint_met,
                "strict_fpr_le_5pct": selected["fpr"] <= strict_fpr_limit,
                "selected_threshold": selected["threshold"],
                "precision": selected["precision"],
                "recall": selected["recall"],
                "f1": selected["f1"],
                "f2": selected["f2"],
                "fpr": selected["fpr"],
                "fnr": selected["fnr"],
            }
        )
    best_f1 = max(item["f1"] for item in optimized)
    # The small grid has a performance plateau.  Do not manufacture a unique
    # scientific winner: among candidates within 0.005 F1 of the maximum,
    # retain every active signal, then prefer the candidate closest to the
    # Phase 3 mix as the least disruptive/stable tie-breaker.
    tied_weight_results = [
        item for item in optimized if item["f1"] >= best_f1 - 0.005
    ]
    phase3_weights = {"rule": 0.4, "classifier": 0.4, "context": 0.2}
    selected_weight_result = max(
        tied_weight_results,
        key=lambda item: (
            min(float(value) for value in item["weights"].values()),
            -sum(
                abs(float(item["weights"][key]) - phase3_weights[key])
                for key in phase3_weights
            ),
            float(item["f1"]),
        ),
    )
    selected_weights = selected_weight_result["weights"]
    selected_threshold, threshold_grid, constraint_met = _best_threshold(
        rows,
        selected_weights,
        policy_mode="score_only",
        objective="f1",
        max_fpr=effective_fpr_limit,
    )
    security_threshold, _, security_constraint_met = _best_threshold(
        rows,
        selected_weights,
        policy_mode="score_only",
        objective="f2",
        max_fpr=effective_fpr_limit,
    )

    named_candidates = [
        ("Rules only", {"rule": 1.0, "classifier": 0.0, "context": 0.0}),
        ("Classifier only", {"rule": 0.0, "classifier": 1.0, "context": 0.0}),
        ("Context only", {"rule": 0.0, "classifier": 0.0, "context": 1.0}),
        ("Rules + classifier", {"rule": 0.5, "classifier": 0.5, "context": 0.0}),
        ("Phase 3 weights", {"rule": 0.4, "classifier": 0.4, "context": 0.2}),
        ("Selected grid weights", selected_weights),
    ]
    candidate_results = _candidate_summary(
        rows, named_candidates, policy_mode="score_only", max_fpr=effective_fpr_limit
    )
    policy_comparison = {
        "score_only_selected": selected_threshold,
        "flag_override_at_selected_threshold": compute_metrics(
            rows,
            threshold=selected_threshold["threshold"],
            weights=selected_weights,
            policy_mode="flag_override",
        ),
        "combined_at_selected_threshold": compute_metrics(
            rows,
            threshold=selected_threshold["threshold"],
            weights=selected_weights,
            policy_mode="combined",
        ),
    }
    nearby_thresholds = [
        metric
        for metric in threshold_grid
        if abs(metric["threshold"] - selected_threshold["threshold"]) <= 0.02
    ]
    risk_bands = _derive_risk_bands(
        rows, selected_weights, selected_threshold["threshold"]
    )
    metrics_artifact = {
        "calibration_performance": selected_threshold,
        "strict_5pct_operating_point": _best_threshold(
            rows,
            selected_weights,
            policy_mode="score_only",
            objective="f1",
            max_fpr=strict_fpr_limit,
        )[0],
        "strict_fpr_limit": strict_fpr_limit,
        "effective_fpr_limit": effective_fpr_limit,
        "security_weighted_f2_operating_point": security_threshold,
        "security_weighted_constraint_met": security_constraint_met,
        "threshold_grid": [_compact_threshold_metrics(metric) for metric in threshold_grid],
        "thresholds_near_selected": [
            _compact_threshold_metrics(metric) for metric in nearby_thresholds
        ],
        "selected_weights": selected_weights,
        "risk_bands": risk_bands,
        "candidate_weight_results": candidate_results,
        "optimized_weight_search": optimized,
        "policy_mode_comparison": policy_comparison,
        "bootstrap_ci_95": bootstrap_confidence_intervals(
            rows,
            threshold=selected_threshold["threshold"],
            weights=selected_weights,
            policy_mode="score_only",
            seed=SEED,
            repetitions=1000,
        ),
    }
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(
        json.dumps(metrics_artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    metadata = {
        "artifact": "Phase 4 calibration metadata",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "python_version": platform.python_version(),
        "source_dataset": str(SOURCE_DATASET.relative_to(ROOT).as_posix()),
        "source_dataset_sha256": _sha256(SOURCE_DATASET),
        "calibration_dataset": str((SPLIT_DIR / "calibration.json").relative_to(ROOT).as_posix()),
        "calibration_dataset_sha256": _sha256(SPLIT_DIR / "calibration.json"),
        "raw_predictions": str(RAW_PATH.relative_to(ROOT).as_posix()),
        "raw_predictions_sha256": _sha256(RAW_PATH),
        "sample_counts": {
            "calibration": len(calibration),
            "held_out_schema_checked_only": len(held_out),
            "malicious_calibration": sum(int(bool(item["is_attack"])) for item in calibration),
            "benign_calibration": sum(int(not item["is_attack"]) for item in calibration),
            "security_adjacent_benign_calibration": sum(
                int(item["category"] == "SECURITY_ADJACENT_BENIGN") for item in calibration
            ),
        },
        "split_metadata": split_metadata,
        "held_out_schema_ok": held_out_schema_ok,
        "held_out_used_for_tuning": False,
        "weight_search": {
            "method": "coarse simplex grid at 0.10 increments; non-negative weights summing to 1",
            "candidate_count": len(grid),
            "objective": "maximize F1 subject to FPR <= max(0.05, 1/N_benign); exact ties prefer higher threshold",
            "strict_fpr_limit": strict_fpr_limit,
            "effective_fpr_limit": effective_fpr_limit,
            "small_sample_rule": "use one-benign-observation resolution when it exceeds 5%; report strict 5% point separately",
            "tie_break": "within 0.005 F1 of the maximum, maximize the smallest weight (retain active signals), then minimize distance from Phase 3 weights",
        },
        "threshold_search": "0.00 through 1.00 inclusive in 0.01 increments",
        "random_seed": SEED,
        "llm": {
            "mode": "deterministic heuristic fallback",
            "external_provider_evaluated": False,
            "note": "LLM CLASSIFIER CALIBRATION NOT VERIFIED",
        },
        "policy_mode_selected": "score_only",
        "flag_override_evaluated_separately": True,
        "selected_configuration": {
            **selected_weights,
            "block_threshold": selected_threshold["threshold"],
            "risk_bands": risk_bands,
            "f1_constraint_met": constraint_met,
        },
        "historical_results_modified": False,
        "held_out_metrics_generated": False,
    }
    METADATA_PATH.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return {"metrics": metrics_artifact, "metadata": metadata}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    result = run()
    selected = result["metadata"]["selected_configuration"]
    print(
        json.dumps(
            {
                "calibration_samples": result["metadata"]["sample_counts"]["calibration"],
                "selected_configuration": selected,
                "f1": result["metrics"]["calibration_performance"]["f1"],
                "fpr": result["metrics"]["calibration_performance"]["fpr"],
                "raw_predictions": str(RAW_PATH),
                "metrics": str(METRICS_PATH),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
