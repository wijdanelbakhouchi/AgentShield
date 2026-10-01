"""Reproducible post-Phase-6 global score/policy calibration.

The runner intentionally works on a checked-in development/calibration artifact.
It refuses protected final-test paths and never imports the historical benchmark
datasets.  Semantic values already recorded by the Phase 6 development run are
used as evidence when the pinned model is unavailable offline; no replacement
encoder or lexical approximation is introduced.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import platform
import random
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from analyzer.context_analyzer import ContextAnalyzer
from analyzer.llm_classifier import LLMSecurityClassifier
from analyzer.rule_detector import RuleBasedDetector
from analyzer.semantic_similarity import get_semantic_detector
from config import (
    SEMANTIC_MODEL_NAME,
    SEMANTIC_MODEL_REVISION,
    SEMANTIC_SIMILARITY_THRESHOLD,
)
from gateway.interceptor import SecurityGateway
from providers.service import provider_metadata, reset_provider_metadata

# Immutable historical PRE-HARDENING operating point. These literals are
# intentionally not imported from config.py, which now contains the selected
# post-hardening values.
PHASE4_RULE_WEIGHT = 0.40
PHASE4_CLASSIFIER_WEIGHT = 0.30
PHASE4_CONTEXT_WEIGHT = 0.30
PHASE4_BLOCK_THRESHOLD = 0.20


ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = ROOT / "experiments" / "post_hardening_calibration" / "datasets" / "post_hardening_calibration.json"
RAW_DIR = ROOT / "experiments" / "post_hardening_calibration" / "raw"
RESULTS_DIR = ROOT / "experiments" / "post_hardening_calibration" / "results"
SEED = 6502
GRID_STEP = 0.1
THRESHOLD_STEP = 0.01
PROTECTED_NAMES = {
    "held_out_test.json",
    "benchmark_dataset.json",
    "adversarial_benchmark",
    "final_test",
    "heldout",
}


def _round(value: float, digits: int = 6) -> float:
    return round(float(value), digits)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dataset_hash(document: Mapping[str, Any]) -> str:
    payload = json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(payload)


def _assert_safe_path(path: Path) -> None:
    lowered = str(path).replace("\\", "/").casefold()
    if any(name in lowered for name in PROTECTED_NAMES):
        raise RuntimeError(f"Calibration safety guard rejected protected path: {path}")


def _load_dataset() -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    _assert_safe_path(DATASET_PATH)
    document = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("post-hardening calibration dataset must contain cases")
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("calibration cases must be objects")
        required = {"id", "label", "category", "family", "group_id", "source", "role", "text"}
        missing = required - set(case)
        if missing:
            raise ValueError(f"calibration case missing fields: {sorted(missing)}")
        if str(case.get("source", "")).casefold() in {"final", "heldout", "benchmark"}:
            raise RuntimeError("Calibration safety guard rejected final/benchmark provenance")
    selected: Dict[str, Dict[str, Any]] = {}
    grouped_variants = 0
    for case in cases:
        group_id = str(case["group_id"])
        if group_id in selected:
            grouped_variants += 1
            continue
        selected[group_id] = case
    groups = list(selected.values())
    duplicate_report = _duplicate_report(cases, groups)
    return document, groups, {"original_count": len(cases), "effective_group_count": len(groups), "grouped_variants": grouped_variants, **duplicate_report}


def _normalize_for_duplicate(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text).casefold()).strip()


def _duplicate_report(cases: Sequence[Mapping[str, Any]], groups: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    exact: Dict[str, List[str]] = defaultdict(list)
    normalized: Dict[str, List[str]] = defaultdict(list)
    for case in cases:
        text = str(case.get("text", ""))
        exact[text].append(str(case.get("id")))
        normalized[_normalize_for_duplicate(text)].append(str(case.get("id")))
    exact_dupes = [ids for ids in exact.values() if len(ids) > 1]
    normalized_dupes = [ids for ids in normalized.values() if len(ids) > 1]
    near_pairs: List[List[str]] = []
    for index, left in enumerate(groups):
        for right in groups[index + 1 :]:
            ratio = difflib.SequenceMatcher(
                None, _normalize_for_duplicate(str(left.get("text"))), _normalize_for_duplicate(str(right.get("text")))
            ).ratio()
            if ratio >= 0.92:
                near_pairs.append([str(left["id"]), str(right["id"])])
    return {
        "exact_duplicate_groups": exact_dupes,
        "normalized_duplicate_groups": normalized_dupes,
        "near_duplicate_pairs": near_pairs,
        "duplicates_collapsed": max(0, len(cases) - len(groups)),
    }


def _context_flags(context_text: str) -> List[str]:
    context_result = ContextAnalyzer.analyze_context(context_text or "")
    flags = list(context_result.get("flags", []))
    context_rule_result = RuleBasedDetector.scan(context_text or "")
    for flag in context_rule_result.get("flags", []):
        value = f"CONTEXT_CONTENT:{flag}"
        if value not in flags:
            flags.append(value)
    return flags


def _semantic_evidence(case: Mapping[str, Any], normalized: str, representations: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    evidence = case.get("semantic_score_evidence")
    if evidence is not None:
        score = max(-1.0, min(1.0, float(evidence)))
        return {
            "status": "ready",
            "semantic_similarity_enabled": True,
            "threshold": SEMANTIC_SIMILARITY_THRESHOLD,
            "top_match": {"similarity": _round(score), "category": str(case.get("category")), "corpus_id": "phase6-development-evidence"},
            "flagged": score >= SEMANTIC_SIMILARITY_THRESHOLD,
            "evidence_source": "phase6_development_evidence",
        }
    if case.get("semantic_evidence_unavailable"):
        return {
            "status": "unavailable",
            "semantic_similarity_enabled": False,
            "threshold": SEMANTIC_SIMILARITY_THRESHOLD,
            "top_match": None,
            "flagged": False,
            "evidence_source": "post_hardening_runtime_unavailable",
        }
    # A live call is permitted only for a case without recorded Phase 6 evidence.
    # If the pinned model cannot be loaded, the detector's explicit unavailable
    # result maps to a zero semantic signal; it is never replaced by a heuristic.
    return get_semantic_detector().detect(normalized, representations)


def _collect_signal(case: Mapping[str, Any]) -> Dict[str, Any]:
    reset_provider_metadata()
    payload = SecurityGateway.process(str(case.get("text", "")), source="calibration", target="calibration")
    representations = payload.normalization_metadata.get("representations", [])
    rule_result = RuleBasedDetector.scan(representations or payload.normalized_input)
    rule_flags = list(rule_result.get("flags", []))
    llm_classification = LLMSecurityClassifier.classify(payload.normalized_input)
    llm_runtime = provider_metadata()
    context_flags = _context_flags(str(case.get("context_text", "")))
    semantic = _semantic_evidence(case, payload.normalized_input, representations)
    semantic_top = semantic.get("top_match") or {}
    semantic_score = float(semantic_top.get("similarity", 0.0)) if semantic.get("flagged") else 0.0
    return {
        "sample_id": str(case["id"]),
        "true_label": int(case["label"]),
        "category": str(case["category"]),
        "family": str(case["family"]),
        "group_id": str(case["group_id"]),
        "text": str(case["text"]),
        "rule_flags": rule_flags,
        "context_flags": context_flags,
        "llm_classification": llm_classification,
        "llm_runtime": {
            "provider": llm_runtime.get("provider"),
            "model": llm_runtime.get("model"),
            "mode": llm_runtime.get("mode"),
            "provider_status": llm_runtime.get("provider_status"),
            "real_llm": bool(llm_runtime.get("real_llm", False)),
        },
        "benchmark_validity": "VALID" if llm_runtime.get("real_llm") else "DEMO_FALLBACK",
        "semantic_evidence": semantic,
        "rule_signal": _round(min(1.0, len(rule_flags) * 0.5)),
        "semantic_signal": _round(max(0.0, min(1.0, semantic_score))),
        "classifier_signal": _round(
            float(llm_classification.get("confidence", 0.0))
            if llm_classification.get("is_malicious", False)
            else 0.0
        ),
        "context_signal": _round(min(1.0, len(context_flags) * 0.5)),
        "semantic_status": str(semantic.get("status", "unknown")),
        "normalization_metadata": payload.normalization_metadata,
    }


def _simplex_weights(step: float = GRID_STEP) -> Iterable[Tuple[float, float, float, float]]:
    n = int(round(1.0 / step))
    for rule in range(n + 1):
        for semantic in range(n - rule + 1):
            for classifier in range(n - rule - semantic + 1):
                context = n - rule - semantic - classifier
                yield tuple(_round(value / n, 2) for value in (rule, semantic, classifier, context))


def _risk_level(score: float, bands: Mapping[str, float]) -> str:
    if score <= bands["low_max"]:
        return "LOW"
    if score <= bands["medium_max"]:
        return "MEDIUM"
    if score <= bands["high_max"]:
        return "HIGH"
    return "CRITICAL"


def _score(row: Mapping[str, Any], weights: Mapping[str, float]) -> float:
    return _round(
        min(
            1.0,
            max(
                0.0,
                weights["rule"] * float(row["rule_signal"])
                + weights["semantic"] * float(row["semantic_signal"])
                + weights["classifier"] * float(row["classifier_signal"])
                + weights["context"] * float(row["context_signal"]),
            ),
        )
    )


def _has_any_flag(row: Mapping[str, Any]) -> bool:
    return bool(row["rule_flags"] or row["context_flags"] or row["semantic_evidence"].get("flagged") or row["llm_classification"].get("is_malicious"))


def _has_high_confidence_flag(row: Mapping[str, Any]) -> bool:
    llm_confidence = float(row["llm_classification"].get("confidence", 0.0))
    return bool(
        float(row["rule_signal"]) >= 1.0
        or float(row["context_signal"]) >= 1.0
        or llm_confidence >= 0.90
        or float(row["semantic_signal"]) >= 0.65
    )


def _blocked(row: Mapping[str, Any], threshold: float, weights: Mapping[str, float], mode: str) -> bool:
    score_block = _score(row, weights) >= threshold
    if mode == "score_only":
        return score_block
    if mode == "unconditional_flag_override":
        return score_block or _has_any_flag(row)
    if mode == "high_confidence_flag_override":
        return score_block or _has_high_confidence_flag(row)
    raise ValueError(f"unknown policy mode: {mode}")


def _metrics(rows: Sequence[Mapping[str, Any]], threshold: float, weights: Mapping[str, float], mode: str = "score_only") -> Dict[str, Any]:
    tp = tn = fp = fn = 0
    for row in rows:
        predicted = _blocked(row, threshold, weights, mode)
        actual = int(row["true_label"]) == 1
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
        elif not predicted and not actual:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    beta2 = 4.0
    f2 = (1 + beta2) * precision * recall / (beta2 * precision + recall) if beta2 * precision + recall else 0.0
    total = tp + tn + fp + fn
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "precision": _round(precision),
        "recall": _round(recall),
        "f1": _round(f1),
        "f2": _round(f2),
        "accuracy": _round((tp + tn) / total if total else 0.0),
        "balanced_accuracy": _round((recall + specificity) / 2),
        "fpr": _round(fpr),
        "fnr": _round(fnr),
        "policy_mode": mode,
        "threshold": _round(threshold, 2),
        "weights": dict(weights),
    }


def _select_search(rows: Sequence[Mapping[str, Any]]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    grid: List[Dict[str, Any]] = []
    for weights_tuple in _simplex_weights():
        weights = dict(zip(("rule", "semantic", "classifier", "context"), weights_tuple))
        for index in range(101):
            threshold = _round(index / 100, 2)
            metrics = _metrics(rows, threshold, weights)
            metrics["candidate_id"] = f"w-{weights_tuple[0]:.2f}-{weights_tuple[1]:.2f}-{weights_tuple[2]:.2f}-{weights_tuple[3]:.2f}-t-{threshold:.2f}"
            grid.append(metrics)
    eligible = [item for item in grid if item["fpr"] <= 0.10]
    if not eligible:
        eligible = grid
    # F1 is primary; F2 and a non-zero semantic weight are transparent tie
    # breakers.  Simpler, lower-dimensional candidates win exact ties.
    selected = max(
        eligible,
        key=lambda item: (
            item["f1"],
            item["f2"],
            1 if item["weights"]["semantic"] > 0 else 0,
            -sum(1 for value in item["weights"].values() if value > 0),
            -item["threshold"],
        ),
    )
    return selected, grid


def _derive_bands(threshold: float) -> Dict[str, float]:
    # Broad telemetry bands are secondary to the binary block operating point.
    low = _round(min(0.20, threshold * 0.40), 2)
    medium = _round(min(0.40, threshold * 0.75), 2)
    high = _round(max(medium + 0.01, threshold - 0.01), 2)
    if high >= threshold:
        high = _round(max(medium + 0.01, threshold - 0.01), 2)
    return {"low_max": low, "medium_max": medium, "high_max": high}


def _raw_predictions(rows: Sequence[Mapping[str, Any]], selected: Mapping[str, Any], bands: Mapping[str, float], config_id: str) -> List[Dict[str, Any]]:
    weights = selected["weights"]
    threshold = float(selected["threshold"])
    output = []
    for row in rows:
        score = _score(row, weights)
        output.append(
            {
                "sample_id": row["sample_id"],
                "true_label": row["true_label"],
                "category": row["category"],
                "group_id": row["group_id"],
                "rule_signal": row["rule_signal"],
                "semantic_signal": row["semantic_signal"],
                "classifier_signal": row["classifier_signal"],
                "context_signal": row["context_signal"],
                "final_risk_score": score,
                "risk_level": _risk_level(score, bands),
                "decision": "BLOCK" if score >= threshold else "ALLOW",
                "selected_configuration_id": config_id,
            }
        )
    return output


def _bootstrap_ci(rows: Sequence[Mapping[str, Any]], selected: Mapping[str, Any], seed: int = SEED, iterations: int = 1000) -> Dict[str, Any]:
    rng = random.Random(seed)
    groups = sorted({str(row["group_id"]) for row in rows})
    by_group = {group: [row for row in rows if str(row["group_id"]) == group] for group in groups}
    values: Dict[str, List[float]] = defaultdict(list)
    for _ in range(iterations):
        sample_groups = [rng.choice(groups) for _ in groups]
        sample = [row for group in sample_groups for row in by_group[group]]
        metrics = _metrics(sample, float(selected["threshold"]), selected["weights"])
        for name in ("precision", "recall", "f1", "f2", "fpr", "fnr"):
            values[name].append(float(metrics[name]))
    return {
        name: {"lower": _round(sorted(samples)[int(0.025 * iterations)]), "upper": _round(sorted(samples)[int(0.975 * iterations) - 1]), "iterations": iterations}
        for name, samples in values.items()
    }


def _category_analysis(rows: Sequence[Mapping[str, Any]], selected: Mapping[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    categories = sorted({str(row["category"]) for row in rows})
    category_rows = []
    benign_rows = []
    for category in categories:
        subset = [row for row in rows if row["category"] == category]
        positives = sum(int(row["true_label"]) for row in subset)
        metrics = _metrics(subset, float(selected["threshold"]), selected["weights"])
        category_rows.append({"category": category, "N": len(subset), "TP": metrics["TP"], "FN": metrics["FN"], "recall": metrics["recall"] if positives else None})
        if not positives:
            benign_rows.append({"category": category, "N": len(subset), "FP": metrics["FP"], "fpr": metrics["fpr"]})
    return category_rows, benign_rows


def _comparison(rows: Sequence[Mapping[str, Any]], selected: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    phase4 = {"rule": PHASE4_RULE_WEIGHT, "semantic": 0.0, "classifier": PHASE4_CLASSIFIER_WEIGHT, "context": PHASE4_CONTEXT_WEIGHT}
    rules_only = {"rule": 1.0, "semantic": 0.0, "classifier": 0.0, "context": 0.0}
    rules_context = {"rule": 0.7, "semantic": 0.0, "classifier": 0.0, "context": 0.3}
    rules_semantic = {"rule": 0.5, "semantic": 0.5, "classifier": 0.0, "context": 0.0}
    rules_semantic_context = {"rule": 0.5, "semantic": 0.3, "classifier": 0.0, "context": 0.2}
    selected_weights = selected["weights"]

    def best_fixed(weights: Mapping[str, float]) -> Dict[str, Any]:
        candidates = [_metrics(rows, _round(index / 100, 2), weights) for index in range(101)]
        eligible = [item for item in candidates if item["fpr"] <= 0.10]
        return max(eligible or candidates, key=lambda item: (item["f1"], item["f2"], -item["threshold"]))

    return {
        "phase4_config": _metrics(rows, PHASE4_BLOCK_THRESHOLD, phase4),
        "rules_only": best_fixed(rules_only),
        "rules_plus_context": best_fixed(rules_context),
        "rules_plus_semantic": best_fixed(rules_semantic),
        "rules_plus_semantic_context": best_fixed(rules_semantic_context),
        "full_available_canonical_scorer": _metrics(rows, float(selected["threshold"]), selected_weights),
        "selected": _metrics(rows, float(selected["threshold"]), selected_weights),
    }


def _stability(rows: Sequence[Mapping[str, Any]], selected: Mapping[str, Any]) -> Dict[str, Any]:
    threshold = float(selected["threshold"])
    thresholds = []
    for offset in (-0.03, -0.02, -0.01, 0.0, 0.01, 0.02, 0.03):
        candidate = max(0.0, min(1.0, _round(threshold + offset, 2)))
        thresholds.append(_metrics(rows, candidate, selected["weights"]))
    close_weights = []
    for weights in _simplex_weights():
        candidate = dict(zip(("rule", "semantic", "classifier", "context"), weights))
        distance = sum(abs(float(candidate[key]) - float(selected["weights"][key])) for key in candidate)
        if distance <= 0.20:
            metrics = _metrics(rows, threshold, candidate)
            if abs(metrics["f1"] - selected["f1"]) <= 0.02:
                close_weights.append({"weights": candidate, "f1": metrics["f1"], "f2": metrics["f2"], "distance_l1": _round(distance)})
    return {"threshold_neighbors": thresholds, "nearby_weight_candidates": close_weights[:50], "nearby_weight_count": len(close_weights)}


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def _write_json(path: Path, value: Any, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=None if compact else 2, ensure_ascii=False, separators=(",", ":") if compact else None)
        + "\n",
        encoding="utf-8",
    )


def run() -> Dict[str, Any]:
    document, cases, duplicate_report = _load_dataset()
    rows = [_collect_signal(case) for case in cases]
    selected, search_grid = _select_search(rows)
    bands = _derive_bands(float(selected["threshold"]))
    config_id = str(selected["candidate_id"])
    raw = _raw_predictions(rows, selected, bands, config_id)
    selected_metrics = _metrics(rows, float(selected["threshold"]), selected["weights"])
    comparison = _comparison(rows, selected)
    override_metrics = {
        mode: _metrics(rows, float(selected["threshold"]), selected["weights"], mode)
        for mode in ("score_only", "unconditional_flag_override", "high_confidence_flag_override")
    }
    categories, benign = _category_analysis(rows, selected)
    result = {
        "schema_version": "1.0",
        "calibration_type": "POST-HARDENING / POST-SEMANTIC GLOBAL CALIBRATION",
        "dataset_version": document["dataset_version"],
        "dataset_path": str(DATASET_PATH.relative_to(ROOT)),
        "dataset_sha256": _dataset_hash(document),
        "heldout_used": False,
        "final_test_used": False,
        "detectors_frozen": True,
        "git_commit": _git_commit(),
        "python_version": platform.python_version(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": SEED,
        "model": {"name": SEMANTIC_MODEL_NAME, "revision": SEMANTIC_MODEL_REVISION, "threshold": SEMANTIC_SIMILARITY_THRESHOLD, "corpus_hash_sha256": "1eb918f80ea304c737ffe0347f1031ff4b96e6f33bfe27472f876d8fd3b59c8a"},
        "signal_definitions": {
            "rule": "min(1, 0.5 * number of unique deterministic rule flags)",
            "semantic": "threshold-gated raw cosine in [0,1]; score is zero below the frozen 0.51 detector threshold",
            "classifier": "fallback/provider confidence only when is_malicious=true; unavailable/benign is zero, never fabricated",
            "context": "min(1, 0.5 * number of unique context flags)",
        },
        "classifier_runtime": {"external_provider_available": False, "calibration_status": "NOT RUNTIME VERIFIED", "scoring_behavior": "The checked-in heuristic fallback contributes only its explicit malicious confidence; no external confidence is synthesized.", "fallback_policy": "Rows generated without a successful external completion are labelled DEMO_FALLBACK and are not runtime-provider evidence."},
        "dataset_summary": duplicate_report,
        "search": {"weight_grid": "simplex step 0.10", "threshold_grid": "0.00..1.00 step 0.01", "candidate_count": len(search_grid), "selection_objective": "maximize F1 subject to FPR <= 0.10; F2, semantic-positive weight, simplicity and threshold stability are tie-breakers", "fpr_constraints_evaluated": [0.10, 0.05]},
        "selected": {**selected, "risk_bands": bands},
        "selected_metrics": selected_metrics,
        "comparison": comparison,
        "flag_override_analysis": override_metrics,
        "category_analysis": categories,
        "benign_analysis": benign,
        "stability": _stability(rows, selected),
        "bootstrap_95_ci": _bootstrap_ci(rows, selected),
        "semantic_contribution_check": {
            "sample_id": "pos-01",
            "without_semantic": _score(next(row for row in rows if row["sample_id"] == "pos-01"), {"rule": selected["weights"]["rule"], "semantic": 0.0, "classifier": selected["weights"]["classifier"], "context": selected["weights"]["context"]}),
            "with_semantic": _score(next(row for row in rows if row["sample_id"] == "pos-01"), selected["weights"]),
            "deterministic_rule_signal": next(row for row in rows if row["sample_id"] == "pos-01")["rule_signal"],
            "semantic_signal": next(row for row in rows if row["sample_id"] == "pos-01")["semantic_signal"],
        },
        "raw_prediction_file": "experiments/post_hardening_calibration/raw/selected_predictions.jsonl",
        "search_results_file": "experiments/post_hardening_calibration/results/search_results.json",
        "metrics_file": "experiments/post_hardening_calibration/results/metrics.json",
        "reproduction_command": ".venv\\Scripts\\python.exe -m experiments.post_hardening_calibration.run_calibration",
    }
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _assert_safe_path(RAW_DIR / "selected_predictions.jsonl")
    (RAW_DIR / "selected_predictions.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in raw), encoding="utf-8")
    # The complete grid is retained for independent checking, but serialized
    # compactly so a small 0.10 simplex/0.01 threshold search is not inflated by
    # pretty-print whitespace.
    _write_json(RESULTS_DIR / "search_results.json", {"grid": search_grid, "selected": selected}, compact=True)
    _write_json(RESULTS_DIR / "metrics.json", {"selected": selected_metrics, "comparison": comparison, "flag_override_analysis": override_metrics, "category_analysis": categories, "benign_analysis": benign, "stability": result["stability"], "bootstrap_95_ci": result["bootstrap_95_ci"]})
    _write_json(RESULTS_DIR / "calibration_metadata.json", result)
    return result


if __name__ == "__main__":
    output = run()
    print(json.dumps({"selected": output["selected"], "selected_metrics": output["selected_metrics"], "dataset_summary": output["dataset_summary"]}, indent=2))
