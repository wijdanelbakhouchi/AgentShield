"""Independent metric recalculation from raw calibration predictions.

The raw JSONL contains detector features, not hand-entered aggregate numbers.
This module is both importable by the calibration runner and executable as:

    python -m experiments.calibration.calculate_metrics --raw <path> ...
"""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple


def _component_values(row: Mapping[str, Any]) -> Tuple[float, float, float]:
    component = row.get("baseline_component_scores") or row.get("component_scores") or {}
    return (
        float(component.get("rule", 0.0)),
        float(component.get("classifier", 0.0)),
        float(component.get("context", 0.0)),
    )


def score_from_row(row: Mapping[str, Any], weights: Mapping[str, float]) -> float:
    """Reproduce the canonical additive score and its production rounding."""
    rule, classifier, context = _component_values(row)
    raw = (
        float(weights["rule"]) * rule
        + float(weights["classifier"]) * classifier
        + float(weights["context"]) * context
    )
    return round(min(1.0, max(0.0, raw)), 2)


def _flagged(row: Mapping[str, Any]) -> bool:
    if "detected" in row:
        return bool(row["detected"])
    classification = row.get("llm_classification") or {}
    return bool(
        row.get("rule_flags")
        or row.get("context_flags")
        or classification.get("is_malicious", False)
    )


def decision_for_row(
    row: Mapping[str, Any],
    *,
    threshold: float,
    weights: Mapping[str, float],
    policy_mode: str = "score_only",
) -> Tuple[str, float]:
    """Return the binary calibration action and score for one raw row."""
    score = score_from_row(row, weights)
    score_block = score >= float(threshold)
    if policy_mode == "score_only":
        blocked = score_block
    elif policy_mode == "flag_override":
        blocked = _flagged(row)
    elif policy_mode == "combined":
        blocked = score_block or _flagged(row)
    else:
        raise ValueError(f"Unknown policy mode: {policy_mode}")
    return ("BLOCK" if blocked else "ALLOW"), score


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def _f1(precision: float, recall: float) -> float:
    return _safe_div(2 * precision * recall, precision + recall)


def _f_beta(precision: float, recall: float, beta: float) -> float:
    beta_sq = beta * beta
    return _safe_div((1 + beta_sq) * precision * recall, beta_sq * precision + recall)


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * (percentile / 100.0)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def _auc_roc(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    concordant = 0.0
    for index, score in enumerate(scores):
        if labels[index] != 1:
            continue
        for other_index, other_score in enumerate(scores):
            if labels[other_index] == 0:
                if score > other_score:
                    concordant += 1.0
                elif score == other_score:
                    concordant += 0.5
    return concordant / (positives * negatives)


def _auc_pr(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positives = sum(labels)
    if not positives:
        return None
    order = sorted(range(len(scores)), key=lambda i: (-float(scores[i]), i))
    tp = 0
    fp = 0
    previous_recall = 0.0
    area = 0.0
    for index in order:
        if labels[index] == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        area += (recall - previous_recall) * precision
        previous_recall = recall
    return area


def _score_distribution(rows: Sequence[Mapping[str, Any]], scores: Sequence[float]) -> Dict[str, Any]:
    distributions: Dict[str, List[float]] = defaultdict(list)
    for row, score in zip(rows, scores):
        distributions["malicious" if bool(row["true_label"]) else "benign"].append(score)
    result: Dict[str, Any] = {}
    for label, values in distributions.items():
        result[label] = {
            "n": len(values),
            "minimum": min(values) if values else 0.0,
            "maximum": max(values) if values else 0.0,
            "mean": round(sum(values) / len(values), 4) if values else 0.0,
            "median": round(_percentile(values, 50), 4),
            "p25": round(_percentile(values, 25), 4),
            "p75": round(_percentile(values, 75), 4),
            "p90": round(_percentile(values, 90), 4),
        }
    return result


def compute_metrics(
    rows: Sequence[Mapping[str, Any]],
    *,
    threshold: float,
    weights: Mapping[str, float],
    policy_mode: str = "score_only",
) -> Dict[str, Any]:
    """Calculate confusion, category, distribution, and AUC metrics."""
    scores: List[float] = []
    decisions: List[str] = []
    tp = tn = fp = fn = 0
    detected_malicious = 0
    for row in rows:
        decision, score = decision_for_row(
            row,
            threshold=threshold,
            weights=weights,
            policy_mode=policy_mode,
        )
        scores.append(score)
        decisions.append(decision)
        label = bool(row["true_label"])
        if label and _flagged(row):
            detected_malicious += 1
        if label and decision == "BLOCK":
            tp += 1
        elif label:
            fn += 1
        elif decision == "BLOCK":
            fp += 1
        else:
            tn += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _f1(precision, recall)
    f2 = _f_beta(precision, recall, 2.0)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)
    accuracy = _safe_div(tp + tn, len(rows))
    balanced_accuracy = (
        _safe_div(tp, tp + fn) + _safe_div(tn, tn + fp)
    ) / 2.0
    category_counts: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"n": 0, "tp": 0, "tn": 0, "fp": 0, "fn": 0}
    )
    for row, decision in zip(rows, decisions):
        category = str(row["category"])
        bucket = category_counts[category]
        bucket["n"] += 1
        label = bool(row["true_label"])
        if label and decision == "BLOCK":
            bucket["tp"] += 1
        elif label:
            bucket["fn"] += 1
        elif decision == "BLOCK":
            bucket["fp"] += 1
        else:
            bucket["tn"] += 1

    category_metrics: Dict[str, Dict[str, Any]] = {}
    for category, counts in sorted(category_counts.items()):
        category_metrics[category] = {
            **counts,
            "recall": _safe_div(counts["tp"], counts["tp"] + counts["fn"]),
            "fpr": _safe_div(counts["fp"], counts["fp"] + counts["tn"]),
        }

    labels = [int(bool(row["true_label"])) for row in rows]
    return {
        "threshold": round(float(threshold), 2),
        "weights": {key: round(float(value), 4) for key, value in weights.items()},
        "policy_mode": policy_mode,
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "f2": f2,
        "accuracy": accuracy,
        "balanced_accuracy": balanced_accuracy,
        "fpr": fpr,
        "fnr": fnr,
        "detection_rate": _safe_div(detected_malicious, sum(labels)),
        "prevention_rate": recall,
        "attack_success_rate": fnr,
        "category_metrics": category_metrics,
        "score_distribution": _score_distribution(rows, scores),
        "roc_auc": _auc_roc(labels, scores),
        "pr_auc": _auc_pr(labels, scores),
    }


def bootstrap_confidence_intervals(
    rows: Sequence[Mapping[str, Any]],
    *,
    threshold: float,
    weights: Mapping[str, float],
    policy_mode: str,
    seed: int = 42,
    repetitions: int = 1000,
) -> Dict[str, Dict[str, float]]:
    """Return percentile 95% bootstrap intervals for key metrics."""
    if not rows:
        return {}
    rng = random.Random(seed)
    samples: Dict[str, List[float]] = defaultdict(list)
    for _ in range(repetitions):
        resample = [rows[rng.randrange(len(rows))] for _ in rows]
        metrics = compute_metrics(
            resample,
            threshold=threshold,
            weights=weights,
            policy_mode=policy_mode,
        )
        for key in ("precision", "recall", "f1", "fpr"):
            samples[key].append(float(metrics[key]))
    return {
        key: {
            "lower_95": round(_percentile(values, 2.5), 4),
            "upper_95": round(_percentile(values, 97.5), 4),
        }
        for key, values in samples.items()
    }


def _parse_weights(value: str) -> Dict[str, float]:
    parts = [float(part.strip()) for part in value.split(",")]
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("weights must be rule,classifier,context")
    return {"rule": parts[0], "classifier": parts[1], "context": parts[2]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--threshold", required=True, type=float)
    parser.add_argument("--weights", required=True, type=_parse_weights)
    parser.add_argument(
        "--policy-mode",
        choices=("score_only", "flag_override", "combined"),
        default="score_only",
    )
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.raw.read_text(encoding="utf-8").splitlines() if line.strip()]
    print(
        json.dumps(
            compute_metrics(
                rows,
                threshold=args.threshold,
                weights=args.weights,
                policy_mode=args.policy_mode,
            ),
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
