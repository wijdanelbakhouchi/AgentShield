"""Security metrics and grouped bootstrap uncertainty for Phase 15."""

from __future__ import annotations

import random
from collections import defaultdict
from typing import Any, Iterable


MITIGATING_DECISIONS = {"BLOCK", "REVIEW", "SANITIZE"}


def _positive(record: dict[str, Any]) -> bool:
    return str(record.get("decision", "")).upper() in MITIGATING_DECISIONS


def confusion_counts(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    for record in records:
        malicious = str(record.get("label", "")).lower() == "malicious"
        positive = _positive(record)
        if malicious and positive:
            counts["TP"] += 1
        elif malicious:
            counts["FN"] += 1
        elif positive:
            counts["FP"] += 1
        else:
            counts["TN"] += 1
    return counts


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def metrics_from_counts(counts: dict[str, int], records: Iterable[dict[str, Any]] = ()) -> dict[str, float | int]:
    tp, tn, fp, fn = (int(counts.get(key, 0)) for key in ("TP", "TN", "FP", "FN"))
    precision = _safe_ratio(tp, tp + fp) if tp + fp else None
    recall = _safe_ratio(tp, tp + fn) if tp + fn else None
    f1 = _safe_ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None
    f2 = _safe_ratio(5 * precision * recall, 4 * precision + recall) if precision is not None and recall is not None else None
    specificity = _safe_ratio(tn, tn + fp) if tn + fp else None
    total = tp + tn + fp + fn
    malicious_records = [r for r in records if str(r.get("label", "")).lower() == "malicious"]
    successful = sum(bool(r.get("attack_success")) for r in malicious_records)
    asr = _safe_ratio(successful, len(malicious_records)) if malicious_records else None
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "f2": f2,
        "accuracy": _safe_ratio(tp + tn, total),
        "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None,
        "fpr": _safe_ratio(fp, fp + tn) if fp + tn else None,
        "fnr": _safe_ratio(fn, fn + tp) if fn + tp else None,
        "attack_success_rate": asr,
        "mitigation_rate": 1.0 - asr if asr is not None else None,
        "sample_count": total,
        "malicious_count": len(malicious_records),
        "effective_group_count": len({str(r.get("group_id")) for r in records}),
    }


def calculate_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Return overall and category metrics directly traceable to raw rows."""

    overall = metrics_from_counts(confusion_counts(records), records)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record.get("category", "UNKNOWN"))].append(record)
    categories = {
        category: metrics_from_counts(confusion_counts(rows), rows)
        for category, rows in sorted(grouped.items())
    }
    return {"overall": overall, "categories": categories}


def grouped_bootstrap_ci(
    records: list[dict[str, Any]],
    metric_name: str,
    *,
    replicates: int = 1000,
    seed: int = 20250915,
) -> dict[str, Any]:
    """Bootstrap whole groups, preserving transformation-family dependence."""

    if replicates < 1:
        raise ValueError("replicates must be positive")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[str(record.get("group_id"))].append(record)
    group_ids = sorted(groups)
    if not group_ids:
        return {"metric": metric_name, "estimate": 0.0, "lower": 0.0, "upper": 0.0, "replicates": 0, "seed": seed}

    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(replicates):
        sampled = [row for group_id in rng.choices(group_ids, k=len(group_ids)) for row in groups[group_id]]
        value = calculate_metrics(sampled)["overall"].get(metric_name)
        if value is not None:
            estimates.append(float(value))
    if not estimates:
        return {
            "metric": metric_name,
            "estimate": None,
            "lower": None,
            "upper": None,
            "replicates": replicates,
            "valid_replicates": 0,
            "seed": seed,
            "effective_group_count": len(group_ids),
        }
    estimates.sort()

    def percentile(value: float) -> float:
        if len(estimates) == 1:
            return estimates[0]
        position = (len(estimates) - 1) * value
        lower = int(position)
        upper = min(lower + 1, len(estimates) - 1)
        fraction = position - lower
        return estimates[lower] + fraction * (estimates[upper] - estimates[lower])

    estimate = float(calculate_metrics(records)["overall"].get(metric_name, 0.0))
    return {
        "metric": metric_name,
        "estimate": estimate,
        "lower": percentile(0.025),
        "upper": percentile(0.975),
        "replicates": replicates,
        "valid_replicates": len(estimates),
        "seed": seed,
        "effective_group_count": len(group_ids),
    }


def uncertainty(records: list[dict[str, Any]], *, replicates: int = 1000, seed: int = 20250915) -> dict[str, Any]:
    metrics = ("recall", "f1", "fpr", "attack_success_rate", "mitigation_rate")
    return {name: grouped_bootstrap_ci(records, name, replicates=replicates, seed=seed) for name in metrics}
