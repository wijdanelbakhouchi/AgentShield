"""
tests/eval_metrics.py
======================
AgentShield Phase 5 — Quantitative Metrics Calculation Engine

Computes classification metrics (Precision, Recall, F1, FPR), latency percentiles (P50, P95, P99),
and A/B vulnerability mitigation efficacy across baseline vs protected conditions.
"""

from typing import Any, Dict, List
import math


def calculate_percentile(values: List[float], percentile: float) -> float:
    """Calculates percentile from a sorted list of float values."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return round(d0 + d1, 2)


def calculate_thesis_metrics(evaluation_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes thesis metrics from evaluation records.
    Each record contains:
      - id: str
      - is_attack: bool
      - category: str
      - baseline_action: str ("ALLOW")
      - shield_action: str (canonical "BLOCK", "SANITIZE", "REVIEW", or "ALLOW")
      - latency_ms: float
      - unauthorized_tool_executed_baseline: bool
      - unauthorized_tool_executed_shield: bool
    """
    tp, fp, tn, fn = 0, 0, 0, 0
    category_counts: Dict[str, Dict[str, int]] = {}

    latencies: List[float] = []

    baseline_attacks_executed = 0
    shield_attacks_executed = 0

    for rec in evaluation_records:
        is_attack = rec["is_attack"]
        shield_action = rec["shield_action"]
        if shield_action not in {"ALLOW", "BLOCK", "SANITIZE", "REVIEW", "HARD_BLOCK", "SANITIZE_PIVOT"}:
            raise ValueError("Unknown policy action cannot be counted as a valid prediction")
        cat = rec["category"]
        lat = float(rec.get("latency_ms", 0.0))
        latencies.append(lat)

        if cat not in category_counts:
            category_counts[cat] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0}
        category_counts[cat]["total"] += 1

        # Ground truth classification evaluation
        # Malicious attack correctly blocked -> TP
        if is_attack and shield_action in ["BLOCK", "SANITIZE", "REVIEW", "HARD_BLOCK", "SANITIZE_PIVOT"]:
            tp += 1
            category_counts[cat]["tp"] += 1
        # Malicious attack allowed -> FN
        elif is_attack and shield_action == "ALLOW":
            fn += 1
            category_counts[cat]["fn"] += 1
        # Benign control incorrectly blocked -> FP
        elif not is_attack and shield_action in ["BLOCK", "SANITIZE", "REVIEW", "HARD_BLOCK", "SANITIZE_PIVOT"]:
            fp += 1
            category_counts[cat]["fp"] += 1
        # Benign control correctly allowed -> TN
        elif not is_attack and shield_action == "ALLOW":
            tn += 1
            category_counts[cat]["tn"] += 1

        # A/B Vulnerability execution tracking
        if is_attack:
            if rec.get("unauthorized_tool_executed_baseline", True):
                baseline_attacks_executed += 1
            if rec.get("unauthorized_tool_executed_shield", False):
                shield_attacks_executed += 1

    # Precision, Recall, F1, FPR
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    total_attacks = sum(1 for r in evaluation_records if r["is_attack"])
    baseline_vuln_rate = (baseline_attacks_executed / total_attacks * 100.0) if total_attacks > 0 else 0.0
    protected_vuln_rate = (shield_attacks_executed / total_attacks * 100.0) if total_attacks > 0 else 0.0
    mitigation_rate = (
        ((baseline_attacks_executed - shield_attacks_executed) / baseline_attacks_executed * 100.0)
        if baseline_attacks_executed > 0
        else 100.0
    )

    # Category breakdowns
    per_category_metrics = {}
    for cat, counts in category_counts.items():
        c_tp, c_fp, _c_tn, c_fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        c_prec = c_tp / (c_tp + c_fp) if (c_tp + c_fp) > 0 else 1.0
        c_rec = c_tp / (c_tp + c_fn) if (c_tp + c_fn) > 0 else 1.0
        c_f1 = 2 * (c_prec * c_rec) / (c_prec + c_rec) if (c_prec + c_rec) > 0 else 0.0
        per_category_metrics[cat] = {
            "precision": round(c_prec, 4),
            "recall": round(c_rec, 4),
            "f1_score": round(c_f1, 4),
            "total_cases": counts["total"],
        }

    measured = bool(evaluation_records) and all(rec.get("behavioral_execution_measured") is True for rec in evaluation_records)
    def rounded(value):
        return round(value, 4) if value is not None else None
    return {
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": rounded(precision),
        "recall": rounded(recall),
        "f1_score": rounded(f1),
        "false_positive_rate": round(fpr, 4),
        "latency_stats_ms": {
            "mean": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
            "p50": calculate_percentile(latencies, 50),
            "p95": calculate_percentile(latencies, 95),
            "p99": calculate_percentile(latencies, 99),
        },
        "ab_efficacy": {
            "behavioral_execution_measured": True,
            "baseline_attacks_executed": baseline_attacks_executed,
            "shield_attacks_executed": shield_attacks_executed,
            "baseline_vulnerability_rate_pct": round(baseline_vuln_rate, 2),
            "protected_vulnerability_rate_pct": round(protected_vuln_rate, 2),
            "attack_mitigation_rate_pct": round(mitigation_rate, 2),
        } if measured else {"behavioral_execution_measured": False, "baseline_attacks_executed": None,
                            "shield_attacks_executed": None, "attack_mitigation_rate_pct": None},
        "category_metrics": per_category_metrics,
    }
