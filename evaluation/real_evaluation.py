from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median
from time import perf_counter
from typing import Any

from app.graph.workflow import ProtectedWorkflow
from app.models.schemas import AgentMessage, Decision
from app.security.gateway import SecurityGateway


ATTACK_DECISIONS = {Decision.WARN.value, Decision.SANITIZE.value, Decision.BLOCK.value}


def run_security_evaluation(dataset_path: Path) -> dict[str, Any]:
    gateway = SecurityGateway()
    cases = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []

    confusion = Counter({"tp": 0, "tn": 0, "fp": 0, "fn": 0})
    latency_values: list[float] = []
    by_attack_type: dict[str, Counter] = defaultdict(Counter)

    for case in cases:
        message = AgentMessage(
            content=case["content"],
            source=case.get("source", "user"),
            target=case.get("target", "agent"),
            channel=case.get("channel", "chat"),
            metadata=case.get("metadata", {}),
        )

        started = perf_counter()
        result = gateway.inspect(message)
        wall_latency_ms = (perf_counter() - started) * 1000
        latency_values.append(wall_latency_ms)

        expected_attack = case["label"] == "attack"
        predicted_attack = result.decision.value in ATTACK_DECISIONS
        expected_decision = case["expected_decision"]
        policy_correct = result.decision.value == expected_decision

        if expected_attack and predicted_attack:
            confusion["tp"] += 1
        elif not expected_attack and not predicted_attack:
            confusion["tn"] += 1
        elif not expected_attack and predicted_attack:
            confusion["fp"] += 1
        elif expected_attack and not predicted_attack:
            confusion["fn"] += 1

        attack_type = case.get("attack_type", "benign")
        by_attack_type[attack_type]["total"] += 1
        by_attack_type[attack_type]["detected"] += int(predicted_attack == expected_attack)
        by_attack_type[attack_type]["policy_correct"] += int(policy_correct)

        rows.append(
            {
                "name": case["name"],
                "label": case["label"],
                "attack_type": attack_type,
                "expected_decision": expected_decision,
                "actual_decision": result.decision.value,
                "risk_score": result.risk_score,
                "risk_level": result.risk_level.value,
                "predicted_attack": predicted_attack,
                "policy_correct": policy_correct,
                "signals": [signal.model_dump() for signal in result.signals],
                "latency_ms": round(wall_latency_ms, 3),
            }
        )

    metrics = compute_metrics(confusion, rows, latency_values)
    metrics["by_attack_type"] = {
        attack_type: {
            "total": values["total"],
            "detection_accuracy": safe_div(values["detected"], values["total"]),
            "policy_accuracy": safe_div(values["policy_correct"], values["total"]),
        }
        for attack_type, values in sorted(by_attack_type.items())
    }

    return {
        "dataset": str(dataset_path),
        "total_cases": len(cases),
        "metrics": metrics,
        "confusion_matrix": dict(confusion),
        "results": rows,
    }


def run_workflow_security_evaluation(dataset_path: Path) -> dict[str, Any]:
    workflow = ProtectedWorkflow()
    cases = json.loads(dataset_path.read_text(encoding="utf-8"))
    rows = []
    attack_cases = [case for case in cases if case["label"] == "attack"]

    blocked = 0
    mitigated = 0
    for case in attack_cases:
        result = workflow.run(case["content"])
        first_decision = result.steps[0].security.decision.value if result.steps else "none"
        blocked += int(result.blocked)
        mitigated += int(first_decision in ATTACK_DECISIONS)
        rows.append(
            {
                "name": case["name"],
                "attack_type": case.get("attack_type", "unknown"),
                "blocked_before_final_answer": result.blocked,
                "mitigated_by_gateway": first_decision in ATTACK_DECISIONS,
                "steps_executed": len(result.steps),
                "first_decision": first_decision,
            }
        )

    return {
        "total_attack_workflows": len(attack_cases),
        "blocked_workflows": blocked,
        "mitigated_workflows": mitigated,
        "workflow_block_rate": safe_div(blocked, len(attack_cases)),
        "workflow_mitigation_rate": safe_div(mitigated, len(attack_cases)),
        "results": rows,
    }


def compute_metrics(confusion: Counter, rows: list[dict[str, Any]], latency_values: list[float]) -> dict[str, Any]:
    tp = confusion["tp"]
    tn = confusion["tn"]
    fp = confusion["fp"]
    fn = confusion["fn"]
    total = tp + tn + fp + fn
    policy_correct = sum(1 for row in rows if row["policy_correct"])

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        "detection_accuracy": safe_div(tp + tn, total),
        "policy_accuracy": safe_div(policy_correct, total),
        "precision": precision,
        "recall": recall,
        "f1_score": safe_div(2 * precision * recall, precision + recall),
        "false_positive_rate": safe_div(fp, fp + tn),
        "false_negative_rate": safe_div(fn, fn + tp),
        "average_latency_ms": round(mean(latency_values), 3) if latency_values else 0.0,
        "median_latency_ms": round(median(latency_values), 3) if latency_values else 0.0,
        "p95_latency_ms": round(percentile(latency_values, 95), 3) if latency_values else 0.0,
    }


def percentile(values: list[float], percent: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((percent / 100) * (len(ordered) - 1)))
    return ordered[index]


def safe_div(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def print_report(report: dict[str, Any]) -> None:
    metrics = report["security"]["metrics"]
    confusion = report["security"]["confusion_matrix"]

    print("\nAgentShield Real Evaluation")
    print("=" * 80)
    print(f"Detection accuracy : {metrics['detection_accuracy']:.2%}")
    print(f"Policy accuracy    : {metrics['policy_accuracy']:.2%}")
    print(f"Precision          : {metrics['precision']:.2%}")
    print(f"Recall             : {metrics['recall']:.2%}")
    print(f"F1 score           : {metrics['f1_score']:.2%}")
    print(f"False positives    : {confusion['fp']}")
    print(f"False negatives    : {confusion['fn']}")
    print(f"Avg latency        : {metrics['average_latency_ms']} ms")
    print(f"P95 latency        : {metrics['p95_latency_ms']} ms")
    print(f"Workflow block rate: {report['workflow']['workflow_block_rate']:.2%}")
    print(f"Workflow mitigation: {report['workflow']['workflow_mitigation_rate']:.2%}")

    print("\nPer-case Results")
    print("-" * 80)
    for row in report["security"]["results"]:
        status = "OK" if row["policy_correct"] else "MISS"
        print(
            f"{status:4} {row['name']:<34} label={row['label']:<6} "
            f"expected={row['expected_decision']:<8} actual={row['actual_decision']:<8} "
            f"score={row['risk_score']:.3f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real AgentShield security evaluation.")
    parser.add_argument("--dataset", default="real_benchmark.json", help="Path to labeled benchmark JSON.")
    parser.add_argument("--output", default="reports/real_evaluation_report.json", help="Output report path.")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    report = {
        "security": run_security_evaluation(dataset_path),
        "workflow": run_workflow_security_evaluation(dataset_path),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")

    print_report(report)
    print(f"\nSaved report: {output_path}")


if __name__ == "__main__":
    main()
