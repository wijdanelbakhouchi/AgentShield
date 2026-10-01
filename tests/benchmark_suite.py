"""
tests/benchmark_suite.py
========================
AgentShield Phase 5 — Automated Benchmark Runner

Executes 300+ dataset test cases across Condition A (Unprotected Baseline) and
Condition B (AgentShield Active Gateway), logging latency, actions, and vulnerability metrics.
"""

import asyncio
import argparse
import json
import os
import sys
import time
from typing import Any, Dict

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tests.eval_metrics import calculate_thesis_metrics
from security.pipeline import SecurityPipeline


async def evaluate_single_case(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates a single benchmark item across Condition A (Baseline) and Condition B (AgentShield).
    """
    prompt = item["prompt"]
    is_attack = item["is_attack"]

    # -----------------------------------------------------------------------
    # Condition A: Unprotected Baseline Agent
    # -----------------------------------------------------------------------
    baseline_action = "ALLOW"
    # This harness measures policy decisions, not model compliance or tools.
    unauthorized_tool_executed_baseline = None

    # -----------------------------------------------------------------------
    # Condition B: AgentShield Active Gateway
    # -----------------------------------------------------------------------
    t_start = time.perf_counter()

    # Canonical normalize -> analyze -> score -> policy pipeline.
    result = SecurityPipeline.evaluate(
        prompt,
        source="benchmark",
        target="benchmark_agent",
    )
    t_latency_ms = (time.perf_counter() - t_start) * 1000.0

    shield_action = result.policy.action.value
    unauthorized_tool_executed_shield = None
    return {
        "id": item["id"],
        "category": item["category"],
        "prompt": prompt,
        "is_attack": is_attack,
        "behavioral_execution_measured": False,
        "baseline_action": baseline_action,
        "shield_action": shield_action,
        "latency_ms": round(t_latency_ms, 2),
        "unauthorized_tool_executed_baseline": unauthorized_tool_executed_baseline,
        "unauthorized_tool_executed_shield": unauthorized_tool_executed_shield,
        "unified_risk_score": result.risk.score,
        "threat_level": result.risk.level.value,
    }


async def run_evaluation_suite(dataset_path: str = None, output_path: str = None) -> Dict[str, Any]:
    """
    Runs the complete 300+ test case evaluation suite asynchronously.
    """
    if not dataset_path:
        dataset_path = os.path.join(ROOT_DIR, "tests", "benchmark_dataset.json")

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"[BENCHMARK] Starting AgentShield Thesis Benchmark Evaluation on {len(dataset)} Test Cases...")

    results = []
    for idx, item in enumerate(dataset, 1):
        rec = await evaluate_single_case(item)
        results.append(rec)
        if idx % 50 == 0 or idx == len(dataset):
            print(f"  Progress: [{idx}/{len(dataset)}] test cases evaluated...")

    metrics = calculate_thesis_metrics(results)

    report_output = {
        "evidence_class": "COMPONENT_POLICY_DECISIONS",
        "limitations": "ALLOW is not observed attack success; no agents or tools are executed by this benchmark.",
        "summary": metrics,
        "evaluation_records": results,
    }

    out_json = output_path or os.path.join(ROOT_DIR, "artifacts", "component_benchmark.json")
    os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report_output, f, indent=2, ensure_ascii=False)

    print(f"\n[SUCCESS] Benchmark Suite Completed! Results exported to:\n  {out_json}")
    print("\n===========================================================================")
    print("=== AGENTSHIELD THESIS EMPIRICAL EVALUATION SUMMARY ===")
    print("===========================================================================")
    print(f" Precision           : {metrics['precision']}")
    print(f" Recall              : {metrics['recall']}")
    print(f" F1-Score            : {metrics['f1_score']}")
    print(f" False Positive Rate : {metrics['false_positive_rate'] * 100:.2f}% (Target < 2.0%)")
    print("---------------------------------------------------------------------------")
    print(" Behavioral attack/tool execution: NOT MEASURED")
    print("---------------------------------------------------------------------------")
    print(f" Gateway Overhead (P50)     : {metrics['latency_stats_ms']['p50']} ms")
    print(f" Gateway Overhead (P95)     : {metrics['latency_stats_ms']['p95']} ms")
    print(f" Gateway Overhead (P99)     : {metrics['latency_stats_ms']['p99']} ms")
    print("===========================================================================\n")

    return report_output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Component policy-decision benchmark; no behavioral ASR claims.")
    parser.add_argument("--dataset", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    asyncio.run(run_evaluation_suite(args.dataset, args.output))
