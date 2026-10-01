"""Run the propagation-study evaluation matrix.

Usage::

    python -m experiments.propagation.run_evaluation --all
    python -m experiments.propagation.run_evaluation --config full_provenance

The runner evaluates every benchmark row (dev + held-out test) under each
configuration, persists raw JSONL records and processed metric summaries, and
prints the security/propagation metric tables.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import CONFIG_NAMES, ROOT, load_all_configs, load_config
from .metrics import calculate_metrics, mcnemar, uncertainty
from .workflow import evaluate_sample

RAW_DIR = ROOT / "raw_results"
PROCESSED_DIR = ROOT / "processed_results"
DATASET_DIR = ROOT / "datasets"
MANIFEST_PATH = DATASET_DIR / "benchmark_v2.manifest.json"

DEFAULT_RUN_ID = "propagation-1"


def load_rows(split: str = "all") -> list[dict[str, Any]]:
    path = DATASET_DIR / f"benchmark_v2_{split}.json"
    if not path.exists():
        raise FileNotFoundError(f"Benchmark split missing: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def run_config(
    config,
    rows: list[dict[str, Any]],
    *,
    run_id: str = DEFAULT_RUN_ID,
    bootstrap_replicates: int = 1000,
) -> dict[str, Any]:
    records = [evaluate_sample(row, config, run_id=run_id) for row in rows]
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    raw_path = RAW_DIR / f"{config.name}.jsonl"
    with raw_path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    result = {
        "configuration": config.as_dict(),
        "raw_results": str(raw_path.relative_to(ROOT.parent.parent)),
        "metrics": calculate_metrics(records),
        "grouped_bootstrap_95_ci": uncertainty(records, replicates=bootstrap_replicates),
        "dataset_sha256": None,
    }
    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        result["dataset_sha256"] = manifest.get("sha256_all")
    processed_path = PROCESSED_DIR / f"{config.name}.json"
    processed_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def print_table(output: dict[str, Any]) -> None:
    for name, result in output.items():
        metrics = result["metrics"]["overall"]
        propagation = result["metrics"]["propagation"]
        print(f"\n=== {name} ===")
        print(
            f"  TP={metrics.get('TP')} TN={metrics.get('TN')} FP={metrics.get('FP')} "
            f"FN={metrics.get('FN')} | precision={metrics.get('precision')} "
            f"recall={metrics.get('recall')} f1={metrics.get('f1')} "
            f"fpr={metrics.get('fpr')}"
        )
        print(
            f"  ASR={metrics.get('attack_success_rate')} "
            f"mitigation={metrics.get('mitigation_rate')} | "
            f"mean_depth={propagation.get('mean_depth')} "
            f"median_depth={propagation.get('median_depth')} "
            f"privileged_reach={propagation.get('privileged_reach_rate')}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", choices=CONFIG_NAMES, help="One config name; omit with --all")
    parser.add_argument("--all", action="store_true", help="Run every checked-in configuration")
    parser.add_argument("--split", choices=("all", "dev", "test"), default="all")
    parser.add_argument("--bootstrap-replicates", type=int, default=1000)
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    args = parser.parse_args()
    if args.config and args.all:
        parser.error("choose --config or --all")
    configs = load_all_configs() if args.all else [load_config(args.config or "full_provenance")]
    rows = load_rows(args.split)
    run_manifest = {
        "run_id": args.run_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "split": args.split,
        "dataset": args.split,
        "provider": "deterministic-detector-only",
        "model": None,
        "seed": 20260907,
        "repeats": 1,
        "configurations": [config.name for config in configs],
        "semantic_model": "sentence-transformers/all-MiniLM-L6-v2",
        "llm_classifier_note": (
            "LLM classifier excluded; calibrated weight is 0.00 so scores are unchanged."
        ),
        "propagation_model_note": (
            "Deterministic reachability model: an agent that receives payload-bearing "
            "content reproduces it verbatim in its output. Measures the defense "
            "envelope, not LLM compliance."
        ),
    }
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / "run_manifest.json").write_text(json.dumps(run_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output = {
        config.name: run_config(
            config, rows, run_id=args.run_id, bootstrap_replicates=args.bootstrap_replicates
        )
        for config in configs
    }

    # Paired comparisons between key configurations.
    by_id = {}
    for name, result in output.items():
        path = Path(result["raw_results"])
        with path.open("r", encoding="utf-8") as handle:
            by_id[name] = [json.loads(line) for line in handle if line.strip()]

    pairs = {
        "baseline_vs_full_no_provenance": mcnemar(by_id["BASELINE_NO_AGENTSHIELD"], by_id["FULL_NO_PROVENANCE"]),
        "full_no_provenance_vs_full_provenance": mcnemar(by_id["FULL_NO_PROVENANCE"], by_id["FULL_PROVENANCE"]),
        "gateway_only_vs_full_no_provenance": mcnemar(by_id["GATEWAY_ONLY"], by_id["FULL_NO_PROVENANCE"]),
        "full_no_provenance_vs_full_banded_sanitize": mcnemar(by_id["FULL_NO_PROVENANCE"], by_id["FULL_BANDED_SANITIZE"]),
    }
    (PROCESSED_DIR / "_paired.json").write_text(
        json.dumps(pairs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"run_manifest": run_manifest, "configurations": output, "paired_mcnemar": pairs}, indent=2, sort_keys=True))
    print_table(output)
    print("\n=== Paired McNemar (attack success) ===")
    for name, test in pairs.items():
        print(f"  {name}: p={test.get('p_value')} (samples={test.get('paired_samples')})")


if __name__ == "__main__":
    main()