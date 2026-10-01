"""Run the frozen deterministic Phase 15 evaluation matrix."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any

from .config import CONFIG_NAMES, ROOT, ExperimentConfig, load_all_configs, load_config
from .metrics import calculate_metrics, uncertainty
from .validate_dataset import DATASET_PATH, MANIFEST_PATH, validate_dataset
from .workflow import evaluate_sample


RAW_DIR = ROOT / "raw_results"
PROCESSED_DIR = ROOT / "processed_results"
FREEZE_PATH = ROOT / "datasets" / "system_freeze.json"


def _load_rows() -> list[dict[str, Any]]:
    with DATASET_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _assert_frozen() -> dict[str, Any]:
    summary = validate_dataset(DATASET_PATH)
    if not MANIFEST_PATH.exists() or not FREEZE_PATH.exists():
        raise RuntimeError("Final evaluation requires a frozen dataset and system freeze record")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    freeze = json.loads(FREEZE_PATH.read_text(encoding="utf-8"))
    if not manifest.get("frozen") or manifest.get("sha256") != summary["sha256"]:
        raise RuntimeError("Final dataset hash does not match its frozen manifest")
    if freeze.get("dataset", {}).get("sha256") != summary["sha256"] or not freeze.get("final_test_read_only"):
        raise RuntimeError("System freeze is stale or does not assert final-test read-only behavior")
    return freeze


def run_config(config: ExperimentConfig, rows: list[dict[str, Any]], *, repeats: int = 1, bootstrap_replicates: int = 1000) -> dict[str, Any]:
    if repeats < 1:
        raise ValueError("repeats must be positive")
    if repeats != 1:
        raise ValueError("Deterministic detector-only evaluation requires exactly one repeat")
    records = [evaluate_sample(row, config, run_id="deterministic-1") for row in rows]
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
    }
    processed_path = PROCESSED_DIR / f"{config.name}.json"
    processed_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", choices=CONFIG_NAMES, help="One config name; omit with --all")
    parser.add_argument("--all", action="store_true", help="Run every checked-in configuration")
    parser.add_argument("--bootstrap-replicates", type=int, default=1000)
    args = parser.parse_args()
    if args.config and args.all:
        parser.error("choose --config or --all")
    freeze = _assert_frozen()
    configs = load_all_configs() if args.all else [load_config(args.config or "full")]
    rows = _load_rows()
    run_manifest = {
        "run_id": "deterministic-1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "dataset": freeze["dataset"],
        "provider": "deterministic-detector-only",
        "model": None,
        "temperature": None,
        "seed": 20250915,
        "repeats": 1,
        "configurations": [config.name for config in configs],
        "final_test_read_only": True,
    }
    (RAW_DIR).mkdir(parents=True, exist_ok=True)
    (RAW_DIR / "run_manifest.json").write_text(json.dumps(run_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output = {config.name: run_config(config, rows, bootstrap_replicates=args.bootstrap_replicates) for config in configs}
    print(json.dumps({"run_manifest": run_manifest, "configurations": output}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
