"""Derive latency distributions and paired overhead from raw JSONL only."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROCESSED_DIR, RAW_DIR, SYSTEM_FREEZE, load_json
from .runtime import git_sha, sha256_file
from .timing import paired_overhead, summarize
from .workflow import STAGES


RAW_REQUIRED = {"run_id", "run_number", "sample_id", "configuration", "timestamp", "provider", "model", "real_llm", "decision", "request_id", "total_ms"}


def read_records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict) or not RAW_REQUIRED.issubset(value):
                raise ValueError(f"Invalid performance row at {path}:{line_number}")
            if not isinstance(value["real_llm"], bool) or value["total_ms"] is None or float(value["total_ms"]) < 0:
                raise ValueError(f"Invalid total/provider metadata at {path}:{line_number}")
            for stage in STAGES:
                stage_value = value.get(stage)
                if stage_value is not None and float(stage_value) < 0:
                    raise ValueError(f"Negative {stage} at {path}:{line_number}")
            records.append(value)
    if not records:
        raise ValueError(f"No performance records in {path}")
    return records


def _stage_summary(records: list[dict[str, Any]]) -> dict[str, dict[str, float | int | None]]:
    return {stage: summarize([float(row[stage]) for row in records if row.get(stage) is not None]) for stage in STAGES}


def compute_summary() -> dict[str, Any]:
    if not SYSTEM_FREEZE.exists():
        raise RuntimeError("Phase 16 runtime freeze is required before processing")
    freeze = load_json(SYSTEM_FREEZE)
    baseline = read_records(RAW_DIR / "BASELINE_NO_AGENTSHIELD.jsonl")
    protected = read_records(RAW_DIR / "FULL_AGENTSHIELD.jsonl")
    if len(baseline) != len(protected):
        raise ValueError("Baseline and protected workloads must have equal record counts")
    baseline_config = {row["configuration"] for row in baseline}
    protected_config = {row["configuration"] for row in protected}
    if baseline_config != {"BASELINE_NO_AGENTSHIELD"} or protected_config != {"FULL_AGENTSHIELD"}:
        raise ValueError("Raw records have unexpected configuration labels")

    manifest_path = RAW_DIR / "performance_run_manifest.json"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    result = {
        "schema_version": "phase16-performance-summary-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(Path(__file__).resolve().parents[2]),
        "freeze_git_sha": freeze.get("git_sha"),
        "dataset": freeze.get("performance_dataset"),
        "configuration_hash": freeze.get("configuration_hash"),
        "semantic_runtime": freeze.get("semantic_runtime"),
        "provider_runtime": freeze.get("provider_runtime"),
        "seed": manifest.get("seed", freeze.get("seed")),
        "cold_start_ms": manifest.get("cold_start_ms"),
        "warmup_requests_per_configuration": manifest.get("warmup_requests_per_configuration"),
        "steady_state_repetitions_per_sample": manifest.get("steady_state_repetitions_per_sample"),
        "safe_sandbox": bool(manifest.get("safe_sandbox", True)),
        "baseline": {"count": len(baseline), "total": summarize([float(row["total_ms"]) for row in baseline]), "stages": _stage_summary(baseline)},
        "protected": {"count": len(protected), "total": summarize([float(row["total_ms"]) for row in protected]), "stages": _stage_summary(protected)},
        "overhead": paired_overhead(baseline, protected),
        "raw_files": {
            "baseline": {"path": str((RAW_DIR / "BASELINE_NO_AGENTSHIELD.jsonl").relative_to(RAW_DIR.parent.parent)), "sha256": sha256_file(RAW_DIR / "BASELINE_NO_AGENTSHIELD.jsonl")},
            "protected": {"path": str((RAW_DIR / "FULL_AGENTSHIELD.jsonl").relative_to(RAW_DIR.parent.parent)), "sha256": sha256_file(RAW_DIR / "FULL_AGENTSHIELD.jsonl")},
        },
        "traceability": {"raw_manifest": str(manifest_path.relative_to(RAW_DIR.parent.parent)), "metric_source": "raw JSONL; no manually entered measurements"},
    }
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    output = PROCESSED_DIR / "performance_summary.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(compute_summary(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

