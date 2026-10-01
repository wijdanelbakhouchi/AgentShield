"""Compute blinded quality summaries from raw evaluator records."""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROCESSED_DIR, QUALITY_DATASET, QUALITY_RUBRIC, RAW_DIR, SYSTEM_FREEZE, load_json
from .runtime import git_sha, sha256_file


DIMENSIONS = ("task_success", "relevance", "completeness", "factuality", "helpfulness")


def read_quality_records(path: Path | None = None) -> list[dict[str, Any]]:
    source = path or (RAW_DIR / "quality_results.jsonl")
    if not source.exists():
        raise FileNotFoundError(source)
    records: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            required = {"sample_id", "configuration", "provider", "model", "real_llm", "run_number", *DIMENSIONS}
            if not isinstance(row, dict) or not required.issubset(row):
                raise ValueError(f"Invalid quality row at {source}:{line_number}")
            if any(row[dimension] is not None and not isinstance(row[dimension], (int, float, bool)) for dimension in DIMENSIONS):
                raise ValueError(f"Invalid quality score at {source}:{line_number}")
            if not isinstance(row["real_llm"], bool):
                raise ValueError(f"real_llm must be boolean at {source}:{line_number}")
            records.append(row)
    if not records:
        raise ValueError("Quality result file is empty")
    return records


def _dimension_stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"n": 0, "mean": None, "std": None, "ci95": [None, None]}
    mean = statistics.fmean(values)
    # Descriptive uncertainty is intentionally conservative for tiny human sets.
    se = statistics.stdev(values) / (len(values) ** 0.5) if len(values) > 1 else 0.0
    return {"n": len(values), "mean": round(mean, 3), "std": round(statistics.stdev(values), 3) if len(values) > 1 else 0.0, "ci95": [round(mean - 1.96 * se, 3), round(mean + 1.96 * se, 3)]}


def compute_summary() -> dict[str, Any]:
    if not SYSTEM_FREEZE.exists():
        raise RuntimeError("Phase 16 runtime freeze is required before quality processing")
    records = read_quality_records()
    if sha256_file(QUALITY_DATASET) != load_json(SYSTEM_FREEZE).get("quality_dataset", {}).get("sha256"):
        raise RuntimeError("Quality dataset identity changed")
    if sha256_file(QUALITY_RUBRIC) != load_json(SYSTEM_FREEZE).get("quality_rubric", {}).get("sha256"):
        raise RuntimeError("Quality rubric identity changed")
    scored = [row for row in records if all(row.get(dimension) is not None for dimension in DIMENSIONS)]
    fallback_scored = [row for row in scored if not row.get("real_llm") or str(row.get("provider", "")).lower() in {"fallback", "demo"}]
    if fallback_scored:
        raise ValueError("Fallback/demo responses cannot receive quality scores")
    configurations = sorted({str(row["configuration"]) for row in records})
    by_config: dict[str, Any] = {}
    for configuration in configurations:
        selected = [row for row in scored if row["configuration"] == configuration]
        by_config[configuration] = {
            "status": "COMPLETE" if selected else "PENDING",
            "n": len(selected),
            "dimensions": {dimension: _dimension_stats([float(row[dimension]) for row in selected]) for dimension in DIMENSIONS},
        }
    manifest_path = RAW_DIR / "quality_run_manifest.json"
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    result = {
        "schema_version": "phase16-quality-summary-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(Path(__file__).resolve().parents[2]),
        "dataset": {"path": str(QUALITY_DATASET.relative_to(Path(__file__).resolve().parents[2])), "sha256": sha256_file(QUALITY_DATASET), "task_count": len(load_json(QUALITY_DATASET))},
        "rubric": {"path": str(QUALITY_RUBRIC.relative_to(Path(__file__).resolve().parents[2])), "sha256": sha256_file(QUALITY_RUBRIC)},
        "method": "human_blinded_ab_comparison",
        "provider": manifest.get("provider", {"provider": "none", "real_llm": False}),
        "real_llm": bool(manifest.get("real_llm", False)),
        "status": "COMPLETE" if scored else "PENDING",
        "records": len(records),
        "scored_records": len(scored),
        "configurations": by_config,
        "fallback_excluded": True,
        "raw_file": str((RAW_DIR / "quality_results.jsonl").relative_to(RAW_DIR.parent.parent)),
    }
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    (PROCESSED_DIR / "quality_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(compute_summary(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
