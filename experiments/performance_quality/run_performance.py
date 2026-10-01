"""Collect raw, paired full-request performance records for Phase 16."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from config import (
    CLASSIFIER_WEIGHT,
    CONTEXT_WEIGHT,
    POLICY_BLOCK_THRESHOLD,
    RULE_WEIGHT,
    SEMANTIC_MODEL_NAME,
    SEMANTIC_MODEL_REVISION,
    SEMANTIC_SIMILARITY_ENABLED,
    SEMANTIC_SIMILARITY_THRESHOLD,
    SIMILARITY_WEIGHT,
)

from .config import PERFORMANCE_DATASET, RAW_DIR, SYSTEM_FREEZE, load_all_configs, load_json
from .runtime import git_sha, provider_status, sha256_file
from .workflow import initialize_sandbox, run_request


def _assert_frozen() -> dict:
    if not SYSTEM_FREEZE.exists():
        raise RuntimeError("Run experiments.performance_quality.freeze_system before measurement")
    freeze = load_json(SYSTEM_FREEZE)
    if not freeze.get("final_test_read_only"):
        raise RuntimeError("Phase 16 freeze does not assert read-only evaluation")
    phase15_root = Path(__file__).resolve().parent.parent / "final_evaluation" / "datasets"
    if freeze.get("phase15", {}).get("dataset_sha256") != load_json(
        phase15_root / "final_corpus_v1.manifest.json"
    ).get("sha256"):
        raise RuntimeError("Phase 15 frozen dataset identity changed")
    if freeze.get("phase15", {}).get("dataset_file_sha256") != sha256_file(phase15_root / "final_corpus_v1.json"):
        raise RuntimeError("Phase 15 dataset file changed after the Phase 16 freeze")
    if freeze.get("performance_dataset", {}).get("sha256") != sha256_file(PERFORMANCE_DATASET):
        raise RuntimeError("Performance workload changed after the Phase 16 freeze")
    expected = freeze.get("security_configuration", {})
    current_weights = {
        "rule": RULE_WEIGHT,
        "semantic_similarity": SIMILARITY_WEIGHT,
        "classifier": CLASSIFIER_WEIGHT,
        "context": CONTEXT_WEIGHT,
    }
    current_semantic = {
        "name": SEMANTIC_MODEL_NAME,
        "revision": SEMANTIC_MODEL_REVISION,
        "threshold": SEMANTIC_SIMILARITY_THRESHOLD,
        "enabled": SEMANTIC_SIMILARITY_ENABLED,
    }
    if expected.get("weights") != current_weights or expected.get("policy_block_threshold") != POLICY_BLOCK_THRESHOLD or expected.get("semantic_model") != current_semantic:
        raise RuntimeError("Security configuration differs from the Phase 16 freeze")
    return freeze


def _load_workload() -> list[dict]:
    rows = load_json(PERFORMANCE_DATASET)
    if not isinstance(rows, list) or not rows:
        raise ValueError("Performance workload must be a non-empty array")
    ids = [str(row.get("sample_id", "")) for row in rows]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("Performance workload sample_id values must be unique and non-empty")
    texts = [" ".join(str(row.get("text", "")).casefold().split()) for row in rows]
    if any(not text for text in texts) or len(texts) != len(set(texts)):
        raise ValueError("Performance workload contains an empty or duplicate text")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=25)
    parser.add_argument("--warmup", type=int, default=2)
    args = parser.parse_args()
    if args.repetitions < 1 or args.warmup < 0:
        parser.error("--repetitions must be positive and --warmup cannot be negative")

    freeze = _assert_frozen()
    workload = _load_workload()
    configs = load_all_configs()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    provider = provider_status()
    semantic = freeze.get("semantic_runtime", {})
    semantic_ready = bool(semantic.get("ready"))

    with tempfile.TemporaryDirectory(prefix="agentshield-phase16-") as temporary:
        sandbox_db = Path(temporary) / "sandbox.sqlite3"
        cold_start_ms = initialize_sandbox(sandbox_db)
        # Warmup calls are intentionally excluded from steady-state raw rows.
        for config in configs:
            for warmup_number in range(1, args.warmup + 1):
                for sample in workload:
                    run_request(
                        sample,
                        config,
                        run_number=warmup_number,
                        semantic_ready=semantic_ready,
                        sandbox_db=sandbox_db,
                        measurement_phase="warmup",
                        persist=False,
                    )

        config_files: dict[str, str] = {}
        total_records = 0
        for config in configs:
            path = RAW_DIR / f"{config.name}.jsonl"
            config_files[config.name] = str(path)
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                for run_number in range(1, args.repetitions + 1):
                    for sample in workload:
                        record = run_request(
                            sample,
                            config,
                            run_number=run_number,
                            semantic_ready=semantic_ready,
                            sandbox_db=sandbox_db,
                        )
                        handle.write(json.dumps(record, sort_keys=True) + "\n")
                        total_records += 1

    manifest = {
        "schema_version": "phase16-performance-v1",
        "run_started_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(Path(__file__).resolve().parents[2]),
        "dataset": {
            "path": str(PERFORMANCE_DATASET.relative_to(Path(__file__).resolve().parents[2])),
            "sha256": sha256_file(PERFORMANCE_DATASET),
            "sample_count": len(workload),
        },
        "configurations": [config.name for config in configs],
        "configuration_hash": freeze.get("configuration_hash"),
        "provider": provider.get("provider", "none"),
        "model": provider.get("model"),
        "real_llm": bool(provider.get("real_llm")),
        "semantic_status": semantic.get("classification", "SEMANTIC_UNAVAILABLE"),
        "semantic_probe": semantic,
        "warmup_requests_per_configuration": args.warmup * len(workload),
        "steady_state_repetitions_per_sample": args.repetitions,
        "steady_state_records_per_configuration": args.repetitions * len(workload),
        "cold_start_ms": cold_start_ms,
        "seed": freeze.get("seed", 20250916),
        "safe_sandbox": True,
        "raw_files": config_files,
        "total_records": total_records,
        "final_test_read_only": True,
    }
    (RAW_DIR / "performance_run_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
