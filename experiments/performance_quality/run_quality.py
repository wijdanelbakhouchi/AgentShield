"""Create blinded A/B quality-evaluation packets without fallback evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .config import QUALITY_DATASET, QUALITY_RUBRIC, RAW_DIR, SYSTEM_FREEZE, load_json
from .runtime import git_sha, provider_status, sha256_file


def blinded_order(task_id: str, *, seed: int) -> tuple[str, str]:
    """Return a reproducible A/B assignment independent of evaluator judgment."""

    digest = hashlib.sha256(f"{seed}|{task_id}".encode("utf-8")).digest()
    return ("BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD") if digest[0] % 2 == 0 else ("FULL_AGENTSHIELD", "BASELINE_NO_AGENTSHIELD")


def _assert_frozen() -> tuple[dict, list[dict], dict]:
    if not SYSTEM_FREEZE.exists():
        raise RuntimeError("Run experiments.performance_quality.freeze_system before quality packets")
    freeze = load_json(SYSTEM_FREEZE)
    if freeze.get("quality_dataset", {}).get("sha256") != sha256_file(QUALITY_DATASET):
        raise RuntimeError("Quality dataset changed after the Phase 16 freeze")
    if freeze.get("quality_rubric", {}).get("sha256") != sha256_file(QUALITY_RUBRIC):
        raise RuntimeError("Quality rubric changed after the Phase 16 freeze")
    tasks = load_json(QUALITY_DATASET)
    rubric = load_json(QUALITY_RUBRIC)
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("Quality dataset must be a non-empty array")
    if not isinstance(rubric, dict) or rubric.get("method") != "human_blinded_ab_comparison":
        raise ValueError("Quality rubric must declare the blinded human method")
    return freeze, tasks, rubric


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-number", type=int, default=1)
    args = parser.parse_args()
    if args.run_number < 1:
        parser.error("--run-number must be positive")
    freeze, tasks, rubric = _assert_frozen()
    provider = provider_status()
    real_provider = bool(provider.get("real_llm"))
    seed = int(freeze.get("seed", 20250916))
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for task in tasks:
        task_id = str(task["task_id"])
        order = blinded_order(task_id, seed=seed)
        for config in ("BASELINE_NO_AGENTSHIELD", "FULL_AGENTSHIELD"):
            rows.append(
                {
                    "sample_id": task_id,
                    "configuration": config,
                    "response_id": None,
                    "provider": provider.get("provider", "none") if real_provider else "none",
                    "model": provider.get("model") if real_provider else None,
                    "real_llm": real_provider,
                    "run_number": args.run_number,
                    "blind_label": "A" if order[0] == config else "B",
                    "display_order": ["A", "B"],
                    "order_seed": seed,
                    "order_pair": list(order),
                    "task_success": None,
                    "relevance": None,
                    "completeness": None,
                    "factuality": None,
                    "helpfulness": None,
                    "judge_metadata": {
                        "method": rubric["method"],
                        "rubric_version": rubric["version"],
                        "evaluator_blinded": True,
                        "judge_provider": None,
                        "judge_model": None,
                        "temperature": rubric.get("judge_temperature"),
                        "prompt_version": rubric.get("prompt_version"),
                    },
                    "notes": "No score or response is assigned until a human evaluates non-fallback provider output." if not real_provider else "Awaiting blinded human evaluation.",
                    "errors": "no_runtime_verified_real_provider" if not real_provider else None,
                    "evaluation_status": "PENDING_REAL_PROVIDER" if not real_provider else "PENDING_HUMAN_EVALUATION",
                    "fallback_excluded": not real_provider,
                }
            )
    manifest = {
        "schema_version": "phase16-quality-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(Path(__file__).resolve().parents[2]),
        "quality_dataset": {"path": str(QUALITY_DATASET.relative_to(Path(__file__).resolve().parents[2])), "sha256": sha256_file(QUALITY_DATASET), "task_count": len(tasks)},
        "rubric": {"path": str(QUALITY_RUBRIC.relative_to(Path(__file__).resolve().parents[2])), "sha256": sha256_file(QUALITY_RUBRIC), "version": rubric["version"]},
        "provider": provider,
        "real_llm": real_provider,
        "seed": seed,
        "run_number": args.run_number,
        "blinded": True,
        "fallback_excluded": True,
        "score_status": "PENDING" if not real_provider else "PENDING_HUMAN_EVALUATION",
        "raw_record_count": len(rows),
    }
    path = RAW_DIR / "quality_results.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    (RAW_DIR / "quality_run_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

