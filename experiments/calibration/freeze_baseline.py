"""Freeze the Phase 3 uncalibrated baseline on the calibration role only.

This command must be run before changing scoring weights or thresholds.  The
result is retained as historical calibration evidence and is never overwritten
by the Phase 4 runner.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer import llm_classifier  # noqa: E402
from config import (  # noqa: E402
    POLICY_BLOCK_THRESHOLD,
    RISK_HIGH_MAX,
    RISK_LOW_MAX,
    RISK_MEDIUM_MAX,
)
from experiments.calibration.dataset import build_splits, write_split_artifacts  # noqa: E402
from security.pipeline import SecurityPipeline  # noqa: E402


SOURCE_DATASET = ROOT / "tests" / "benchmark_dataset.json"
SPLIT_DIR = ROOT / "experiments" / "calibration" / "datasets"
BASELINE_DIR = ROOT / "experiments" / "calibration" / "baseline"
BASELINE_ROWS = BASELINE_DIR / "phase3_uncalibrated_predictions.jsonl"
BASELINE_METADATA = BASELINE_DIR / "phase3_uncalibrated_metadata.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if BASELINE_ROWS.exists() or BASELINE_METADATA.exists():
        raise RuntimeError(
            "The Phase 3 baseline is immutable; remove nothing and do not overwrite it."
        )
    calibration, held_out, split_metadata = build_splits(SOURCE_DATASET)
    if not (SPLIT_DIR / "calibration.json").exists():
        write_split_artifacts(calibration, held_out, split_metadata, SPLIT_DIR)

    # The Phase 3 local environment has no configured provider.  Explicitly
    # force the deterministic fallback here so freezing never makes network
    # calls or records a secret-bearing provider response.
    original_get_llm = llm_classifier.get_llm
    llm_classifier.get_llm = lambda: None
    try:
        rows = []
        for item in calibration:
            result = SecurityPipeline.evaluate(
                item["prompt"],
                source="phase3-baseline-calibration",
                target="calibration",
                context_text=item.get("context"),
            )
            rows.append(
                {
                    "sample_id": item["id"],
                    "group_id": item["group_id"],
                    "true_label": int(bool(item["is_attack"])),
                    "category": item["category"],
                    "prompt": item["prompt"],
                    "context": item.get("context"),
                    "rule_flags": result.analysis.rule_flags,
                    "context_flags": result.analysis.context_flags,
                    "llm_classification": result.analysis.llm_classification,
                    "baseline_component_scores": {
                        "rule": min(1.0, len(result.analysis.rule_flags) * 0.5),
                        "classifier": (
                            float(result.analysis.llm_classification.get("confidence", 0.0))
                            if result.analysis.llm_classification.get("is_malicious", False)
                            else 0.0
                        ),
                        "context": min(1.0, len(result.analysis.context_flags) * 0.5),
                    },
                    "risk_score": result.risk.score,
                    "risk_level": result.risk.level.value,
                    "policy_decision": result.policy.action.value,
                    "detected": bool(
                        result.analysis.rule_flags
                        or result.analysis.context_flags
                        or result.analysis.llm_classification.get("is_malicious", False)
                    ),
                }
            )
    finally:
        llm_classifier.get_llm = original_get_llm

    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    with BASELINE_ROWS.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    metadata = {
        "artifact": "PHASE 3 UNCALIBRATED BASELINE",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": "c2f0744d6797aaa355aded6b73dbede82ccfa28f",
        "python_version": platform.python_version(),
        "source_dataset": str(SOURCE_DATASET.relative_to(ROOT).as_posix()),
        "source_sha256": _sha256(SOURCE_DATASET),
        "calibration_dataset_sha256": _sha256(SPLIT_DIR / "calibration.json"),
        "sample_count": len(rows),
        "weights": {"rule": 0.40, "classifier": 0.40, "context": 0.20},
        "policy_flag_override": True,
        "thresholds": {
            "policy_block": POLICY_BLOCK_THRESHOLD,
            "risk_low_max": RISK_LOW_MAX,
            "risk_medium_max": RISK_MEDIUM_MAX,
            "risk_high_max": RISK_HIGH_MAX,
        },
        "llm": "deterministic heuristic fallback; optional external classifier not evaluated",
        "split_metadata": split_metadata,
        "rows_sha256": _sha256(BASELINE_ROWS),
    }
    BASELINE_METADATA.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Frozen {len(rows)} Phase 3 baseline rows at {BASELINE_ROWS}")


if __name__ == "__main__":
    main()
