"""Freeze a development-only detector baseline before Phase 5 edits.

This script intentionally reads only ``cases/development_cases.json``.  It
must never load the protected Phase 4 held-out dataset or historical benchmark.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer.rule_detector import RuleBasedDetector  # noqa: E402
from gateway.input_normalizer import normalize_input  # noqa: E402


CASES = ROOT / "experiments" / "detector_hardening" / "cases" / "development_cases.json"
OUTPUT = ROOT / "experiments" / "detector_hardening" / "results" / "pre_hardening_baseline.json"


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:
        return "unknown"


def main() -> None:
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    records = []
    for case in cases:
        normalized = normalize_input(case["text"])
        detection = RuleBasedDetector.scan(normalized["augmented_eval_prompt"])
        records.append(
            {
                "case_id": case["case_id"],
                "kind": case["kind"],
                "attack_family": case["attack_family"],
                "transformation": case["transformation"],
                "expected_rule_prefix": case.get("expected_rule_prefix"),
                "flags": detection.get("flags", []),
                "categories": detection.get("categories", {}),
                "normalized_input": normalized["normalized_input"],
                "metadata": normalized.get("metadata", {}),
            }
        )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(
            {
                "artifact": "Phase 5 development detector baseline",
                "label": "DEVELOPMENT HARDENING BASELINE - NOT FINAL TEST PERFORMANCE",
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "git_commit": _git_commit(),
                "source_cases": str(CASES.relative_to(ROOT)).replace("\\", "/"),
                "held_out_loaded": False,
                "benchmark_loaded": False,
                "records": records,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
