"""Run the Phase 5 DEVELOPMENT detector matrix and bounded smoke timings.

Only ``cases/development_cases.json`` and the immutable pre-hardening baseline
are read. This runner deliberately has no held-out or benchmark dataset path.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer.rule_detector import RuleBasedDetector  # noqa: E402
from gateway.input_normalizer import normalize_input  # noqa: E402


CASE_PATH = ROOT / "experiments" / "detector_hardening" / "cases" / "development_cases.json"
BASELINE_PATH = ROOT / "experiments" / "detector_hardening" / "results" / "pre_hardening_baseline.json"
OUTPUT_PATH = ROOT / "experiments" / "detector_hardening" / "results" / "development_matrix.json"


def main() -> None:
    cases = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    before = {item["case_id"]: item for item in baseline["records"]}
    matrix = []
    timings_ms = []
    for case in cases:
        started = time.perf_counter()
        normalized = normalize_input(case["text"])
        detected = RuleBasedDetector.scan(normalized["metadata"]["representations"])
        timings_ms.append((time.perf_counter() - started) * 1000.0)
        matching = [
            finding
            for finding in detected["findings"]
            if finding["rule_id"].startswith(case.get("expected_rule_prefix", "\0"))
        ]
        matrix.append(
            {
                "case_id": case["case_id"],
                "attack_family": case["attack_family"],
                "transformation": case["transformation"],
                "kind": case["kind"],
                "expected_finding": case.get("expected_rule_prefix"),
                "actual_finding": bool(matching),
                "rule_id": matching[0]["rule_id"] if matching else None,
                "representation_id": matching[0]["representation_id"] if matching else None,
                "provenance": matching[0]["provenance"] if matching else [],
                "all_flags": detected["flags"],
                "before_flags": before.get(case["case_id"], {}).get("flags", []),
                "pass": bool(matching) if case["kind"] == "malicious" else not detected["flags"],
            }
        )

    malicious = [item for item in matrix if item["kind"] == "malicious"]
    benign = [item for item in matrix if item["kind"] == "benign"]
    before_malicious = sum(bool(before.get(item["case_id"], {}).get("flags")) for item in malicious)
    after_malicious = sum(item["actual_finding"] for item in malicious)
    benign_findings = sum(bool(item["all_flags"]) for item in benign)
    payload = {
        "artifact": "Phase 5 development detector hardening matrix",
        "label": "DEVELOPMENT HARDENING RESULTS - NOT FINAL TEST PERFORMANCE",
        "held_out_loaded": False,
        "benchmark_loaded": False,
        "source_cases": str(CASE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "pre_hardening_baseline": str(BASELINE_PATH.relative_to(ROOT)).replace("\\", "/"),
        "summary": {
            "total_cases": len(matrix),
            "malicious_cases": len(malicious),
            "benign_cases": len(benign),
            "malicious_detected_before": before_malicious,
            "malicious_detected_after": after_malicious,
            "malicious_missed_after": len(malicious) - after_malicious,
            "benign_cases_with_findings": benign_findings,
            "mean_normalization_detection_ms": round(statistics.mean(timings_ms), 3),
            "max_normalization_detection_ms": round(max(timings_ms), 3),
        },
        "matrix": matrix,
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    main()
