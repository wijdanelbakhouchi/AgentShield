"""Probe multilingual semantic behavior without changing calibration."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer.semantic_similarity import SemanticSimilarityDetector  # noqa: E402


INPUT = ROOT / "experiments" / "semantic_similarity" / "multilingual_cases.json"
OUTPUT = ROOT / "experiments" / "semantic_similarity" / "multilingual_results.json"


def main() -> None:
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    detector = SemanticSimilarityDetector(threshold=0.51)
    rows = []
    for case in data["cases"]:
        result = detector.detect(case["text"])
        top = result.get("top_match") or {}
        rows.append(
            {
                "id": case["id"],
                "language": case["language"],
                "label": case["label"],
                "score": round(float(top.get("similarity", 0.0)), 6),
                "flagged_at_calibrated_threshold": bool(result.get("flagged", False)),
                "top_category": top.get("category"),
            }
        )
    output = {
        "dataset_version": data["dataset_version"],
        "purpose": data["provenance"],
        "english_focused_model": True,
        "model_status": detector.status(),
        "results": rows,
        "interpretation": "Scores are a development probe only. Non-English misses are expected risk for this English-focused model and require a multilingual model/evaluation before claiming coverage.",
    }
    OUTPUT.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
