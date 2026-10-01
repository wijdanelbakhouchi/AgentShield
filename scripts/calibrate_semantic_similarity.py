"""Calibrate Phase 6 similarity threshold on development data only.

This script never reads the protected held-out/final benchmark.  It writes
aggregate metrics and score distributions without copying input text into the
artifact.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer.rule_detector import RuleBasedDetector  # noqa: E402
from analyzer.semantic_similarity import SemanticSimilarityDetector  # noqa: E402
from analyzer.threat_evaluator import EMBEDDING_MATCH_THRESHOLD, LexicalSimilarityDetector  # noqa: E402
from config import SEMANTIC_SIMILARITY_THRESHOLD  # noqa: E402


DATASET_PATH = ROOT / "experiments" / "semantic_similarity" / "similarity_calibration.json"
OUTPUT_PATH = ROOT / "experiments" / "semantic_similarity" / "calibration_results.json"


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> Dict[str, Any]:
    predicted = scores >= threshold
    positive = labels == 1
    negative = ~positive
    tp = int(np.sum(predicted & positive))
    tn = int(np.sum(~predicted & negative))
    fp = int(np.sum(predicted & negative))
    fn = int(np.sum(~predicted & positive))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    f2 = 5 * precision * recall / (4 * precision + recall) if 4 * precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    balanced_accuracy = ((tp / (tp + fn) if tp + fn else 0.0) + (tn / (tn + fp) if tn + fp else 0.0)) / 2
    return {
        "threshold": round(float(threshold), 2),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "f2": round(f2, 6),
        "fpr": round(fpr, 6),
        "fnr": round(fnr, 6),
        "balanced_accuracy": round(balanced_accuracy, 6),
    }


def _best_threshold(labels: np.ndarray, scores: np.ndarray) -> Dict[str, Any]:
    grid = [_metrics(labels, scores, value) for value in np.arange(0.0, 1.001, 0.01)]
    # Security-oriented objective: maximize F1 subject to <=10% FPR. F2 and
    # neighboring scores are retained to make the trade-off auditable.
    acceptable = [item for item in grid if item["fpr"] <= 0.10]
    selected = max(acceptable or grid, key=lambda item: (item["f1"], item["balanced_accuracy"], -item["threshold"]))
    selected_threshold = selected["threshold"]
    neighbors = [item for item in grid if abs(item["threshold"] - selected_threshold) <= 0.03]
    return {
        "objective": "maximize F1 subject to FPR <= 0.10; report F2 for security-sensitive recall comparison",
        "selected": selected,
        "f2_at_selected": selected["f2"],
        "grid": grid,
        "neighbor_stability": neighbors,
    }


def _component_row(labels: np.ndarray, scores: np.ndarray, threshold: float) -> Dict[str, Any]:
    return _metrics(labels, scores, threshold)


def main() -> None:
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    cases = dataset["cases"]
    labels = np.asarray([int(item["label"]) for item in cases], dtype=np.int8)
    detector = SemanticSimilarityDetector(threshold=SEMANTIC_SIMILARITY_THRESHOLD)
    lexical = LexicalSimilarityDetector()

    semantic_scores: List[float] = []
    lexical_scores: List[float] = []
    rule_scores: List[float] = []
    score_rows: List[Dict[str, Any]] = []
    for case in cases:
        text = str(case["text"])
        semantic = detector.detect(text)
        top = semantic.get("top_match") or {}
        semantic_score = float(top.get("similarity", 0.0)) if semantic.get("semantic_similarity_enabled") else 0.0
        lexical_score, lexical_name, lexical_category = lexical.match(text)
        rule_score = 1.0 if RuleBasedDetector.scan(text).get("flags") else 0.0
        semantic_scores.append(semantic_score)
        lexical_scores.append(float(lexical_score))
        rule_scores.append(rule_score)
        score_rows.append(
            {
                "id": case["id"],
                "label": int(case["label"]),
                "category": case.get("category"),
                "hard_negative": bool(case.get("hard_negative", False)),
                "text_sha256_prefix": _text_hash(text),
                "semantic_score": round(semantic_score, 6),
                "lexical_score": round(float(lexical_score), 6),
                "lexical_top_category": lexical_category,
                "lexical_top_name": lexical_name,
                "rule_score": rule_score,
            }
        )

    semantic_array = np.asarray(semantic_scores, dtype=np.float64)
    lexical_array = np.asarray(lexical_scores, dtype=np.float64)
    rule_array = np.asarray(rule_scores, dtype=np.float64)
    calibration = _best_threshold(labels, semantic_array)
    threshold = float(calibration["selected"]["threshold"])
    lexical_threshold = float(EMBEDDING_MATCH_THRESHOLD)
    component_comparison = {
        "rules_only": _component_row(labels, rule_array, 0.5),
        "lexical_only": _component_row(labels, lexical_array, lexical_threshold),
        "semantic_only": _component_row(labels, semantic_array, threshold),
        "rules_plus_semantic_or": _component_row(labels, np.maximum(rule_array, semantic_array), threshold),
        "notes": "Development/calibration comparison only; not a final benchmark or ablation claim.",
    }
    hard_negative_scores = [row["semantic_score"] for row in score_rows if row["hard_negative"]]
    positive_scores = [row["semantic_score"] for row in score_rows if row["label"] == 1]
    benign_scores = [row["semantic_score"] for row in score_rows if row["label"] == 0 and not row["hard_negative"]]
    output = {
        "schema_version": "1.0",
        "dataset_version": dataset.get("dataset_version"),
        "dataset_path": str(DATASET_PATH.relative_to(ROOT)),
        "development_only": True,
        "heldout_used": False,
        "detector_status": detector.status(),
        "threshold_calibration": calibration,
        "selected_threshold": threshold,
        "component_comparison": component_comparison,
        "score_distributions": {
            "positive": positive_scores,
            "benign": benign_scores,
            "hard_negative_security_discussion": hard_negative_scores,
        },
        "cases": score_rows,
    }
    OUTPUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({
        "selected_threshold": threshold,
        "selected_metrics": calibration["selected"],
        "component_comparison": component_comparison,
        "output": str(OUTPUT_PATH),
    }, indent=2))


if __name__ == "__main__":
    main()
