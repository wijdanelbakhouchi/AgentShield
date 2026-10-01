"""Validate and freeze the independent Phase 15 corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .config import ROOT


DATASET_PATH = ROOT / "datasets" / "final_corpus_v1.json"
MANIFEST_PATH = ROOT / "datasets" / "final_corpus_v1.manifest.json"
REQUIRED_FIELDS = {
    "sample_id", "label", "category", "group_id", "text", "source",
    "provenance", "expected_security_outcome", "requires_tool",
    "requires_agent_workflow", "notes",
}
ALLOWED_LABELS = {"malicious", "benign"}
ALLOWED_OUTCOMES = {"ALLOW", "BLOCK", "REVIEW", "SANITIZE"}
ALLOWED_CATEGORIES = {
    "DIRECT_INJECTION", "INDIRECT_INJECTION", "OBFUSCATION",
    "SYSTEM_PROMPT_EXTRACTION", "SECRET_EXFILTRATION", "TOOL_ABUSE",
    "ROLE_HIJACKING", "CROSS_AGENT_ATTACK", "WORKFLOW_HIJACK",
    "BENIGN_SECURITY_DISCUSSION", "NORMAL_BENIGN",
}


def _canonical_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def dataset_hash(path: Path = DATASET_PATH) -> str:
    """Hash canonical JSON so Windows newline conversion cannot alter identity."""

    with path.open("r", encoding="utf-8") as handle:
        canonical = json.load(handle)
    payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_dataset(path: Path = DATASET_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        rows = json.load(handle)
    if not isinstance(rows, list) or not rows:
        raise ValueError("Final corpus must be a non-empty JSON array")

    ids: set[str] = set()
    texts: set[str] = set()
    groups: dict[str, tuple[str, str]] = {}
    categories: Counter[str] = Counter()
    labels: Counter[str] = Counter()
    duplicate_ids: list[str] = []
    duplicate_texts: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"Sample {index} must be an object")
        missing = REQUIRED_FIELDS - row.keys()
        if missing:
            raise ValueError(f"Sample {index} missing fields: {sorted(missing)}")
        sample_id = str(row["sample_id"])
        group_id = str(row["group_id"])
        text = str(row["text"])
        label = str(row["label"]).lower()
        category = str(row["category"])
        if not sample_id or sample_id in ids:
            duplicate_ids.append(sample_id or f"index-{index}")
        if not text.strip():
            raise ValueError(f"Sample {sample_id} has empty text")
        canonical = _canonical_text(text)
        if canonical in texts:
            duplicate_texts.append(sample_id)
        ids.add(sample_id)
        texts.add(canonical)
        if label not in ALLOWED_LABELS:
            raise ValueError(f"Sample {sample_id} has invalid label {label!r}")
        if category not in ALLOWED_CATEGORIES:
            raise ValueError(f"Sample {sample_id} has invalid category {category!r}")
        if row["expected_security_outcome"] not in ALLOWED_OUTCOMES:
            raise ValueError(f"Sample {sample_id} has invalid expected outcome")
        if label == "malicious" and row["expected_security_outcome"] == "ALLOW":
            raise ValueError(f"Malicious sample {sample_id} cannot expect ALLOW")
        if label == "benign" and row["expected_security_outcome"] != "ALLOW":
            raise ValueError(f"Benign sample {sample_id} must expect ALLOW")
        if not isinstance(row["requires_tool"], bool) or not isinstance(row["requires_agent_workflow"], bool):
            raise ValueError(f"Sample {sample_id} requires boolean capability fields")
        if not isinstance(row["provenance"], dict) or not row["provenance"].get("method"):
            raise ValueError(f"Sample {sample_id} requires honest provenance.method")
        signature = (label, category)
        if group_id in groups and groups[group_id] != signature:
            raise ValueError(f"Group {group_id} crosses labels or categories")
        groups[group_id] = signature
        categories[category] += 1
        labels[label] += 1

    if duplicate_ids:
        raise ValueError(f"Duplicate sample IDs: {duplicate_ids}")
    if duplicate_texts:
        raise ValueError(f"Exact/case/whitespace duplicate texts: {duplicate_texts}")
    missing_categories = sorted(ALLOWED_CATEGORIES - categories.keys())
    if missing_categories:
        raise ValueError(f"Missing required categories: {missing_categories}")
    indirect_without_metadata = [
        row["sample_id"] for row in rows
        if row["category"] == "INDIRECT_INJECTION" and not row.get("source_metadata")
    ]
    if indirect_without_metadata:
        raise ValueError(f"Indirect samples require source_metadata: {indirect_without_metadata}")
    try:
        display_path = str(path.resolve().relative_to(ROOT.parent.parent.resolve()))
    except ValueError:
        display_path = str(path.resolve())
    return {
        "dataset_version": "final_corpus_v1",
        "dataset_path": display_path,
        "sha256": dataset_hash(path),
        "total_samples": len(rows),
        "effective_groups": len(groups),
        "labels": dict(sorted(labels.items())),
        "category_counts": dict(sorted(categories.items())),
        "duplicate_policy": "casefolded whitespace-normalized text and sample IDs",
        "hash_policy": "canonical UTF-8 JSON (sorted keys, compact separators)",
        "group_policy": "transformation siblings share group_id and are resampled together",
        "frozen": False,
    }


def freeze_dataset(path: Path = DATASET_PATH, manifest: Path = MANIFEST_PATH) -> dict[str, Any]:
    summary = validate_dataset(path)
    if manifest.exists():
        previous = json.loads(manifest.read_text(encoding="utf-8"))
        if previous.get("sha256") != summary["sha256"]:
            raise ValueError(
                "Frozen dataset content changed; create a new dataset version instead of overwriting the manifest"
            )
    summary["frozen"] = True
    summary["freeze_note"] = "Manifest is a content hash; changing samples requires a new dataset version."
    manifest.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    summary = freeze_dataset(args.dataset) if args.write_manifest else validate_dataset(args.dataset)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
