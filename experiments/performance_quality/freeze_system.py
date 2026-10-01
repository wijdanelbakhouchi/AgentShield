"""Freeze Phase 15 and security/runtime metadata before timing begins."""

from __future__ import annotations

import json
from datetime import datetime, timezone

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

from .config import (
    CONFIGS_DIR,
    PERFORMANCE_CONFIG_NAMES,
    PERFORMANCE_DATASET,
    QUALITY_DATASET,
    QUALITY_RUBRIC,
    ROOT,
    SYSTEM_FREEZE,
    load_json,
)
from .runtime import git_sha, probe_semantic, provider_status, sha256_file, sha256_json, python_metadata


REPO = ROOT.parent.parent
PHASE15_FREEZE = REPO / "experiments" / "final_evaluation" / "datasets" / "system_freeze.json"
PHASE15_MANIFEST = REPO / "experiments" / "final_evaluation" / "datasets" / "final_corpus_v1.manifest.json"
PHASE15_DATASET = REPO / "experiments" / "final_evaluation" / "datasets" / "final_corpus_v1.json"


def _config_hash() -> str:
    values = {name: load_json(CONFIGS_DIR / f"{name}.json") for name in PERFORMANCE_CONFIG_NAMES}
    return sha256_json(values)


def _phase15_snapshot() -> dict:
    if not PHASE15_FREEZE.exists() or not PHASE15_MANIFEST.exists() or not PHASE15_DATASET.exists():
        raise RuntimeError("Phase 16 requires the checked-in Phase 15 freeze, manifest, and dataset")
    manifest = load_json(PHASE15_MANIFEST)
    freeze = load_json(PHASE15_FREEZE)
    dataset_hash = sha256_file(PHASE15_DATASET)
    if manifest.get("sha256") != freeze.get("dataset", {}).get("sha256"):
        raise RuntimeError("Phase 15 manifest and system freeze disagree")
    # Phase 15 hashes canonical JSON, so retain its recorded hash rather than
    # treating a platform newline representation as a new dataset.
    if manifest.get("sha256") != freeze.get("dataset", {}).get("sha256"):
        raise RuntimeError("Phase 15 dataset freeze is inconsistent")
    return {
        "dataset_version": manifest.get("dataset_version"),
        "dataset_sha256": manifest.get("sha256"),
        "dataset_file_sha256": dataset_hash,
        "manifest_sha256": sha256_file(PHASE15_MANIFEST),
        "system_freeze_sha256": sha256_file(PHASE15_FREEZE),
        "base_commit": freeze.get("git_commit"),
        "security_weights": freeze.get("security_weights"),
        "policy_block_threshold": freeze.get("policy_block_threshold"),
        "semantic_model": freeze.get("semantic_model"),
        "attack_corpus": freeze.get("attack_corpus"),
        "tool_policy": freeze.get("tool_policy"),
        "graph_architecture": freeze.get("graph_architecture"),
    }


def build_freeze() -> dict:
    phase15 = _phase15_snapshot()
    semantic = probe_semantic()
    provider = provider_status()
    if git_sha(REPO) != "a3e8e7bd4f16bea4f1d00ec3b9d5822b53dbe1a6":
        raise RuntimeError("Phase 16 must start from the requested Phase 15 commit")
    return {
        "freeze_version": "phase16-runtime-freeze-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha(REPO),
        "phase15": phase15,
        "security_configuration": {
            "weights": {
                "rule": RULE_WEIGHT,
                "semantic_similarity": SIMILARITY_WEIGHT,
                "classifier": CLASSIFIER_WEIGHT,
                "context": CONTEXT_WEIGHT,
            },
            "policy_block_threshold": POLICY_BLOCK_THRESHOLD,
            "semantic_model": {
                "name": SEMANTIC_MODEL_NAME,
                "revision": SEMANTIC_MODEL_REVISION,
                "threshold": SEMANTIC_SIMILARITY_THRESHOLD,
                "enabled": SEMANTIC_SIMILARITY_ENABLED,
            },
            "security_config_hash": sha256_json({
                "rule": RULE_WEIGHT,
                "semantic_similarity": SIMILARITY_WEIGHT,
                "classifier": CLASSIFIER_WEIGHT,
                "context": CONTEXT_WEIGHT,
                "policy_block_threshold": POLICY_BLOCK_THRESHOLD,
                "semantic_model": SEMANTIC_MODEL_NAME,
                "semantic_revision": SEMANTIC_MODEL_REVISION,
                "semantic_threshold": SEMANTIC_SIMILARITY_THRESHOLD,
                "semantic_enabled": SEMANTIC_SIMILARITY_ENABLED,
            }),
        },
        "performance_dataset": {
            "path": str(PERFORMANCE_DATASET.relative_to(REPO)),
            "sha256": sha256_file(PERFORMANCE_DATASET),
            "sample_count": len(load_json(PERFORMANCE_DATASET)),
        },
        "quality_dataset": {
            "path": str(QUALITY_DATASET.relative_to(REPO)),
            "sha256": sha256_file(QUALITY_DATASET),
            "task_count": len(load_json(QUALITY_DATASET)),
        },
        "quality_rubric": {"path": str(QUALITY_RUBRIC.relative_to(REPO)), "sha256": sha256_file(QUALITY_RUBRIC)},
        "configuration_hash": _config_hash(),
        "semantic_runtime": semantic,
        "provider_runtime": provider,
        "python": python_metadata(),
        "seed": 20250916,
        "final_test_read_only": True,
        "fallback_quality_evidence": False,
    }


def main() -> None:
    data = build_freeze()
    SYSTEM_FREEZE.parent.mkdir(parents=True, exist_ok=True)
    if SYSTEM_FREEZE.exists():
        existing = load_json(SYSTEM_FREEZE)
        protected = ("phase15", "security_configuration", "performance_dataset", "quality_dataset", "quality_rubric", "configuration_hash")
        if any(existing.get(key) != data.get(key) for key in protected):
            raise RuntimeError("Existing Phase 16 freeze differs; create a new experiment version instead of overwriting")
    SYSTEM_FREEZE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
