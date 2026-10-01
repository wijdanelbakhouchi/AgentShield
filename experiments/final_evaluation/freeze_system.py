"""Record the Phase 15 system freeze before final evaluation begins."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import config as runtime_config
from security.tool_security import ToolSecurityPolicy

from .config import ROOT
from .validate_dataset import DATASET_PATH, MANIFEST_PATH, validate_dataset


FREEZE_PATH = ROOT / "datasets" / "system_freeze.json"
SEMANTIC_CORPUS = Path(__file__).resolve().parents[2] / "experiments" / "semantic_similarity" / "attack_corpus.json"


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT.parents[1],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def freeze_system(path: Path = FREEZE_PATH) -> dict[str, Any]:
    dataset = validate_dataset(DATASET_PATH)
    if not MANIFEST_PATH.exists():
        raise ValueError("Freeze the final dataset first with --write-manifest")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest.get("sha256") != dataset["sha256"] or not manifest.get("frozen"):
        raise ValueError("Dataset manifest is missing, stale, or not frozen")

    policy = {
        tool: sorted(role.value for role in roles)
        for tool, roles in sorted(ToolSecurityPolicy.PERMISSIONS.items())
    }
    evidence = {
        "freeze_version": "phase15-system-freeze-v1",
        "git_commit": _git_commit(),
        "security_weights": {
            "rule": runtime_config.RULE_WEIGHT,
            "semantic_similarity": runtime_config.SIMILARITY_WEIGHT,
            "classifier": runtime_config.CLASSIFIER_WEIGHT,
            "context": runtime_config.CONTEXT_WEIGHT,
        },
        "policy_block_threshold": runtime_config.POLICY_BLOCK_THRESHOLD,
        "semantic_model": {
            "name": runtime_config.SEMANTIC_MODEL_NAME,
            "revision": runtime_config.SEMANTIC_MODEL_REVISION,
            "threshold": runtime_config.SEMANTIC_SIMILARITY_THRESHOLD,
            "enabled": runtime_config.SEMANTIC_SIMILARITY_ENABLED,
        },
        "attack_corpus": {
            "path": str(SEMANTIC_CORPUS.relative_to(ROOT.parents[1])),
            "sha256": _sha256(SEMANTIC_CORPUS),
        },
        "tool_policy": {
            "permissions": policy,
            "approval_required": sorted(ToolSecurityPolicy.APPROVAL_REQUIRED_TOOLS),
            "legacy_tools_denied": sorted(ToolSecurityPolicy.LEGACY_TOOLS),
        },
        "graph_architecture": [
            "START → researcher → guard_researcher_planner → planner",
            "planner → guard_planner_writer → writer",
            "writer → guard_writer_finalizer → finalizer → END",
            "guard rejection → workflow_terminated → END",
        ],
        "dataset": {
            "version": dataset["dataset_version"],
            "sha256": dataset["sha256"],
            "total_samples": dataset["total_samples"],
            "effective_groups": dataset["effective_groups"],
        },
        "final_test_read_only": True,
        "note": "This record is captured before evaluation; final-test outcomes cannot alter security configuration.",
    }
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=FREEZE_PATH)
    args = parser.parse_args()
    print(json.dumps(freeze_system(args.output), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
