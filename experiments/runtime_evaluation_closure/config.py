"""Immutable paths and identities used by the Phase 16.5 closure run."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
PHASE15_ROOT = REPO_ROOT / "experiments" / "final_evaluation"
PHASE16_ROOT = REPO_ROOT / "experiments" / "performance_quality"
PHASE15_DATASET = PHASE15_ROOT / "datasets" / "final_corpus_v1.json"
PHASE15_MANIFEST = PHASE15_ROOT / "datasets" / "final_corpus_v1.manifest.json"
PHASE15_FREEZE = PHASE15_ROOT / "datasets" / "system_freeze.json"
PHASE16_FREEZE = PHASE16_ROOT / "datasets" / "system_freeze_phase16.json"
SEMANTIC_CORPUS = REPO_ROOT / "experiments" / "semantic_similarity" / "attack_corpus.json"
QUALITY_DATASET = PHASE16_ROOT / "datasets" / "quality_tasks_v1.json"
QUALITY_RUBRIC = PHASE16_ROOT / "datasets" / "quality_rubric_v1.json"

OUTPUT_ROOT = ROOT / "provider_verified_run"
PHASE15_OUTPUT = OUTPUT_ROOT / "phase15"
PHASE16_OUTPUT = OUTPUT_ROOT / "phase16"
QUALITY_OUTPUT = OUTPUT_ROOT / "quality"
RUNTIME_PROBE = ROOT / "runtime_probe.json"
CLOSURE_REPORT = ROOT / "closure_report.json"
CLOSURE_REPORT_MD = ROOT / "closure_report.md"

EXPECTED_PHASE15_SHA256 = "4bbcc382db9d70108c3f084ed9bd9247e51fb40947c56b85ba330b6c57c2234a"
EXPECTED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EXPECTED_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
EXPECTED_DIMENSION = 384
