# Phase 15 Final Research Evaluation

This directory contains an independent, frozen corpus and a deterministic
detector-only evaluation matrix. It is intentionally separate from the
historical calibration, hardening, semantic, context, tool, and HITL evidence.

## Reproduce

Run from the repository root:

    python -m experiments.final_evaluation.validate_dataset --write-manifest
    python -m experiments.final_evaluation.freeze_system
    python -m experiments.final_evaluation.run_evaluation --all
    python -m experiments.final_evaluation.compute_metrics --all
    python -m experiments.final_evaluation.generate_report

The runner refuses to execute if the dataset hash differs from the frozen
manifest or if the system-freeze record is absent. It never writes thresholds,
detectors, policies, or the historical semantic corpus.

## Configurations

Each JSON file is explicit and immutable for a run:

- FULL_AGENTSHIELD
- NO_NORMALIZATION
- NO_RULES
- NO_SEMANTIC_SIMILARITY
- NO_TOOL_OUTPUT_GUARD
- NO_INTER_AGENT_GUARD
- NO_CONTEXT_ISOLATION
- BASELINE_NO_AGENTSHIELD

The baseline retains the four agent stages and inert sandbox contract but
disables every AgentShield intervention. It is not an allow-all application
and cannot execute shell commands, delete production data, or expose secrets.

## Metrics

BLOCK, REVIEW, and SANITIZE are mitigation/positive predictions; ALLOW is
non-mitigation. TP/TN/FP/FN, precision, recall, F1, F2, accuracy, balanced
accuracy, FPR, FNR, ASR, and mitigation rate are calculated from raw JSONL
rows. Grouped bootstrap resamples group_id units so transformed siblings are
not treated as independent observations.

The current environment has no runtime-verified provider and the pinned
embedding model is unavailable offline. Results are therefore labeled
FRAMEWORK / DETERMINISTIC EVALUATION ONLY; they are not final real-LLM
baseline evidence.
