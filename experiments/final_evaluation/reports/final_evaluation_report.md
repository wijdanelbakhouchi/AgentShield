# Phase 15 Final Research Evaluation Report

**Status: FRAMEWORK / DETERMINISTIC EVALUATION ONLY**

This report is generated from frozen dataset, configuration, and raw-result artifacts. It is not a thesis conclusion.

## Dataset

- Version: final_corpus_v1
- SHA-256: 4bbcc382db9d70108c3f084ed9bd9247e51fb40947c56b85ba330b6c57c2234a
- Samples: 52 (malicious 36, benign 16)
- Effective groups: 50
- Category counts: {"BENIGN_SECURITY_DISCUSSION": 8, "CROSS_AGENT_ATTACK": 4, "DIRECT_INJECTION": 4, "INDIRECT_INJECTION": 4, "NORMAL_BENIGN": 8, "OBFUSCATION": 4, "ROLE_HIJACKING": 4, "SECRET_EXFILTRATION": 4, "SYSTEM_PROMPT_EXTRACTION": 4, "TOOL_ABUSE": 4, "WORKFLOW_HIJACK": 4}
- Provenance: manually curated threat-model tasks, with explicitly marked transformed variants; no public dataset or real-world attack claim.
- Development/calibration samples reused as final: NO.
- Duplicate policy: casefolded whitespace-normalized text and unique sample IDs; transformation siblings share group_id.

## Frozen System

- Base commit: 0cc8f62a83550c1e2dca28113b0f37badd3f80b5
- Security weights: {"classifier": 0.0, "context": 0.3, "rule": 0.4, "semantic_similarity": 0.3}
- Block threshold: 0.17
- Semantic model/revision/threshold: sentence-transformers/all-MiniLM-L6-v2 / 1110a243fdf4706b3f48f1d95db1a4f5529b4d41 / 0.51
- Historical semantic attack corpus SHA-256: c1752cf57e79414de28a56769432301de33f1831c22f041a6e08ca976e269ce3
- Final-test runner is read-only with respect to thresholds, detectors, rules, semantic corpus, and policies.

## Method

The controlled evaluator preserves the researcher -> planner -> writer -> finalizer topology and uses only inert evaluation resources. FULL_AGENTSHIELD reuses the repository normalizer, rule detector, context analyzer, calibrated scorer, and policy mapping. Ablations disable only the named defense flag; business/task stages and sandbox constraints remain. BASELINE_NO_AGENTSHIELD disables all AgentShield interventions while retaining the same four stages and records attack behavior as successful when a malicious row reaches the end.

Decision mapping: BLOCK, REVIEW, and SANITIZE are mitigation/positive; ALLOW is non-mitigation. TP = malicious mitigated, TN = benign allowed, FP = benign mitigated, FN = malicious allowed. Attack Success Rate (ASR) = successful malicious rows / malicious rows; Mitigation Rate = 1 - ASR.

The pinned embedding runtime was unavailable in this environment, so semantic findings are recorded as unavailable and no lexical substitute is used. No classifier ablation is claimed because its frozen weight is 0.00 and no runtime provider was verified.

## Baseline vs Full

| Configuration | Recall | F1 | FPR | ASR | Mitigation Rate |
|---|---:|---:|---:|---:|---:|
| BASELINE_NO_AGENTSHIELD | 0.0% | N/A | 0.0% | 100.0% | 0.0% |
| FULL_AGENTSHIELD | 66.7% | 77.4% | 12.5% | 33.3% | 66.7% |

## Ablation

Delta ASR is ablation ASR minus FULL_AGENTSHIELD ASR; positive values mean more attacks succeeded after removing a layer.

| Configuration | Recall | F1 | FPR | ASR | Delta ASR |
|---|---:|---:|---:|---:|---:|
| FULL_AGENTSHIELD | 66.7% | 77.4% | 12.5% | 33.3% | 0.0% |
| NO_NORMALIZATION | 61.1% | 73.3% | 12.5% | 38.9% | 5.6% |
| NO_RULES | 11.1% | 20.0% | 0.0% | 88.9% | 55.6% |
| NO_SEMANTIC_SIMILARITY | 66.7% | 77.4% | 12.5% | 33.3% | 0.0% |
| NO_TOOL_OUTPUT_GUARD | 66.7% | 77.4% | 12.5% | 33.3% | 0.0% |
| NO_INTER_AGENT_GUARD | 66.7% | 77.4% | 12.5% | 33.3% | 0.0% |
| NO_CONTEXT_ISOLATION | 55.6% | 69.0% | 12.5% | 44.4% | 11.1% |

## Grouped 95% Bootstrap Intervals (FULL)

| Metric | Estimate | 95% CI | Effective groups |
|---|---:|---:|---:|
| attack_success_rate | 33.3% | 18.2% - 48.6% | 50 |
| f1 | 77.4% | 65.2% - 88.1% | 50 |
| fpr | 12.5% | 0.0% - 29.4% | 50 |
| mitigation_rate | 66.7% | 51.4% - 81.8% | 50 |
| recall | 66.7% | 51.4% - 81.8% | 50 |

## Category Results (FULL)

| Category | Samples | Groups | Recall | FPR | ASR |
|---|---:|---:|---:|---:|---:|
| BENIGN_SECURITY_DISCUSSION | 8 | 8 | N/A | 25.0% | N/A |
| CROSS_AGENT_ATTACK | 4 | 4 | 100.0% | N/A | 0.0% |
| DIRECT_INJECTION | 4 | 4 | 100.0% | N/A | 0.0% |
| INDIRECT_INJECTION | 4 | 4 | 100.0% | N/A | 0.0% |
| NORMAL_BENIGN | 8 | 8 | N/A | 0.0% | N/A |
| OBFUSCATION | 4 | 2 | 100.0% | N/A | 0.0% |
| ROLE_HIJACKING | 4 | 4 | 50.0% | N/A | 50.0% |
| SECRET_EXFILTRATION | 4 | 4 | 25.0% | N/A | 75.0% |
| SYSTEM_PROMPT_EXTRACTION | 4 | 4 | 75.0% | N/A | 25.0% |
| TOOL_ABUSE | 4 | 4 | 50.0% | N/A | 50.0% |
| WORKFLOW_HIJACK | 4 | 4 | 0.0% | N/A | 100.0% |

## Provider and Limitations

- Real provider available: NO (OpenAI, Gemini, Groq, and Ollama were not runtime verified/configured).
- Demo fallback used as final LLM evidence: NO.
- Real-provider final multi-agent evaluation: PENDING.
- This deterministic matrix is suitable for validating dataset integrity, ablation wiring, and detector-only security behavior; it must not be labeled a real-LLM baseline.
- Raw rows are in raw_results/*.jsonl; processed metrics are in processed_results/*.json; every metric is recomputed from raw rows.

## Reproduction

    python -m experiments.final_evaluation.validate_dataset --write-manifest
    python -m experiments.final_evaluation.freeze_system
    python -m experiments.final_evaluation.run_evaluation --all
    python -m experiments.final_evaluation.compute_metrics --all
    python -m experiments.final_evaluation.generate_report
