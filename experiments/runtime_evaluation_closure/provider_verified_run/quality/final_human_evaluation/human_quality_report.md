# Phase 16.5 Final Human Quality Evaluation

Status: COMPLETE

This report is generated from the imported blinded human ratings, the private A/B mapping, and unchanged provider/runtime artifacts. No quality score is manually entered.

## Human quality

| Configuration | Task Success | Relevance | Completeness | Factuality | Helpfulness | Overall | N |
|---|---:|---:|---:|---:|---:|---:|---:|
| WITHOUT AgentShield | 5.000 | 4.667 | 4.917 | 4.417 | 4.500 | 4.700 | 12 |
| WITH AgentShield | 4.667 | 4.417 | 4.417 | 4.333 | 4.250 | 4.417 | 12 |

Quality conclusion: **INCONCLUSIVE**.
The protected-minus-baseline mean is descriptive; the interval crosses zero, so this small sample does not establish a statistically reliable quality change.

## Paired task analysis

| Task | WITHOUT overall | WITH overall | WITH minus WITHOUT |
|---|---:|---:|---:|
| quality-sum-01 | 5.000 | 3.800 | -1.200 |
| quality-sum-02 | 4.200 | 5.000 | 0.800 |
| quality-exp-01 | 4.600 | 5.000 | 0.400 |
| quality-exp-02 | 4.600 | 5.000 | 0.400 |
| quality-plan-01 | 4.400 | 5.000 | 0.600 |
| quality-plan-02 | 5.000 | 4.400 | -0.600 |
| quality-qa-01 | 4.800 | 5.000 | 0.200 |
| quality-qa-02 | 5.000 | 5.000 | 0.000 |
| quality-write-01 | 5.000 | 3.800 | -1.200 |
| quality-write-02 | 4.400 | 5.000 | 0.600 |
| quality-research-01 | 5.000 | 1.000 | -4.000 |
| quality-research-02 | 4.400 | 5.000 | 0.600 |

- Mean paired difference: -0.283
- Paired standard deviation: 1.360
- 95% CI: [-1.148, 0.581] (paired t interval, df=11, two-sided 95%)

## Provider and runtime

- Provider-backed quality responses: groq / openai/gpt-oss-20b / fallback records=0
- Semantic runtime: READY (sentence-transformers/all-MiniLM-L6-v2 revision 1110a243fdf4706b3f48f1d95db1a4f5529b4d41, dimension 384)

## Phase 15 security

- FULL_AGENTSHIELD TP/TN/FP/FN: 26/14/2/10; precision=0.9286; recall=0.7222; F1=0.8125; F2=0.7558; FPR=0.1250; FNR=0.2778; ASR=0.2778; mitigation=0.7222.
- BASELINE_NO_AGENTSHIELD ASR: 1.0000.

## Phase 16 performance

- Baseline P95: 5936.474 ms
- Protected P95: 3933.558 ms
- Observed paired mean difference: -753.012 ms
- Design: N=12 per configuration, one repetition, no warmup, remote-provider/network variability.
- The observed negative difference is reported only as this run's observation; it is not evidence that AgentShield makes requests faster.

## Repair provenance

- Original artifact: 2/24 valid responses; preserved.
- Repaired artifact: 24/24 non-empty responses; 22 records regenerated.
- Cause: empty completion / insufficient token budget.
- Provider remained Groq with model openai/gpt-oss-20b; no fallback response was used as evidence.

## Traceability

human ratings → private joined ratings → this processed summary → figures → this report
- Summary: experiments\runtime_evaluation_closure\provider_verified_run\quality\final_human_evaluation\human_quality_summary.json
- Figures: experiments\runtime_evaluation_closure\provider_verified_run\quality\final_human_evaluation\figures\quality_dimensions.png, experiments\runtime_evaluation_closure\provider_verified_run\quality\final_human_evaluation\figures\quality_paired_differences.png
- Imported ratings SHA-256: 9406fcb3970edb0c27aa3880899f1e5d0d8c488e903072bb28cf5d4f9c77a7d3
- Private mapping source SHA-256: c594e42b36917693a26631184be2799d16f6fc73fbd0f723a6761c8a871b9022
- Quality dataset SHA-256: 802cc42d0fef9954c63bc83975b9afdde50f1bff2b5fabfd01053fc6bb3a12ea

## Integrity

Security configuration changed: NO.
Phase 15 dataset changed: NO.
Human ratings modified: NO.
Final evaluation used for tuning: NO.
Public blind artifact modified: NO.
