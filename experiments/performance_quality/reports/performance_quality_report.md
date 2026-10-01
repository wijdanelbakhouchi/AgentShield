# Phase 16 Performance + Quality Report

**Status: PARTIAL**

This report is generated from processed artifacts. Performance numbers derive from paired raw JSONL records; Phase 15 security numbers are read programmatically from its processed artifacts.

## Runtime Availability

- Semantic model: SEMANTIC_UNAVAILABLE
- Provider: fallback / model N/A / real_llm=False
- Demo/fallback output used as quality evidence: NO

## Performance

- Status: PARTIAL — deterministic/backend timing measured; unavailable semantic/provider stages remain N/A
- Workload: 300 baseline records and 300 protected records; repetitions=25; warmup/configuration=24
- Cold sandbox initialization: 3.781 ms

| Configuration | Mean | Median | P50 | P95 | P99 | Std |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 3.074 | 2.987 | 2.987 | 3.869 | 4.149 | 0.405 |
| Protected | 3.559 | 3.503 | 3.503 | 4.339 | 4.675 | 0.422 |

- Security overhead: 0.485 ms (15.771%).

## Stage Latency

| Stage | Baseline | Protected |
|---|---|---|
| Normalization | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=0.262, median=0.252, P50=0.252, P95=0.363, P99=0.425, std=0.055 |
| Rules | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=0.116, median=0.115, P50=0.115, P95=0.171, P99=0.216, std=0.035 |
| Semantic embeddings | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A |
| Scoring | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=0.016, median=0.016, P50=0.016, P95=0.024, P99=0.035, std=0.006 |
| Policy | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=0.011, median=0.010, P50=0.010, P95=0.016, P99=0.027, std=0.004 |
| LLM/provider | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A |
| Tool execution | mean=0.010, median=0.009, P50=0.009, P95=0.011, P99=0.044, std=0.011 | mean=0.011, median=0.010, P50=0.010, P95=0.016, P99=0.019, std=0.002 |
| Tool output guard | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A |
| Context isolation | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=0.100, median=0.092, P50=0.092, P95=0.135, P99=0.166, std=0.021 |
| Inter-agent guard | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A | mean=N/A, median=N/A, P50=N/A, P95=N/A, P99=N/A, std=N/A |
| Database/persistence | mean=3.022, median=2.923, P50=2.923, P95=3.805, P99=4.053, std=0.396 | mean=3.061, median=2.993, P50=2.993, P95=3.784, P99=3.977, std=0.367 |
| Agent workflow | mean=0.008, median=0.004, P50=0.004, P95=0.017, P99=0.027, std=0.009 | mean=0.007, median=0.003, P50=0.003, P95=0.017, P99=0.027, std=0.008 |

## Response Quality

- Status: PENDING
- Method: human blinded A/B comparison using the checked-in rubric; no LLM judge was used.
- Dataset size: 12 benign tasks; scored records: 0
- Provider: fallback
- Task Success / Relevance / Completeness / Factuality / Helpfulness: N/A — real provider response and human scores are pending.

## Phase 15 Security Effectiveness (linked artifact)

- FULL_AGENTSHIELD: TP/TN/FP/FN=24/14/2/12; recall=0.667; F1=0.774; ASR=0.333.
- BASELINE_NO_AGENTSHIELD: TP/TN/FP/FN=0/16/0/36; ASR=1.000.

## Results Pipeline

runner → raw JSONL → compute_performance/compute_quality → processed summaries → figures → report
- Figures: `experiments/performance_quality/figures/latency_comparison.png`, `experiments/performance_quality/figures/stage_latency_distribution.png`, `experiments/performance_quality/figures/security_overhead.png`
- Every displayed number is derived from a raw/processed artifact and configuration; no manual measurements are embedded.

## Traceability

- Runtime freeze: experiments\performance_quality\datasets\system_freeze_phase16.json (SHA-256 1511dd9522eb7920b2afba125f805a7778321190c864f3b80988500d500b3885)
- Performance summary: experiments\performance_quality\processed_results\performance_summary.json (SHA-256 37dd49aa872fcb41530037fd03ce7405c06481fe65c86ded03dc0a97db3bb99a)
- Quality summary: experiments\performance_quality\processed_results\quality_summary.json (SHA-256 856cfb0c9f9f882e9608ba1d36bd69975302fbd1a5bad509287aad94858d69fa)
- Git SHA recorded by freeze: a3e8e7bd4f16bea4f1d00ec3b9d5822b53dbe1a6
- Seed: 20250916; Python: 3.11.4 (tags/v3.11.4:d2340ef, Jun  7 2023, 05:45:37) [MSC v.1934 64 bit (AMD64)]

## Limitations

Semantic embeddings were unavailable in the current runtime, so semantic latency is N/A. Canonical tool-output and inter-agent guard timings are also N/A because those boundaries would re-enter the unavailable semantic runtime; no substitute latency is reported. No real provider was runtime-verified; response-quality scores remain PENDING. Deterministic backend timing uses an inert temporary SQLite sandbox and cannot substitute for provider latency.

Reproduction commands are documented in `experiments/performance_quality/README.md`.
