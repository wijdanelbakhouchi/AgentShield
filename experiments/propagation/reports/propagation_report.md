# AgentShield Propagation Study — Results Report

**Status:** deterministic detector-stack evaluation on the frozen benchmark v2 corpus. All numbers below are reported from processed experiment summaries; raw run records are generated artifacts and are not committed by default.

## 1. Research questions

1. How far do prompt-injection payloads propagate through the frozen multi-agent graph when the system is unprotected?
2. Which defense layer (gateway, tool security, message-level inter-agent monitoring, provenance awareness) closes the propagation gap, and by how much?
3. What is the false-positive cost of each configuration on benign and benign-with-adversarial-distractor content?
4. How much do adaptive (transformed) attacks degrade containment relative to non-adaptive attacks?

## 2. Methodology

- **Testbed:** frozen graph `user -> researcher -> planner -> writer -> finalizer` with canonical `InterAgentGuard` boundaries; agent prompts and topology are frozen in the propagation experiment configuration.
- **Detector stack:** canonical normalize -> rules -> context -> sentence-embedding similarity -> calibrated risk -> policy. The LLM classifier is excluded because its calibrated weight is 0.00; scores are unchanged.
- **Propagation model:** deterministic reachability — an agent that receives payload-bearing content reproduces it verbatim in its output. This measures the security envelope, not LLM compliance, and is fully reproducible without a live provider.
- **Corpus:** benchmark v2 (dev + held-out test template families); the split methodology is encoded in the benchmark dataset builder and propagation experiment configuration.
- **Uncertainty:** 95% group bootstrap CIs (template family as the resampling unit); paired configuration comparisons use McNemar's test with Yates correction on per-sample attack success.

## 3. Security metrics (per configuration)

| Configuration | ASR | Mitigation | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|
| Baseline (unprotected) | 1.0000 | 0.0000 | — | 0.0000 | — | 0.0000 |
| Gateway only | 0.8429 | 0.1571 | 0.8462 | 0.1571 | 0.2651 | 0.1739 |
| Full, no semantic | 0.5500 | 0.4500 | 0.8750 | 0.4500 | 0.5943 | 0.3913 |
| Full AgentShield | 0.5500 | 0.4500 | 0.8630 | 0.4500 | 0.5915 | 0.4348 |
| Full + provenance | 0.4643 | 0.5357 | 0.8621 | 0.5357 | 0.6608 | 0.5217 |
| Full, banded policy | 0.5500 | 0.4500 | 0.8630 | 0.4500 | 0.5915 | 0.4348 |
| Alert-only (detection) | 1.0000 | 0.0000 | — | 0.0000 | — | 0.0000 |

FPR is measured on the benign arm (normal + benign-with-distractor); a high FPR on distractor content is a measured cost of aggressive deterministic rules, not a claim of zero false positives.

## 4. Propagation metrics

| Configuration | Mean depth | Median depth | Privileged reach | Contained @ gateway | Contained @ tool | Contained @ researcher | Contained @ inter-agent |
|---|---|---|---|---|---|---|---|
| Baseline (unprotected) | 4.0000 | 4.0000 | 1.0000 | 0 | 0 | 0 | 0 |
| Gateway only | 3.3714 | 4.0000 | 0.7297 | 22 | 0 | 0 | 0 |
| Full, no semantic | 2.2000 | 4.0000 | 0.7297 | 19 | 34 | 10 | 0 |
| Full AgentShield | 2.1857 | 4.0000 | 0.7297 | 22 | 32 | 9 | 1 |
| Full + provenance | 1.8500 | 0.0000 | 0.6757 | 39 | 32 | 4 | 1 |
| Full, banded policy | 2.1857 | 4.0000 | 0.7297 | 22 | 32 | 9 | 1 |
| Alert-only (detection) | 4.0000 | 4.0000 | 1.0000 | 0 | 0 | 0 | 0 |

Privileged reach = attacks targeting the writer or finalizer that reached their target.

## 5. Paired comparisons (McNemar)

| Comparison | p-value | Paired samples |
|---|---|---|
| baseline_vs_full_no_provenance | 0.0000 | 140 |
| full_no_provenance_vs_full_banded_sanitize | 1.0000 | 140 |
| full_no_provenance_vs_full_provenance | 0.0015 | 140 |
| gateway_only_vs_full_no_provenance | 0.0000 | 140 |

p < 0.05 indicates a statistically significant difference in per-sample attack success on this corpus.

## 6. Adaptive vs non-adaptive attacks

| Configuration | Non-adaptive ASR | Adaptive ASR |
|---|---|---|
| Baseline (unprotected) | 1.0000 (n=69) | 1.0000 (n=71) |
| Gateway only | 0.8261 (n=69) | 0.8592 (n=71) |
| Full, no semantic | 0.6522 (n=69) | 0.4507 (n=71) |
| Full AgentShield | 0.6522 (n=69) | 0.4507 (n=71) |
| Full + provenance | 0.5652 (n=69) | 0.3662 (n=71) |
| Full, banded policy | 0.6522 (n=69) | 0.4507 (n=71) |
| Alert-only (detection) | 1.0000 (n=69) | 1.0000 (n=71) |

## 7. Detector signal quality (alert-only arm)

Precision —, recall 0.0000, F1 —, FPR 0.0000, detection rate 0.0000.

## 8. Figures

- `adaptive_vs_non` -> `figures/adaptive_vs_non.png`
- `asr_by_config` -> `figures/asr_by_config.png`
- `blocked_at` -> `figures/blocked_at.png`
- `category_heatmap` -> `figures/category_heatmap.png`
- `detection_pr` -> `figures/detection_pr.png`
- `propagation_depth` -> `figures/propagation_depth.png`
- `propagation_rate_depth` -> `figures/propagation_rate_depth.png`

## 9. Honest limitations

- The propagation model measures payload **reachability**, not whether a particular LLM would comply; real-provider compliance studies remain future work (see `experiments/e2e_evaluation/`).
- FPR is estimated on a small benign arm; bootstrap CIs are wide.
- Semantic similarity uses the frozen English-focused MiniLM model; multilingual coverage is not claimed.
- Provenance bonuses (0.03 / 0.01 / 0.02) are one operating point; sensitivity to these parameters is future work.
- The LLM classifier (weight 0.00) was excluded; a future calibrated classifier tier can be added without changing the stack.

## 10. How to reproduce

```bash
python -m experiments.propagation.run_evaluation --all
python -m experiments.propagation.generate_figures
python -m experiments.propagation.generate_report
```
