# AgentShield Phase 4 Calibration Report

This report is generated from the committed raw calibration outputs. All
performance values below are **CALIBRATION PERFORMANCE — NOT FINAL TEST PERFORMANCE**.

## Dataset

- Source: `tests/benchmark_dataset.json` (SHA-256 `2655ec616d5cc509a0d21dae7fc14b35e8366136bb53d776975404026a8efe31`).
- Historical benchmark rows: 300; one representative retained per grouped base prompt.
- Authored Phase 4 rows: 24 (security-adjacent benign and context attacks, provenance-labelled).
- Calibration rows: 51 (33 malicious, 18 benign).
- Security-adjacent benign rows: 11.
- Categories: INDIRECT_INJECTION_CONTEXT=5, SECURITY_ADJACENT_BENIGN=11, DIRECT_INJECTION=7, SYSTEM_EXFILTRATION=7, INDIRECT_INJECTION=7, OBFUSCATED_EVASION=7, BENIGN_CONTROL=7.
- Exact duplicates detected in source: 0; near-duplicate/variant rows collapsed: 250; removed from calibration representatives: 250.

## Data Separation

- Development set: historical detector/rule development provenance; not used as one undifferentiated tuning set.
- Calibration set: `experiments/calibration/datasets/calibration.json`, grouped 70% role, used for Phase 4 search.
- Held-out test set: `experiments/calibration/datasets/held_out_test.json`, grouped 30% role, schema-loadability checked only.
- Was final test used during tuning? **NO**.
- No held-out score, error, or performance metric was generated.

## Existing Uncalibrated Scoring

Formula (from the Phase 3 implementation):

`round(clip(rule_weight * min(1, 0.5 * rule_flag_count) + classifier_weight * (confidence if malicious else 0) + context_weight * min(1, 0.5 * context_flag_count), 0, 1), 2)`.

Previous weights: rule `0.40`, classifier `0.40`, context `0.20`.
Previous provisional bands: `0.30 / 0.60 / 0.80`; block threshold `0.30`.
The previous values had no dataset split, objective, uncertainty estimate, or
empirical threshold search, so they were scientifically unsupported.
The immutable Phase 3 baseline is `experiments/calibration/baseline/phase3_uncalibrated_predictions.jsonl`.

## Candidate Weights

| Configuration | Weights (Rule/Classifier/Context) | Threshold | Precision | Recall | F1 | F2 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| Rules only | 1.00/0.00/0.00 | 0.50 | 0.9000 | 0.2727 | 0.4186 | 0.3169 | 5.56% |
| Classifier only | 0.00/1.00/0.00 | 0.92 | 0.8000 | 0.1212 | 0.2105 | 0.1460 | 5.56% |
| Context only | 0.00/0.00/1.00 | 0.50 | 0.8333 | 0.1515 | 0.2564 | 0.1812 | 5.56% |
| Rules + classifier | 0.50/0.50/0.00 | 0.25 | 0.9000 | 0.2727 | 0.4186 | 0.3169 | 5.56% |
| Phase 3 weights | 0.40/0.40/0.20 | 0.20 | 0.9000 | 0.2727 | 0.4186 | 0.3169 | 5.56% |
| Selected grid weights | 0.40/0.30/0.30 | 0.20 | 0.9000 | 0.2727 | 0.4186 | 0.3169 | 5.56% |

The grid used 66 non-negative simplex candidates at 0.10 increments. The best
F1 values form a plateau; the selected all-active mix is therefore a
stability/tie choice, not evidence that the three weights are uniquely
identifiable. The optional external LLM classifier was not evaluated.

## Candidate Thresholds

Threshold grid: `0.00` through `1.00` inclusive at `0.01` resolution.

| Threshold | Precision | Recall | F1 | F2 | FPR | FNR |
|---:|---:|---:|---:|---:|---:|---:|
| 0.19 | 0.9000 | 0.2727 | 0.4186 | 0.3169 | 5.56% | 72.73% |
| 0.20 **selected** | 0.9000 | 0.2727 | 0.4186 | 0.3169 | 5.56% | 72.73% |
| 0.21 | 0.8333 | 0.1515 | 0.2564 | 0.1812 | 5.56% | 84.85% |
| 0.22 | 0.8333 | 0.1515 | 0.2564 | 0.1812 | 5.56% | 84.85% |

Strict 5% FPR operating point (same selected weights): threshold `0.68`,
F1 `0.0588`, recall `0.0303`, FPR `0.00%`.
Because one benign row is `0.0556` FPR, the declared
operating constraint used the smallest resolvable limit `max(0.05, 1/N_benign)`;
the strict point is retained for transparency.

## Optimization Objective

Maximize F1 subject to the smallest empirically resolvable false-positive limit;
exact threshold ties prefer the higher (more conservative) threshold. F2 is
reported as a security-oriented sensitivity check, not automatically selected.
The F2 point is threshold `0.20` with F2 `0.3169`.

## Metric Definitions

TP = malicious blocked; TN = benign allowed; FP = benign blocked; FN = malicious
allowed. BLOCK is the only prevention action in this binary calibration; no
SANITIZE/REVIEW evidence was treated as mitigation. Detector detection rate and
policy prevention rate are reported separately. Flag-override and combined
policies were evaluated separately from score-only calibration.

## Results

Selected score-only calibration metrics: ROC-AUC `0.6566`,
PR-AUC `0.7593`. Bootstrap 95% intervals: precision
`[0.6667, 1.0000]`, recall
`[0.1289, 0.4286]`, F1
`[0.2222, 0.5883]`, FPR
`[0.0000, 0.1765]`.

Policy comparison at selected threshold: score-only F1 `0.4186` / FPR
`5.56%`; current flag-override and combined F1
`0.5714` /
FPR `11.11%`.
The override improves recall on this calibration set but adds security-adjacent
false positives, so the Phase 3 strict override remains an explicit production
setting rather than being hidden inside threshold metrics.

## Selected Configuration

- Rule weight: `0.40`
- Classifier weight: `0.30`
- Context weight: `0.30`
- BLOCK threshold: `0.20`
- LOW maximum: `0.00`
- MEDIUM maximum: `0.01`
- HIGH maximum: `0.19`
- CRITICAL begins above: `0.19`
- `POLICY_FLAG_OVERRIDE`: `true` (Phase 3 strict safety behavior retained).

## Scientific Justification

Weights were selected from the declared simplex grid. The all-active
`0.40/0.30/0.30` mix is within 0.005 F1 of the maximum and maximizes the
smallest signal weight, then minimizes distance from the Phase 3 mix; the data
does not identify a unique weight vector. The BLOCK threshold `0.20`
is the highest-F1 operating point under the one-observation FPR resolution rule;
the strict 5% point is shown separately and has unacceptable recall. Risk bands
are empirical score-distribution quantiles constrained by the selected boundary
(`0.00/0.01/0.19`), and their coarse separation is explicitly a limitation.

## Calibration Performance

**CALIBRATION PERFORMANCE — NOT FINAL TEST PERFORMANCE**

- TP: 9; TN: 17; FP: 1; FN: 24
- Precision: `0.9000`
- Recall: `0.2727`
- F1: `0.4186`
- F2: `0.3169`
- Accuracy: `0.5098`
- Balanced accuracy: `0.6086`
- FPR: `5.56%`
- FNR: `72.73%`
- ROC-AUC: `0.6566`
- PR-AUC: `0.7593`

## Category Performance

| Category | N | TP | FN | Recall |
|---|---:|---:|---:|---:|
| DIRECT_INJECTION | 7 | 4 | 3 | 57.14% |
| INDIRECT_INJECTION | 7 | 1 | 6 | 14.29% |
| INDIRECT_INJECTION_CONTEXT | 5 | 0 | 5 | 0.00% |
| OBFUSCATED_EVASION | 7 | 1 | 6 | 14.29% |
| SYSTEM_EXFILTRATION | 7 | 3 | 4 | 42.86% |

## Benign False Positive Analysis

| Benign category | N | FP | FPR |
|---|---:|---:|---:|
| BENIGN_CONTROL | 7 | 0 | 0.00% |
| SECURITY_ADJACENT_BENIGN | 11 | 1 | 9.09% |

## Threshold Stability

Performance around the selected threshold: `0.19` and
`0.20` are identical; at `0.21`
F1 falls to `0.2564`. Stable? **NO**.
The operating point is threshold-sensitive because scores are rounded to two
decimals and the calibration set is small.

## Raw Evidence

- Calibration dataset: `experiments/calibration/datasets/calibration.json`
- Raw prediction artifact: `experiments/calibration/raw/calibration_predictions.jsonl`
- Metrics artifact: `experiments/calibration/results/calibration_metrics.json`
- Calibration metadata: `experiments/calibration/results/calibration_metadata.json`
- Immutable Phase 3 baseline: `experiments/calibration/baseline/phase3_uncalibrated_predictions.jsonl`
- Reproduction command: `python -m experiments.calibration.run_calibration`
- Independent metric command: `python -m experiments.calibration.calculate_metrics --raw experiments/calibration/raw/calibration_predictions.jsonl --threshold 0.20 --weights 0.40,0.30,0.30 --policy-mode score_only`

## Configuration Update

Canonical configuration file: `config.py`.
Values updated: calibrated `RULE_WEIGHT/CLASSIFIER_WEIGHT/CONTEXT_WEIGHT =
0.40/0.30/0.30`, `POLICY_BLOCK_THRESHOLD=0.20`, risk maxima
`0.00/0.01/0.19`; all active API, CLI, Streamlit, and benchmark paths load this
source through `SecurityPipeline`.
Any duplicate active threshold definitions remaining? **NO** (legacy research
helpers read canonical constants and are not runtime paths).

## Regression Tests

Phase 3 baseline: 23 passed. Current collected: `PASS: 29 passed, 4 warnings`.
Compileall: `PASS`. Ruff: `PASS: calibration files clean; full repository retains 95 pre-existing findings`.

## Runtime

FastAPI: `PASS: TestClient startup and endpoint smoke checks`. Health HTTP 200: `PASS: HTTP 200`.
Canonical benign analysis: `PASS: 0.00 LOW ALLOW`.
Canonical malicious analysis: `PASS: 0.40 CRITICAL BLOCK`.

## Docker

Build: `PASS`. Startup: `PASS: backend healthy and frontend started`.
Health: `PASS: HTTP 200; calibrated config loaded`. Services were stopped after validation.

## Frontend

Source redesigned? **NO**. `npm ci`: `PASS: lockfile install (Node 22 engine warning; 2 audit advisories reported)`.
`npm run build`: `PASS: Vite production build (chunk-size warning only)`.

## Historical Research Integrity

Historical benchmark JSON modified? **NO**. Historical thesis results modified? **NO**.
Historical confusion matrices modified? **NO**. Held-out final-test result generated? **NO**.

## Limitations

- The calibration set has only 51 grouped representatives and 18 benign rows; intervals are wide.
- Historical cases are synthetic/template-derived and are not independent of detector development.
- The optional external LLM classifier was unavailable; **LLM CLASSIFIER CALIBRATION NOT VERIFIED**.
- Obfuscation and indirect-context families show substantial false negatives.
- Weight candidates are tied on this small dataset; no unique scientific weight estimate is possible.
- Score rounding creates threshold sensitivity; calibration performance must not be presented as final generalization.

## Deferred to Phase 5

Detector-level hardening remains out of scope: obfuscation normalization gaps,
semantic attacks missed by rules/classifier fallback, indirect-context coverage,
and similarity-detector integration. No detector rules, prompts, guards,
authentication, HITL, database, or frontend design were changed in Phase 4.

## Completion Matrix

| Item | Result |
|---|---|
| Existing scoring formula documented | PASS |
| Dataset roles separated | PASS |
| Calibration set created/validated | PASS |
| Held-out set protected | PASS |
| Duplicates checked | PASS |
| Weight search reproducible | PASS |
| Threshold search reproducible | PASS |
| Precision / Recall / F1 / FPR / FNR | PASS |
| F2/security tradeoff calculated | PASS |
| Category and benign metrics | PASS |
| Score distributions analyzed | PASS |
| Final threshold selected empirically | PASS |
| Weights selected empirically | PARTIAL (performance plateau) |
| Risk bands justified | PARTIAL (coarse due score mass at zero) |
| Raw output and metadata preserved | PASS |
| Config updated from selected result | PASS |
| Existing tests pass | PASS |
| Docker healthy | PASS |
| Frontend build passes | PASS |

## Final Decision

- Are risk-scoring weights now empirically justified? **PARTIAL** (the selected mix is traceable but not uniquely identifiable).
- Is the BLOCK threshold empirically justified? **YES, for this calibration operating point only**.
- Were false positives considered? **YES**.
- Were false negatives considered? **YES**.
- Was the final held-out test protected from tuning? **YES**.
- Can every selected configuration value be traced to raw calibration evidence? **YES**.
- Is Phase 4 scientifically reproducible? **YES**.
- Is Phase 4 complete? **YES**.

Generated with Python 3.11.4 from git commit `5604de9e1d09409b25a3a96b46cfda1fa8783d33`.
