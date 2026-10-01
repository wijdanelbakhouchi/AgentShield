# Phase 6 Result

STATUS: PASS

## Git

- Branch: `phase6/semantic-similarity`
- Base: `90e725f102462a3f408b8d1a920bc7a866d26d2d` (Phase 5)
- Phase 0–5 branches and their artifacts were not edited.
- No held-out/final benchmark, historical benchmark, or Phase 4 calibration dataset was read.

## Previous Similarity System

The prior `EmbeddingThreatMatcher` was fixed-vocabulary term-frequency cosine
over five manually authored signatures. It was used only by the legacy async
research evaluator, not the canonical runtime. It is now explicitly named
`LexicalSimilarityDetector`; the baseline inventory is in
`BASELINE_REPORT.md`.

## Semantic Model

The canonical detector uses the real local `sentence-transformers/all-MiniLM-L6-v2`
sentence encoder, pinned to snapshot `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`.
Runtime verification succeeded with CPU inference and a 384-dimensional output.
No lexical score is substituted when the model is unavailable.

## Attack Corpus

`attack_corpus.json` contains 45 structured, manually authored entries across
direct/indirect injection, jailbreak, prompt/system exfiltration, secret access,
tool abuse, role hijack, obfuscation, and workflow hijack families. Every entry
has an ID, category, family, and text; provenance/version metadata is recorded.
Corpus SHA-256: `1eb918f80ea304c737ffe0347f1031ff4b96e6f33bfe27472f876d8fd3b59c8a`.

## Corpus Embedding

Corpus vectors are batch encoded once during lazy singleton initialization and
retained in process memory. The detector returns the corpus hash, count,
embedding dimension, model revision, and `corpus_embedding_precomputed` status
with each result.

## Semantic Detector

Candidate inputs are the canonical normalized representation plus meaningful
normalized/decoded Phase 5 representations. Opaque encoded strings are skipped;
decoded candidates retain representation ID, depth, and provenance. Cosine
similarity is computed against all corpus vectors, and top-k (default 3) matches
include category, family, score, representation, and provenance. Findings are
matches at or above the distinct semantic threshold (`0.51`).

## Similarity Calibration Dataset

`similarity_calibration.json` is development-only: 16 semantic attack
paraphrases, 8 benign requests, and 8 hard-negative security discussions. It
contains no protected final/held-out records and was not used as a final
benchmark. Score rows store only IDs and text-hash prefixes in the result.

## Threshold Calibration

`calibrate_semantic_similarity.py` evaluated the full 0.00–1.00 grid at 0.01
steps. Objective: maximize F1 subject to FPR ≤ 0.10, while reporting F2 for
security-sensitive recall comparison. Selected threshold: **0.51**.

Development metrics at 0.51: TP=13, TN=15, FP=1, FN=3, precision=0.928571,
recall=0.812500, F1=0.866667, F2=0.833333, FPR=0.062500, FNR=0.187500,
balanced accuracy=0.875000. The complete grid, neighboring thresholds, and
score distributions are in `calibration_results.json`.

## Component Comparison

Development/calibration comparison only (not a final ablation):

- Rules only: F1=0.000, recall=0.000, FPR=0.0625.
- Legacy lexical only (`0.35`): F1=0.210526, recall=0.125, FPR=0.0625.
- Semantic only (`0.51`): F1=0.866667, recall=0.8125, FPR=0.0625.
- Rules + semantic (OR): F1=0.838710, recall=0.8125, FPR=0.125.

## Semantic Paraphrase Evaluation

The 16 positive paraphrases produced 13 threshold findings (recall 81.25%).
The three misses are retained in the development artifact for transparency;
they are not used to inspect or tune the protected final test.

## Hard-Negative Analysis

Eight benign security-discussion cases were evaluated separately. One semantic
hard negative crossed 0.51 (score 0.554746); seven remained below threshold.
The lexical/rule baselines also show their own discussion false positives in the
case-level artifact. This confirms that security vocabulary alone is not a
semantic verdict and motivates later global calibration.

## Normalized Representation Integration

Semantic detection is called from canonical `RiskAnalyzer` after the existing
Phase 5 normalization and rule scan. Base64/hex/ROT13/URL/HTML decoded forms
can be embedded as bounded candidates with provenance; normalization code and
limits were not redesigned.

## Model Failure Behavior

`SEMANTIC_SIMILARITY_ENABLED=false` returns `status=disabled` and
`semantic_similarity_enabled=false`. Import, model-load, or corpus failures
return `status=unavailable`, a warning reason, no findings, and no lexical
fallback. Fixture encoders exist only in unit tests and are labeled `fixture`.

## Performance

After model/corpus warm-up, a 384-d CPU detector measured approximately 16.7–25.9
ms per single candidate request in the local smoke run (mean 19.5 ms over 15
requests). Model initialization and one-time corpus precompute are intentionally
outside the steady-state request cost.

## Scorer Integration

`SecurityAnalysisResult.semantic_similarity`, `raw_signals`, and
`RiskScorer.component_values["semantic_similarity"]` expose structured evidence;
the scorer also records a contributing-factor explanation. Semantic score impact
is explicitly disabled (effective weight 0) pending post-Phase-6 global risk and
policy recalibration. Existing Phase 4 rule/classifier/context weights and policy
thresholds remain unchanged.

## Regression Tests

Full pytest: **78 passed** (Phase 5 baseline was 74). New tests cover fixture
lifecycle/precompute, provenance selection, explicit failure behavior, corpus
structure, and the renamed lexical baseline.

## Runtime

Real local model status: `ready`; corpus precompute: `true`; model revision and
dimension are recorded above. Canonical API smoke returned a semantic finding
such as `SEMANTIC_SIMILARITY:SYSTEM_EXFILTRATION:0.693`.

## Docker

`docker compose build` passed for backend and frontend. Backend image uses the
CPU-only PyTorch wheel and bakes the pinned embedding snapshot. `docker compose
up -d` passed; `/api/v1/health` returned HTTP 200 with database connected;
frontend `/` returned HTTP 200; canonical `/api/v1/analyze` smoke returned HTTP
200 and semantic findings. Containers were stopped after verification.

## Frontend

Frontend `npm ci --ignore-scripts` completed (the normal sandboxed install hit a
Windows EPERM worker-spawn restriction). `npm run build` completed successfully
with Node 22 (the project requests Node 20.x); only the existing chunk-size
warning was emitted. No frontend design changes were made.

## Ruff

Targeted Phase 6 files: **all checks passed**. Full-tree Ruff reports 95
pre-existing legacy findings outside this scoped detector work; no new Phase 6
module findings remain.

## Research Integrity

No final benchmark, held-out test, historical benchmark, or post-Phase-4 global
calibration was used. Development artifacts identify their purpose and hashes.
The old lexical implementation is clearly labeled and no longer described as an
embedding detector.

## Recalibration Requirement

**Required.** Once semantic evidence is admitted to production risk/policy
decisions, rerun global risk/policy calibration after Phase 6. The Phase 4
operating point must not be claimed as post-Phase-6 optimal.

## Remaining Limitations

- `all-MiniLM-L6-v2` is English-centric; the multilingual development probe
  flagged the English attack but missed Spanish, French, and Arabic paraphrases
  at 0.51. Results are in `multilingual_results.json`.
- The corpus and calibration set are development-sized and manually authored;
  they do not establish final benchmark performance.
- Semantic evidence is currently audit/provisional only and does not change the
  production score until global recalibration.

## Files Changed

- `analyzer/semantic_similarity.py`
- `analyzer/risk_analyzer.py`, `state.py`, `scoring/risk_scorer.py`
- `analyzer/threat_evaluator.py`, `tests/test_threat_evaluator.py`
- `api/server.py`, `config.py`, `.env.example`, `requirements.txt`
- `Dockerfile.backend`
- `experiments/semantic_similarity/*`
- `scripts/calibrate_semantic_similarity.py`,
  `scripts/evaluate_semantic_multilingual.py`
- `tests/test_semantic_similarity.py`

## Final Decision

- Real embedding detector implemented and runtime-verified: **YES**
- Old lexical system clearly labeled as lexical baseline: **YES**
- Similarity threshold empirically justified on development data: **YES (0.51)**
- Hard negatives evaluated and reported: **YES**
- Semantic detector adds demonstrated development value: **YES (provisional)**
- Canonical runtime integration: **YES (`RiskAnalyzer`)**
- Held-out/final test preserved: **YES**
- Global recalibration required after Phase 6: **YES**
- Phase 6 complete: **YES**

