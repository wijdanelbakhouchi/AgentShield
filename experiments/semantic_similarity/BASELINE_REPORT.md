# Phase 6 baseline: legacy similarity inventory

Baseline captured from commit `90e725f102462a3f408b8d1a920bc7a866d26d2d`
before the Phase 6 implementation.

## Previous behavior

`analyzer/threat_evaluator.py` called its `EmbeddingThreatMatcher`, but it did
not load an embedding model. It built a fixed vocabulary from five manually
written attack strings, represented each string with term-frequency vectors,
and computed ordinary cosine similarity over that vocabulary. The threshold
was `EMBEDDING_MATCH_THRESHOLD=0.35`.

The five signatures were `DAN_Jailbreak_v4`, `System_Prompt_Exfiltration_v2`,
`Role_Hijack_DevNull_AI`, `Credential_Harvesting_API_Key`, and
`SQL_Injection_Bypass`. The implementation was instantiated as a module-level
matcher and used only by the asynchronous legacy `evaluate_threats` research
pipeline. The canonical runtime path (`SecurityGateway` -> `RiskAnalyzer` ->
`RiskScorer` -> `PolicyEngine`) did not call it.

## Phase 6 correction

The historical matcher is retained only as an explicitly named lexical
baseline. The canonical path receives evidence from a new local sentence
embedding detector. Its model identity, corpus hash, threshold calibration,
availability status, and score contribution policy are recorded in the Phase 6
report and development artifacts.

