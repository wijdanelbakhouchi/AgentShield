# Phase 5 Detector Hardening — Development Report

This report is development evidence for deterministic detector hardening. It is
not final benchmark or calibration evidence. The cases are local, targeted
fixtures under `cases/development_cases.json`; no Phase 4 held-out sample or
historical benchmark was loaded.

## Research status

Phase 4 calibration measured the pre-hardening detector stack. Phase 5 changes
normalization and deterministic detector outputs, so Phase 4 weights and
threshold performance must not be interpreted as final post-hardening evidence.
The Phase 4 artifacts remain unchanged and reproducible. A new calibration is
required after detector and the Phase 6 similarity architecture stabilize.

## Development matrix

The executable matrix is `results/development_matrix.json`. It compares the
immutable `results/pre_hardening_baseline.json` with the current detector over
28 development cases:

- malicious development cases: 17; detected before: 8; detected after: 17;
  missed after: 0;
- benign controls: 11; deterministic rule findings: 0;
- mean normalization/detection smoke time: approximately 0.581 ms;
  worst representative case: approximately 5.151 ms.

These are **DEVELOPMENT HARDENING RESULTS — NOT FINAL TEST PERFORMANCE**.

## Support matrix

| Technique | Implemented | Unit Tested | Detector Tested | Benign Control | Limitations |
|---|---:|---:|---:|---:|---|
| Plain injection | YES | YES | YES | YES | Pattern families remain deterministic heuristics |
| Unicode normalization | YES | YES | YES | YES | NFKC does not infer arbitrary semantic equivalence |
| Zero-width | YES | YES | YES | YES | Scoped invisible/control set; raw input is preserved |
| Homoglyphs | YES | YES | YES | YES | Small security-scoped Latin/Cyrillic/Greek map, not full Unicode confusable coverage |
| Base64 | YES | YES | YES | YES | Printable UTF-8 candidates only; arbitrary binary is ignored |
| Nested Base64 | YES | YES | YES | YES | Maximum decode depth is bounded at 3 |
| Hex | YES | YES | YES | YES | Printable text candidates only; hashes/colors/addresses are ignored when not plausible text |
| ROT13 | YES | YES | YES | YES | Only strong security-word candidates are expanded |
| URL encoding | YES | YES | YES | YES | Standard percent-decoding is bounded by representation depth |
| HTML entities | YES | YES | YES | YES | Numeric/named entities are decoded conservatively |
| Leetspeak | YES | YES | YES | YES | Conservative token map; multilingual and novel substitutions remain limited |
| Case obfuscation | YES | YES | YES | YES | Case-insensitive rule families; original case remains available |
| Spacing obfuscation | YES | YES | YES | YES | Detector-only compact/segmented representation; no destructive rewrite of user text |
| Mixed transformations | YES | YES | YES | YES | Breadth and depth are capped to avoid combinatorial expansion |

## Safety bounds

Limits are centralized in `config.py` and can be set through `.env`:

- maximum processing input length: `100000` characters (raw input is retained);
- maximum decoded representation length: `32000` characters;
- maximum decode depth: `3`;
- maximum representations: `24`;
- maximum candidates per representation: `32`;
- maximum candidates per representation: `32`.

Malformed Base64, hex, percent, and HTML encodings fail closed and leave the
original input available. The representation queue and candidate limits prevent
representation explosion and recursion errors.

## Transformation provenance and findings

Each representation carries a stable `rep-N` identifier, bounded text,
transformation provenance, and decode depth. Supported provenance IDs include
`NORMALIZED_UNICODE`, `ZERO_WIDTH_REMOVED`, `CONFUSABLES_NORMALIZED`,
`LEETSPEAK_NORMALIZED`, `SPACING_NORMALIZED`, `BASE64_DECODED`,
`HEX_DECODED`, `ROT13_DECODED`, `URL_DECODED`, and
`HTML_ENTITY_DECODED`. Findings report rule ID, category, severity,
description, representation ID, provenance, and short evidence; credential-
shaped evidence is redacted.

## Canonical path

`SecurityGateway.process` still performs normalization, `RiskAnalyzer` scans
the representation set with `RuleBasedDetector`, `RiskScorer` consumes the
existing rule/classifier/context components, and `PolicyEngine` remains the
Phase 4 policy implementation. No scorer weight, risk band, or policy
threshold was changed. The generic detector is also run over supplied
untrusted context as an additional capability signal; tool-output guard wiring
was not redesigned.

## Remaining weaknesses and Phase 6

The detector does not claim complete multilingual confusable coverage,
semantic paraphrase detection, arbitrary binary decoding, or universal
obfuscation resistance. False-positive risk remains for novel code/security
phrasing outside the tested defensive discussion controls. Real similarity,
embeddings, attack-corpus research, similarity threshold selection, and scorer
integration are deferred to Phase 6.

## Runtime and regression verification

- Phase 4 baseline: 29 tests passed.
- Phase 5 suite: 74 tests passed, 0 failed, 0 errors, 0 skipped (including the
  45 new detector-hardening tests).
- Targeted Ruff checks for all modified detector/config/test/evidence files:
  clean. Repository-wide Ruff retains the 95 pre-existing findings documented
  before Phase 5; no modified-file finding was introduced.
- FastAPI on the safe alternate host port `8001` (host port `8000` was already
  occupied): health returned HTTP 200/`HEALTHY`; benign analyze was `ALLOW`;
  plain and Base64-obfuscated attacks returned `BLOCK` with deterministic
  findings.
- Docker Compose build and startup succeeded. In-container health was
  `HEALTHY` and the encoded analyze smoke test returned `BLOCK`; containers and
  network were brought down cleanly afterward.
- Frontend source was not redesigned. `npm ci` and `npm run build` succeeded
  under the existing Node 22 environment (the existing Node 20 engine warning,
  two npm audit advisories, and Vite chunk-size warning remain).
