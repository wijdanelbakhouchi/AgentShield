# Phase 9 — context isolation validation

**DEVELOPMENT / MITIGATION VALIDATION — NOT FINAL TEST PERFORMANCE.**

## Position

Context isolation is an additional prompt-level data/instruction separation
mitigation. It is not a standalone security boundary, sandbox, or guarantee
that delimited content cannot influence an LLM. Phase 8 inspection remains the
security decision.

## Before

`hooks/context_isolator.py` wrapped text in `<untrusted_content>` and performed
limited substitutions for a small set of tags. It did not itself inspect or
score content. Existing callers included the Phase 8 tool-output guard and
agent fallback/prompt formatting. The main weakness was that ordinary markup
and new delimiter spellings could survive, and the old wrapper did not expose
source/trust metadata.

## After

The active order is:

```text
external result
→ UntrustedContentGuard / SecurityPipeline
→ ALLOW or distinct SANITIZE safe content
→ ContextIsolator
→ explicit external_data section
→ agent / LLM
```

`isolate_external_content` emits trusted application data-only guidance,
escaped `<external_data>`, source/name, and an explicit trust value. Boundary
tags (`external_data`, `untrusted_content`, `system`, `system_prompt`,
`user_input`, and related names) are replaced with neutral markers; remaining
markup is HTML-escaped. The original inspected text remains in the security
result for audit evidence. BLOCK and REVIEW never call the isolator; SANITIZE
passes only the distinct safe value.

Researcher prompts now place trusted application rules and the user task before
an explicitly labelled inspected external-data section. Planner, Writer, and
Finalizer label upstream material as untrusted agent data. `InterAgentGuard`
remains the downstream defense layer.

The API's optional `context` field is inspected as `user_upload` before graph
execution. Safe context is carried in `external_context`, separate from the
user task; blocked/review-required context stops the graph.

## Focused development tests

`tests/test_phase9_context_isolation.py` covers benign content, direct and
mixed attacks, closing-tag breakout, fake/nested system tags, Base64,
zero-width obfuscation, semantic fixture detection, quoted security
discussion, SANITIZE ordering, BLOCK prompt exclusion, REVIEW stopping,
isolator failure fail-closed, and the real guarded-tool → Researcher →
InterAgentGuard graph path. Existing context-isolator tests remain passing.

The isolation-only test intentionally shows that wrapping does not remove the
ordinary sentence “ignore all previous instructions”; the subsequent canonical
guard blocks that content before isolation. This is a structural limitation
demonstration, not a weakened runtime path.

## Evidence

- Phase 8 baseline: 111 passed.
- Focused Phase 9 + Phase 8/context-isolator tests: 30 passed.
- Full fallback/no-key regression after Phase 9: **123 passed**, 4 existing
  Pydantic deprecation warnings.
- No detector, normalization, semantic corpus/model/threshold, scoring,
  calibration, historical result, or held-out dataset changes.
- Runtime smoke: benign `/api/v1/chat` returned `COMPLETED` with two tool
  events and three correlated handoffs. A controlled delimiter-busting tool
  result returned `BLOCKED`, produced one tool event and zero handoffs, and the
  sentinel was absent from the final output. A malicious uploaded-context API
  request also returned `BLOCKED` with no sentinel in the final output.

## Remaining limitations

- Prompt-level delimiters cannot guarantee model non-influence.
- Delimiter escaping is limited to the implemented boundary vocabulary and
  ordinary markup handling; provider-specific prompt parsing may differ.
- Quoted-vs-operative language, multilingual content, semantic false
  negatives, and model nondeterminism remain possible.
- Document/retrieval runtime integration is not implemented.
- Phase 8's documented semantic false negative remains unchanged.
