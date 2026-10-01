# Post-remediation end-to-end evaluation

`harness.py` executes the real LangGraph application path used by `/api/v1/chat`.
It records the actual yielded node trace, guarded tool events, guarded handoff
events, outcomes, and wall-clock timings. The baseline calls the same graph and
concrete tools with `security_enabled=False` as an experiment-only configuration;
it is not a production endpoint and does not hardcode a security result.

The independent `post_remediation_final_v1` dataset is frozen before execution
and is never used to tune thresholds, weights, rules, or the semantic corpus.
Provider-backed results remain pending until a runtime-verified external model
is available; deterministic fallback output is never reported as provider
evidence.

Run from the repository root:

```powershell
python -m experiments.e2e_evaluation.harness --warmup 1 --repetitions 3
```
