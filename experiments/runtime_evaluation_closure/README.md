# Phase 16.5 — Runtime evaluation closure

This is an additive closure runner for the Phase 16 runtime gaps. It resolves
the exact pinned `sentence-transformers/all-MiniLM-L6-v2` snapshot when it is
present in the Hugging Face cache and records a real cosine score. Provider
evidence is written only after `ProviderService.validate()` returns
`runtime_verified=true` and `real_llm=true`.

Run from the repository root with the project virtual environment:

```powershell
$env:HF_HUB_OFFLINE = "1"
$env:TRANSFORMERS_OFFLINE = "1"
.venv\Scripts\python.exe -m experiments.runtime_evaluation_closure.run_closure --semantic-only
```

When an external provider is already configured and reachable, the same
command (without `--semantic-only`) runs the provider-backed Phase 15 matrix,
paired Phase 16 latency workload, and paired blinded quality-response packet.
Use `--repetitions` and `--warmup` only to choose the measurement size; the
frozen datasets and security configuration are never edited.

All closure files are under this directory. The original Phase 15/16 partial
`raw_results`, `processed_results`, figures, and reports remain untouched.
If no provider is available, `provider_verified_run/BLOCKER_REAL_PROVIDER.json`
is the authoritative blocker and all provider-dependent outputs remain
explicitly `PENDING_REAL_PROVIDER`.
