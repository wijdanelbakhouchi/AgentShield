# Phase 16 — Performance, Response Quality, and Reproducible Results

This package measures paired full-request latency using the same bounded
researcher → planner → writer → finalizer task contract.  The baseline disables
AgentShield interventions through configuration; both variants retain an inert
temporary SQLite sandbox and never execute shell commands, network requests,
production database operations, or real secrets.

## Reproduction (PowerShell)

From the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\python.exe -m experiments.performance_quality.freeze_system
.\.venv\Scripts\python.exe -m experiments.performance_quality.run_performance --repetitions 25 --warmup 2
.\.venv\Scripts\python.exe -m experiments.performance_quality.compute_performance
.\.venv\Scripts\python.exe -m experiments.performance_quality.run_quality
.\.venv\Scripts\python.exe -m experiments.performance_quality.compute_quality
.\.venv\Scripts\python.exe -m experiments.performance_quality.generate_figures
.\.venv\Scripts\python.exe -m experiments.performance_quality.generate_report
```

`freeze_system` must run before any measurement.  It verifies the Phase 15
dataset identity and records the exact security weights, policy threshold,
semantic model/revision/threshold, corpus hash, tool policy, graph topology,
Python runtime, provider status, and seed.  Re-running it after artifacts exist
is allowed only when the protected snapshot is identical.

## Interpretation

The performance runner writes one raw JSON object per steady-state request for
both configurations.  Warmups and cold sandbox initialization are reported
separately.  Missing or unavailable stages are `null`, never fabricated zeroes.
The quality runner uses a blinded human A/B rubric and refuses to score
`DEMO_FALLBACK` or any row without a runtime-verified provider; therefore the
current no-provider run produces pending quality records and no quality figure.

Processed summaries and all figures are generated from raw artifacts.  The
report reads Phase 15 security metrics from its processed JSON files rather than
copying values into Phase 16 code.

