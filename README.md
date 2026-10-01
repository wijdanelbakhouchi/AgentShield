# AgentShield

AgentShield is a Master's research prototype for runtime mediation in a controlled multi-agent LLM workflow. It applies security controls at user ingress, untrusted-content ingestion, agent handoffs, tool boundaries, and the final user-visible response.

## Overview

The project investigates whether layered runtime mediation can reduce selected prompt-injection, tool-abuse, data-leakage, and inter-agent propagation outcomes without unacceptable benign-task or latency costs. It does not claim that prompt injection is solved or that the system is production-ready.

## Research problem and question

Multi-agent systems add trust boundaries beyond an initial user prompt: retrieved web content, documents, tool outputs, and agent-to-agent state can carry malicious instructions.

> To what extent can a layered runtime mediation architecture reduce selected prompt-injection and tool-abuse outcomes in a controlled multi-agent LLM workflow, while preserving benign-task utility and latency?

## Threat model

AgentShield addresses selected direct and indirect prompt injection, encoding and Unicode obfuscation, unsafe tool arguments, sandbox path escape, disposable database abuse, poisoned tool output, agent-handoff propagation, final-output credential leakage, and internal-instruction leakage.

It does not claim protection from arbitrary adaptive adversaries, image or scanned-document injections, production tenancy at scale, arbitrary external tools, or autonomous persistent memory.

## Architecture

```text
User / API client
    |
    +-- API edge: authentication, body limit, rate limit, CORS/security headers
    +-- SecurityPipeline: normalize -> detectors -> risk -> policy
    +-- LangGraph: researcher -> guard -> planner -> guard -> writer -> guard -> finalizer
    |      tools: identity + agent capability + schema + quota -> sandbox -> output isolation
    +-- final structured answer -> final-output DLP/instruction validation -> relevance validation
    +-- redacted operational telemetry and separate research traces
```

## Security layers

- **Ingress and normalization:** NFKC, zero-width removal, selected homoglyph and leetspeak normalization, and bounded Base64, hexadecimal, ROT13, URL, and HTML entity decoding.
- **Detection:** deterministic rules, context inspection, and a pinned local semantic detector. The LLM classifier is explicitly **advisory** and never overrides deterministic critical controls.
- **Policy:** `ALLOW`, `SANITIZE`, `REVIEW`, and `BLOCK`; credential leakage, internal-instruction exfiltration, and destructive code patterns can block independently of a blended score.
- **Degraded security:** semantic unavailability is recorded as `DEGRADED`; suspicious content is escalated and sensitive tools can be restricted rather than receiving a zero-risk score.
- **Provenance:** agent state carries origin chains, taint, and propagation depth for audited handoffs.
- **Tool broker:** active tools enforce server identity, user role, agent capability, strict schema, request budgets, sandbox containment, disposable SQLite access, approval for the destructive fixture, and mandatory output inspection.
- **External egress:** live web search is disabled by default; enabling it is an explicit configuration decision and each search has a hard client timeout. The offline fallback never echoes the original query.
- **Final output:** the formatted LLM response is scanned after finalizer generation for credentials, bearer tokens, internal metadata, instruction leakage, and echoed injection text.

## Multi-agent workflow

The active graph is `researcher -> planner -> writer -> finalizer`. Every handoff is inspected by `InterAgentGuard`. The researcher is the only workflow agent with active research/document capabilities; planner, writer, and finalizer have no tool capabilities. Minimal conversation history is scoped by authenticated subject and reintroduced only as explicitly marked data after final-output validation.

## Installation

### Requirements

- Python 3.11.4 or later
- Node.js 20.x and npm 10.x
- Docker Engine and Docker Compose v2 for the optional container workflow

### Run without Docker

```powershell
git clone <repository-url>
cd Agent_Shield
Copy-Item .env.example .env

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
python -m alembic upgrade head
python -m scripts.run_backend
```

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

On Linux/macOS, activate with `source .venv/bin/activate`.

### Environment variables

Copy `.env.example`; never commit `.env`. In production set `AGENTSHIELD_ENV=production`, `AGENTSHIELD_DEV_AUTH_ENABLED=false`, `AGENTSHIELD_DEV_ANONYMOUS_DEMO=false`, `AGENTSHIELD_API_AUTH_REQUIRED=true`, and an environment-secret `AGENTSHIELD_API_TOKENS` JSON mapping. Development identities are rejected in production.

For graded enforcement, set `POLICY_MODE=banded` (the supplied template does) and review the MEDIUM/HIGH/CRITICAL action values. The compatibility default remains score-threshold enforcement for the frozen historical calibration; critical leakage/destructive findings still override it.

Provider keys are environment secrets. A real-provider research run must set a provider key and `LLM_FALLBACK_ENABLED=false`; fallback output is never real-provider evidence.

### Run with Docker

```powershell
Copy-Item .env.example .env
docker compose build
docker compose up -d
curl http://127.0.0.1:8000/api/v1/health
docker compose down
```

Compose binds services to loopback by default, runs the backend as a non-root user, keeps SQLite in a named volume, and applies read-only filesystem/capability restrictions. Docker validation still depends on the host runtime.

## Tests and quality checks

```powershell
python -m compileall -q agents analyzer api gateway hooks policy scoring security storage providers experiments
python -m pytest -m "not real_provider" -q
python -m ruff check .
python -m pip_audit -r requirements.txt

cd frontend
npm ci
npm test
npm run build
npm audit --audit-level=high
```

### Local dashboard telemetry

Chat is available to the default development USER identity. Operational pages
such as Overview, Requests, Events, and Analytics require the development
ANALYST fixture. For a local Docker demo, create `frontend/.env.local` (it is
ignored by Git) with:

```dotenv
VITE_API_BASE_URL=http://localhost:8000/api/v1
VITE_AGENTSHIELD_DEV_AUTH_TOKEN=dev-analyst-token
```

Then rebuild the frontend with `docker compose up -d --build frontend` and
refresh the dashboard. This fixture is for local development only; configure a
real server-owned token mapping for production.

## E2E experiment

The real graph harness executes the same LangGraph nodes, tool broker, handoff guards, and final-output boundary used by the runtime. It stores JSON/JSONL payload, normalization evidence, policy decision, handoffs, tools, final output, output-security disposition, behavioral attack outcome, latency, provider metadata, and errors.

```powershell
$env:LLM_PROVIDER = "groq"
$env:GROQ_API_KEY = "<environment-secret>"
$env:LLM_FALLBACK_ENABLED = "false"
python -m experiments.e2e_evaluation.harness --warmup 1 --repetitions 3 --artifact-root experiments/e2e_evaluation/results/run_local
```

The runner stops rather than silently emitting fallback results when a provider completion is unavailable. Do not tune active rules, thresholds, or the semantic corpus on the frozen E2E dataset.

## Results and limitations

Historical component-level and deterministic evaluation material is retained under `experiments/` for reproducibility. Generated run outputs are intentionally kept out of the public repository unless they are needed as processed thesis evidence. Only a completed run with `real_llm=true`, `fallback=false`, and the frozen dataset may support real-provider end-to-end claims.

The defensible thesis claim is that AgentShield **implements and evaluates a layered runtime mediation architecture under specified conditions**. It does not support claims of universal attack prevention, production-grade security, zero false positives, or hallucination prevention.

## Repository structure

```text
agents/                 LangGraph agent nodes
analyzer/               deterministic, context, semantic, and advisory analysis
api/                    FastAPI service and edge controls
gateway/                canonical normalization and interception
hooks/                  handoff, tool, and untrusted-content boundaries
policy/                 severity and capability-aware policy decisions
security/               runtime pipeline, tools, provenance, output validation
storage/ and logging/   SQLite audit persistence and redacted telemetry
experiments/            frozen datasets, harnesses, and processed research evidence
frontend/               React operational dashboard
tests/                  unit, integration, security, and E2E-oriented tests
```

## Thesis scope

AgentShield is a research prototype emphasizing reproducible evidence, explicit limitations, and defense-in-depth boundaries. See `experiments/e2e_evaluation/README.md` for real-provider experiment rules.
