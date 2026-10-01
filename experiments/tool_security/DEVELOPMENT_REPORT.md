# AgentShield Phase 10 Tool Security

**DEVELOPMENT / INTEGRATION EVIDENCE — NOT FINAL SECURITY PERFORMANCE**

## Scope

Phase 10 replaces the misleading privileged-tool behavior with one canonical
`SecureToolExecutor`.  It preserves the frozen Phase 8 output guard and adds
server-side development identity resolution, centralized RBAC, argument
security, disposable resources, and correlated telemetry.  No detector,
normalizer, semantic model/corpus/threshold, scorer, policy threshold,
calibration result, inter-agent guard, context isolator, or held-out artifact
was changed.

## Tool inventory

| Tool | Status | Scope |
| --- | --- | --- |
| `search_web` / `web_search_tool` | ACTIVE / compatibility alias | bounded web provider with offline fallback |
| `read_document` | ACTIVE | dedicated temporary sandbox only |
| `query_test_db` | ACTIVE | parameterized disposable SQLite reads |
| `mock_database_tool` | ACTIVE / compatibility alias | same disposable parameterized read; no production handle |
| `write_temp_file`, `read_temp_file` | ACTIVE | dedicated temporary sandbox only |
| `delete_temp_record` | ACTIVE | ADMIN-only `temp-*` records |
| `system_cmd`, `tool_delete_database` | LEGACY / SIMULATED / DENIED | former UNSAFE privileged behavior; never dispatched |

The old string-returning privileged implementations were classified
`UNSAFE/SIMULATED` during the audit and are no longer in the active registry.

## Identity and RBAC evidence

`ServerIdentityResolver` maps server-owned subjects/tokens to `USER`,
`ANALYST`, or `ADMIN`.  `user_role`/`role` values from a request or tool
arguments are ignored and removed before implementation dispatch.  The
central policy permits safe search/read to USER, test DB and temp-file
operations to ANALYST, and controlled temp-record deletion to ADMIN.

Focused tests prove USER denial, ANALYST query access, ADMIN disposable delete,
fake ADMIN request-body/argument escalation denial, and zero implementation
calls on denied requests.

## Argument and resource safety

The existing canonical ToolGuard scanner is the argument boundary.  It blocks
SQL injection, shell metacharacters/imports, oversized strings, absolute paths,
path traversal (including URL-encoded traversal), and role override attempts
before execution.  `ToolSandbox.resolve_path` independently enforces that the
resolved path remains below the dedicated temporary root.  The SQLite test DB
uses parameterized statements and rejects non-`temp-*` deletes.

## Output and telemetry evidence

Every successful implementation result is sent through Phase 8
`UntrustedContentGuard`; poisoned output is blocked before agent consumption.
Each attempt emits `ToolExecutionEvent`/`ToolLog` metadata with
`request_id`, `tool_call_id`, `subject_id`, `resolved_role`, authorization,
argument, execution, and output decisions, timestamp, and latency.  Audit
arguments are redacted/truncated for credential-like values and raw output is
never stored.

## Active bypass audit

The researcher production node now creates `ToolRequest` objects and invokes
`SecureToolExecutor` for both tool calls.  Direct implementation calls remain
only in development tests and inside the executor's registered dispatch.  No
active graph/API path calls an implementation around ToolGuard.

## Limitations

Authentication is explicitly development authentication / server-side identity
context, not production-grade authentication.  The sandbox is a local
process/filesystem boundary for disposable resources, not an OS/container
security boundary.  Future tools must register with the same executor; direct
implementation calls are acceptable only in development tests.
