# Phase 11 HITL approval development report

**DEVELOPMENT / INTEGRATION EVIDENCE — NOT FINAL SECURITY PERFORMANCE**

- `delete_temp_record` is centrally marked approval-required.  A server-RBAC
  authorized request returns `REQUIRES_APPROVAL`, persists a `PENDING`
  `ToolApproval`, and does not invoke the sandbox implementation.
- Pending records use canonical JSON arguments and retain `approval_id`,
  `request_id`, `tool_call_id`, requester, resolved role, decision timestamps,
  and a practical `APPROVAL_TTL_SECONDS` expiry.
- The decision routes resolve identity from the Phase 10 development
  server-side context.  Request-body `user_role` is ignored; only ADMIN can
  approve or reject.
- Approval resumes the exact persisted request after active-tool, identity,
  RBAC, and state revalidation.  No caller-supplied arguments are accepted by
  the decision schema.  Conditional PENDING transitions prevent replay and
  cross-request substitution.
- Reject and expiry prevent execution.  Invalid state, DB/identity/request
  revalidation errors, missing tools, and output-guard failures fail closed.
- Each lifecycle transition is persisted in `approval_audit_logs`; tool output
  remains mandatory Phase 8 `UntrustedContentGuard` input after approval.
