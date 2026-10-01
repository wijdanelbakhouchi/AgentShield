// A later boundary can stop a request that ingress allowed. Never infer
// permission merely from the absence of a BLOCK decision.
export function responseDecision(response = {}) {
  // The ingress policy action is the authoritative user-request security
  // decision. Execution statuses (including downstream handoff stops and
  // provider failures) must not turn an ALLOW into a misleading BLOCKED UI.
  const policyAction = String(response.policy_decision?.action || '').toUpperCase();
  if (['BLOCK', 'DENY', 'DENIED', 'REJECT', 'REJECTED'].includes(policyAction)) {
    return { label: 'BLOCKED', tone: 'danger' };
  }
  if (['REVIEW', 'REVIEW_REQUIRED', 'REQUIRES_APPROVAL', 'PENDING'].includes(policyAction)) {
    return { label: 'REVIEW REQUIRED', tone: 'warning' };
  }
  if (['SANITIZE', 'SANITIZED'].includes(policyAction)) {
    return { label: 'SANITIZED', tone: 'warning' };
  }

  const executionStatus = String(response.execution?.status || response.status || '').toUpperCase();
  const providerMode = String(response.final_output?.provider_metadata?.mode || '').toUpperCase();
  if (executionStatus === 'PROVIDER_ERROR' || providerMode === 'PROVIDER_ERROR') {
    return { label: 'FAILED', tone: 'danger' };
  }

  const outputDecision = String(response.final_output?.output_security_decision || '').toUpperCase();
  if (['BLOCK', 'DENY', 'DENIED', 'REJECT', 'REJECTED'].includes(outputDecision)) {
    return policyAction === 'ALLOW'
      ? { label: 'OUTPUT BLOCKED', tone: 'danger' }
      : { label: 'BLOCKED', tone: 'danger' };
  }
  if (['REVIEW', 'REVIEW_REQUIRED', 'REQUIRES_APPROVAL', 'PENDING'].includes(outputDecision)) {
    return { label: 'REVIEW REQUIRED', tone: 'warning' };
  }

  if (['SECURITY_REVIEW', 'REVIEW_REQUIRED'].includes(executionStatus)) {
    return { label: 'REVIEW REQUIRED', tone: 'warning' };
  }
  if (['PROVIDER_ERROR', 'PROVIDER_TIMEOUT', 'PROVIDER_RATE_LIMIT', 'AGENT_ERROR', 'SECURITY_BLOCKED', 'BLOCKED', 'FAILED', 'ERROR'].includes(executionStatus)) {
    return { label: 'FAILED', tone: 'danger' };
  }
  if (['ALLOW', 'ALLOWED', 'COMPLETED'].includes(policyAction)) {
    return { label: 'ALLOWED', tone: 'success' };
  }
  return { label: 'UNKNOWN', tone: 'neutral' };
}
