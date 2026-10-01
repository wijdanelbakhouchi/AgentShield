/**
 * The only browser boundary for AgentShield's canonical API.
 * Keeping request construction and error handling here prevents pages from
 * silently inventing data or using a legacy compatibility route.
 */

const viteEnv = import.meta.env || {};
const configuredBase = viteEnv.VITE_API_BASE_URL || (viteEnv.DEV ? '/api/v1' : 'http://localhost:8000/api/v1');
export const API_BASE_URL = configuredBase.replace(/\/$/, '');

// Fetch only the resources needed by the current page. A USER can chat
// without access to analyst telemetry or administrator approvals.
export const pageResources = (page) => {
  const resources = {
    overview: ['metrics', 'requests', 'events', 'alerts'],
    chat: [],
    requests: ['requests'],
    events: ['events'],
    traces: ['requests', 'events'],
    tools: ['requests', 'events'],
    approvals: ['approvals'],
    analytics: ['metrics'],
    experiments: [],
    settings: [],
  };
  return ['health', 'providersStatus', ...(resources[page] || resources.overview)];
};

// Development identity is resolved by the backend's server-owned subject/token
// mapping.  The frontend only forwards the configured identifier; it never
// sends a caller-selected role claim.  Keep this unset for the default USER
// identity, or configure it in an ignored .env.*.local file for HITL testing.
export const DEV_IDENTITY = Object.freeze({
  subject_id: String(viteEnv.VITE_AGENTSHIELD_DEV_SUBJECT_ID || '').trim() || null,
  auth_token: String(viteEnv.VITE_AGENTSHIELD_DEV_AUTH_TOKEN || '').trim() || null,
});

export class ApiError extends Error {
  constructor(message, { code = 'API_ERROR', requestId = null, status = 0 } = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.requestId = requestId;
    this.status = status;
  }
}

const parseBody = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return null;
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const request = async (path, options = {}) => {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs || 15000);
  const { timeoutMs: _timeoutMs, ...fetchOptions } = options;

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...fetchOptions,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(fetchOptions.body ? { 'Content-Type': 'application/json' } : {}),
        ...(DEV_IDENTITY.auth_token ? { Authorization: `Bearer ${DEV_IDENTITY.auth_token}` } : {}),
        ...(fetchOptions.headers || {}),
      },
    });
    const body = await parseBody(response);
    if (!response.ok) {
      const error = body?.error || {};
      const fallbackMessage = body?.detail || response.statusText || 'The API request failed.';
      throw new ApiError(error.message || fallbackMessage, {
        code: error.code || `HTTP_${response.status}`,
        requestId: error.request_id || body?.request_id || null,
        status: response.status,
      });
    }
    return body;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error?.name === 'AbortError') {
      throw new ApiError('The API request timed out. Check that the backend is reachable.', { code: 'TIMEOUT' });
    }
    const browserNetworkFailure = ['Failed to fetch', 'NetworkError when attempting to fetch resource.'].includes(error?.message);
    const message = browserNetworkFailure
      ? `Backend unavailable at ${API_BASE_URL}. Start the local AgentShield backend and retry.`
      : (error?.message || 'The API is unavailable.');
    throw new ApiError(message, { code: 'NETWORK_ERROR' });
  } finally {
    window.clearTimeout(timeout);
  }
};

const json = (body) => ({ method: 'POST', body: JSON.stringify(body) });

export const api = {
  health: () => request('/health'),
  metrics: () => request('/metrics'),
  requests: (limit = 100) => request(`/requests?limit=${Math.min(Math.max(limit, 1), 200)}`),
  requestLifecycle: (requestId) => request(`/requests/${encodeURIComponent(requestId)}`),
  events: ({ requestId = '', limit = 200 } = {}) => {
    const query = new URLSearchParams({ limit: String(Math.min(Math.max(limit, 1), 500)) });
    if (requestId) query.set('request_id', requestId);
    return request(`/events?${query.toString()}`);
  },
  alerts: (limit = 100) => request(`/alerts?limit=${Math.min(Math.max(limit, 1), 200)}`),
  providersStatus: (probe = false) => request(`/providers/status${probe ? '?probe=true' : ''}`),
  chat: (query, context = null) => request('/chat', { ...json({ query, context, source: 'react_control_center' }), timeoutMs: 60000 }),
  analyze: (prompt, context = null) => request('/analyze', { ...json({ prompt, context }), timeoutMs: 30000 }),
  approvals: () => request('/approvals'),
  approve: (approvalId) => request(`/approvals/${encodeURIComponent(approvalId)}/approve`, { ...json({}), timeoutMs: 60000 }),
  reject: (approvalId) => request(`/approvals/${encodeURIComponent(approvalId)}/reject`, { ...json({}), timeoutMs: 60000 }),
};

export default api;
