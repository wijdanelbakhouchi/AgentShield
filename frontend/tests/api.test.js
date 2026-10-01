import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ApiError, api, pageResources } from '../src/services/api.js';
import { responseDecision } from '../src/services/decision.js';

test('chat UI does not render internal execution status metadata', () => {
  const source = readFileSync(new URL('../src/App.jsx', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /Execution:\s*\{/);
  assert.doesNotMatch(source, /<dt>Execution<\/dt>/);
});

test('review and failed responses never display ALLOWED', () => {
  for (const status of ['REVIEW_REQUIRED', 'FAILED', 'BLOCKED']) {
    const decision = responseDecision({ status, policy_decision: { action: 'ALLOW' } });
    assert.notEqual(decision.tone, 'success');
    assert.notEqual(decision.label, 'ALLOWED');
  }
  assert.equal(responseDecision({ status: 'COMPLETED', policy_decision: { action: 'REVIEW' } }).label, 'REVIEW REQUIRED');
  assert.equal(responseDecision({ policy_decision: { action: 'SANITIZE' } }).label, 'SANITIZED');
  assert.equal(responseDecision({ status: 'COMPLETED', policy_decision: { action: 'ALLOW' }, final_output: { output_security_decision: 'BLOCK' } }).label, 'OUTPUT BLOCKED');
  assert.equal(responseDecision({ status: 'COMPLETED', policy_decision: { action: 'ALLOW' }, execution: { status: 'PROVIDER_ERROR' } }).label, 'FAILED');
  assert.equal(responseDecision({ status: 'BLOCKED', policy_decision: { action: 'ALLOW' }, final_output: { provider_metadata: { mode: 'provider_error' } } }).label, 'FAILED');
  assert.equal(responseDecision({ status: 'BLOCKED', policy_decision: { action: 'ALLOW' }, execution: { status: 'SECURITY_BLOCKED' } }).label, 'FAILED');
  assert.equal(responseDecision({}).label, 'UNKNOWN');
  assert.equal(responseDecision({ status: 'COMPLETED', policy_decision: { action: 'ALLOW' } }).label, 'ALLOWED');
});

global.window = { setTimeout, clearTimeout };

test('live chat refresh does not request privileged telemetry or approvals', async () => {
  const calls = [];
  global.fetch = async (url) => {
    calls.push(new URL(url).pathname);
    return new Response('{}', { headers: { 'content-type': 'application/json' } });
  };
  await Promise.all(pageResources('chat').map((name) => api[name]()));
  assert.deepEqual(calls, ['/api/v1/health', '/api/v1/providers/status']);
});

test('protected pages still request their own authorized resources', () => {
  assert.ok(pageResources('approvals').includes('approvals'));
  assert.ok(pageResources('requests').includes('requests'));
  assert.ok(!pageResources('overview').includes('approvals'));
});

test('canonical metrics call uses the metrics endpoint and returns JSON', async () => {
  const calls = [];
  global.fetch = async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ overview: { total_requests: 3 } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const result = await api.metrics();
  assert.equal(result.overview.total_requests, 3);
  assert.match(calls[0], /\/api\/v1\/metrics$/);
});

test('API errors preserve the structured request identifier without exposing a stack', async () => {
  global.fetch = async () => new Response(JSON.stringify({ error: { code: 'DB_UNAVAILABLE', message: 'Database unavailable', request_id: 'req-123' } }), {
    status: 503,
    headers: { 'content-type': 'application/json' },
  });

  await assert.rejects(api.health(), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, 'DB_UNAVAILABLE');
    assert.equal(error.requestId, 'req-123');
    assert.equal(error.message, 'Database unavailable');
    return true;
  });
});

test('chat uses the canonical workflow and renders the server decision envelope unchanged', async () => {
  let call;
  global.fetch = async (url, options) => {
    call = { url: String(url), options };
    return new Response(JSON.stringify({ request_id: 'req-blocked', status: 'BLOCKED', policy_decision: { action: 'BLOCK' } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const result = await api.chat('unsafe prompt', 'untrusted context');
  assert.equal(result.policy_decision.action, 'BLOCK');
  assert.match(call.url, /\/api\/v1\/chat$/);
  assert.deepEqual(JSON.parse(call.options.body), {
    query: 'unsafe prompt',
    context: 'untrusted context',
    source: 'react_control_center',
  });
});

test('approval listing uses the configured bearer header and no identity query fields', async () => {
  let call;
  global.fetch = async (url, options) => {
    call = { url: String(url), options };
    return new Response(JSON.stringify({ approvals: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  await api.approvals();
  const parsed = new URL(call.url);
  assert.equal(parsed.pathname, '/api/v1/approvals');
  assert.equal(parsed.searchParams.has('auth_token'), false);
  assert.equal(parsed.searchParams.has('user_role'), false);
  assert.equal(call.options.body, undefined);
});

test('frontend approve and reject send empty bodies; identity is header-owned', async () => {
  const calls = [];
  global.fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    return new Response(JSON.stringify({ approval_id: 'approval-1', status: 'COMPLETED' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  await api.approve('approval-1');
  await api.reject('approval-2');
  assert.match(calls[0].url, /\/api\/v1\/approvals\/approval-1\/approve$/);
  assert.deepEqual(JSON.parse(calls[0].options.body), {});
  assert.match(calls[1].url, /\/api\/v1\/approvals\/approval-2\/reject$/);
  assert.deepEqual(JSON.parse(calls[1].options.body), {});
  assert.equal(calls[0].options.body.includes('user_role'), false);
  assert.equal(calls[1].options.body.includes('user_role'), false);
});

test('providersStatus forwards probe query parameter when requested', async () => {
  const calls = [];
  global.fetch = async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ active_provider: 'groq', mode: 'provider', real_llm: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  await api.providersStatus();
  assert.match(calls[0], /\/api\/v1\/providers\/status$/);

  await api.providersStatus(true);
  assert.match(calls[1], /\/api\/v1\/providers\/status\?probe=true$/);
});
