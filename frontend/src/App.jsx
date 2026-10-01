import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bot,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Database,
  FileSearch,
  Gauge,
  GitBranch,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  Menu,
  MessageSquare,
  RefreshCw,
  Search,
  Send,
  Settings2,
  Shield,
  ShieldAlert,
  TerminalSquare,
  X,
  XCircle,
  Zap,
} from 'lucide-react';
import api, { API_BASE_URL, DEV_IDENTITY, pageResources } from './services/api';
import { responseDecision } from './services/decision';

const NAVIGATION = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'chat', label: 'Live Chat', icon: MessageSquare },
  { id: 'requests', label: 'Requests', icon: ListChecks },
  { id: 'events', label: 'Security Events', icon: FileSearch },
  { id: 'traces', label: 'Agent Traces', icon: GitBranch },
  { id: 'tools', label: 'Tool Activity', icon: TerminalSquare },
  { id: 'approvals', label: 'Approvals', icon: LockKeyhole },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'experiments', label: 'Experiments', icon: Gauge },
  { id: 'settings', label: 'Settings', icon: Settings2 },
];

const PAGE_IDS = new Set(NAVIGATION.map(({ id }) => id));

function pageFromLocation() {
  if (typeof window === 'undefined') return 'overview';
  const value = window.location.hash.replace(/^#\/?/, '').split('/')[0];
  return PAGE_IDS.has(value) ? value : 'overview';
}

const numberValue = (value, digits = 0) => {
  if (value === null || value === undefined || value === '') return 'No data yet';
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(digits) : String(value);
};

const textValue = (value, fallback = 'N/A') => (
  value === null || value === undefined || value === '' ? fallback : String(value)
);

const dateValue = (value) => {
  if (!value) return 'N/A';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};

const arrayValue = (value, key) => {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value[key])) return value[key];
  return [];
};

const decisionTone = (decision) => {
  const value = String(decision || '').toUpperCase();
  if (value.includes('BLOCK') || value.includes('DENY') || value.includes('REJECT')) return 'danger';
  if (value.includes('REVIEW') || value.includes('WARN') || value.includes('SANIT')) return 'warning';
  if (value.includes('ALLOW') || value.includes('PASS') || value.includes('COMPLETE')) return 'success';
  return 'neutral';
};

const riskTone = (level) => {
  const value = String(level || '').toUpperCase();
  if (value === 'CRITICAL' || value === 'HIGH') return 'danger';
  if (value === 'MEDIUM') return 'warning';
  if (value === 'LOW') return 'success';
  return 'neutral';
};

function Badge({ children, tone = 'neutral' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function MetricCard({ label, value, detail, icon: Icon, tone = 'blue' }) {
  return (
    <article className="metric-card">
      <div className="metric-heading"><span>{label}</span><Icon size={17} className={`icon-${tone}`} /></div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </article>
  );
}

function EmptyState({ title = 'No data yet', detail = 'The API has not returned records for this view.' }) {
  return <div className="empty-state"><Database size={20} /><strong>{title}</strong><span>{detail}</span></div>;
}

function ErrorState({ error, onRetry }) {
  if (!error) return null;
  return (
    <div className="error-banner" role="alert">
      <AlertTriangle size={18} />
      <div><strong>{error.message || 'The API is unavailable.'}</strong><span>{error.requestId ? `Request ID: ${error.requestId}` : 'No request ID was returned.'}</span></div>
      {onRetry && <button className="button button-subtle" onClick={onRetry}><RefreshCw size={15} /> Retry</button>}
    </div>
  );
}

function resolveProviderState(provider, error) {
  if (error && !provider) {
    return {
      state: 'FETCH_ERROR',
      label: 'Provider status unavailable',
      detail: 'Live provider verification requires a reachable backend.',
      tone: 'danger',
      isFallback: true,
      isVerified: false,
      isConfigured: false,
    };
  }
  if (!provider) {
    return {
      state: 'FETCH_ERROR',
      label: 'Connecting…',
      detail: 'Waiting for provider status from backend.',
      tone: 'neutral',
      isFallback: false,
      isVerified: false,
      isConfigured: false,
    };
  }

  const activeStatus = String(provider.active_status || '').toLowerCase();
  const mode = String(provider.mode || '').toLowerCase();
  const activeProvider = textValue(provider.active_provider, 'None');
  const providerDetails = provider.providers?.[provider.active_provider] || {};
  const model = providerDetails.model || provider.model || '';
  const modelLabel = model ? ` (${model})` : '';

  if (provider.real_llm === true || activeStatus === 'ready' || providerDetails.runtime_verified === true) {
    return {
      state: 'VERIFIED',
      label: `${activeProvider}${modelLabel} · Verified`,
      detail: `Verified live provider active. Responses generated by ${activeProvider}.`,
      tone: 'success',
      isFallback: false,
      isVerified: true,
      isConfigured: true,
    };
  }

  if (activeStatus === 'configured_but_unverified' || (mode === 'provider' && providerDetails.configured)) {
    return {
      state: 'CONFIGURED_UNVERIFIED',
      label: `${activeProvider}${modelLabel} · Configured`,
      detail: `Configured with credentials. Verification occurs automatically on first prompt or explicit probe.`,
      tone: 'info',
      isFallback: false,
      isVerified: false,
      isConfigured: true,
    };
  }

  if (activeStatus === 'demo_fallback' || mode === 'demo') {
    if (providerDetails.error || provider.fallback_reason) {
      const reason = providerDetails.error || provider.fallback_reason;
      return {
        state: 'FALLBACK',
        label: 'Demo / Fallback Mode',
        detail: `Provider call failed (${reason}). Operating with local safe template responses.`,
        tone: 'warning',
        isFallback: true,
        isVerified: false,
        isConfigured: false,
      };
    }
    return {
      state: 'FALLBACK',
      label: 'Demo / Fallback Mode',
      detail: 'No external LLM provider configured. Operating with local deterministic responses.',
      tone: 'neutral',
      isFallback: true,
      isVerified: false,
      isConfigured: false,
    };
  }

  if (activeStatus === 'not_configured' || activeStatus === 'unavailable') {
    return {
      state: 'UNAVAILABLE',
      label: 'No Provider Configured',
      detail: 'No external LLM provider configured. Security analysis remains fully functional.',
      tone: 'neutral',
      isFallback: true,
      isVerified: false,
      isConfigured: false,
    };
  }

  return {
    state: 'CONFIGURED_UNVERIFIED',
    label: `${activeProvider} · Configured`,
    detail: 'Ready to verify on first prompt.',
    tone: 'info',
    isFallback: false,
    isVerified: false,
    isConfigured: true,
  };
}

function ProviderBadge({ provider, error }) {
  const info = resolveProviderState(provider, error);
  let Icon = Zap;
  if (info.state === 'VERIFIED') Icon = CheckCircle2;
  else if (info.state === 'CONFIGURED_UNVERIFIED') Icon = Bot;
  else if (info.state === 'FALLBACK') Icon = ShieldAlert;
  else if (info.state === 'FETCH_ERROR') Icon = AlertTriangle;
  else Icon = Shield;

  return (
    <span className={`provider-badge provider-badge-${info.tone}`} title={info.detail}>
      <Icon size={13} />
      <span>{info.label}</span>
    </span>
  );
}

function ChatProviderNotice({ provider, error }) {
  const info = resolveProviderState(provider, error);
  if (info.state === 'VERIFIED') {
    return null;
  }
  if (info.state === 'CONFIGURED_UNVERIFIED') {
    return (
      <div className="chat-provider-notice chat-notice-info">
        <Bot size={15} />
        <div>
          <strong>{info.label} (Pending Verification)</strong>
          <span>First prompt will verify live connection to {textValue(provider?.active_provider)}. Safe fallback is enabled if provider fails.</span>
        </div>
      </div>
    );
  }
  return (
    <div className="chat-provider-notice chat-notice-fallback">
      <ShieldAlert size={15} />
      <div>
        <strong>{info.label}</strong>
        <span>{info.detail} Security gateway and policy enforcement remain 100% active.</span>
      </div>
    </div>
  );
}

function ProviderBanner({ provider, error }) {
  const info = resolveProviderState(provider, error);
  if (info.state === 'VERIFIED') {
    return (
      <div className="provider-banner provider-live">
        <CheckCircle2 size={18} />
        <div>
          <strong>Verified external provider active</strong>
          <span>{info.detail}</span>
        </div>
        <code>{textValue(provider?.active_provider)} / {textValue(provider?.mode)}</code>
      </div>
    );
  }
  if (info.state === 'CONFIGURED_UNVERIFIED') {
    return (
      <div className="provider-banner provider-configured">
        <Bot size={18} />
        <div>
          <strong>External provider configured (unverified)</strong>
          <span>{info.detail}</span>
        </div>
        <code>{textValue(provider?.active_provider)} / configured</code>
      </div>
    );
  }
  if (info.state === 'FETCH_ERROR') {
    return (
      <div className="provider-banner provider-unknown">
        <ShieldAlert size={18} />
        <div>
          <strong>Provider status unavailable</strong>
          <span>{info.detail}</span>
        </div>
      </div>
    );
  }
  return (
    <div className="provider-banner provider-fallback">
      <ShieldAlert size={18} />
      <div>
        <strong>{info.label}</strong>
        <span>{info.detail}</span>
      </div>
      <code>{textValue(provider?.active_provider)} / {textValue(provider?.mode)}</code>
    </div>
  );
}

function PageHeader({ title, description, onRefresh, refreshing }) {
  return <div className="page-header"><div><p className="eyebrow">AGENTSHIELD CONTROL CENTER</p><h2>{title}</h2><p>{description}</p></div><button className="button button-subtle" onClick={onRefresh} disabled={refreshing}><RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh</button></div>;
}

function Overview({ snapshot, onRefresh, refreshing, onSelectRequest }) {
  const overview = snapshot?.metrics?.overview || {};
  const risk = snapshot?.metrics?.risk_distribution || {};
  const rules = arrayValue(snapshot?.metrics?.top_triggered_rules);
  const events = snapshot?.events || [];
  const alerts = snapshot?.alerts || [];
  const handoffCount = events.filter((event) => String(event?.event_type || '').toUpperCase() === 'HANDOFF_SECURITY').length;
  const toolCount = events.filter((event) => String(event?.event_type || '').toUpperCase().startsWith('TOOL_')).length;
  const recent = arrayValue(snapshot?.metrics?.recent_logs);
  return <>
    <PageHeader title="Overview" description="Real persisted security telemetry from the canonical AgentShield API." onRefresh={onRefresh} refreshing={refreshing} />
    <div className="metric-grid">
      <MetricCard label="Total requests" value={numberValue(overview.total_requests)} detail="Persisted security logs" icon={Activity} />
      <MetricCard label="Blocked" value={numberValue(overview.blocked_requests)} detail={overview.block_rate_percent === undefined ? 'Block rate not exposed' : `${numberValue(overview.block_rate_percent, 1)}% of persisted requests`} icon={ShieldAlert} tone="red" />
      <MetricCard label="Allowed" value={numberValue(overview.allowed_requests)} detail="Only shown when API exposes an aggregate" icon={CheckCircle2} tone="green" />
      <MetricCard label="Review" value={numberValue(overview.review_requests)} detail="Only shown when API exposes an aggregate" icon={AlertTriangle} tone="amber" />
      <MetricCard label="Average risk" value={numberValue(overview.avg_risk_score, 3)} detail="SecurityLog risk score" icon={Zap} tone="amber" />
      <MetricCard label="Alerts" value={alerts.length ? numberValue(alerts.length) : numberValue(overview.alert_count)} detail="Records returned by alerts API" icon={ShieldAlert} tone="red" />
      <MetricCard label="Tool events" value={toolCount ? numberValue(toolCount) : 'No data yet'} detail="Observed in the loaded event window" icon={TerminalSquare} />
      <MetricCard label="Handoff events" value={handoffCount ? numberValue(handoffCount) : 'No data yet'} detail="Observed in the loaded event window" icon={GitBranch} />
    </div>
    <div className="content-grid two-column">
      <section className="panel"><div className="section-heading"><div><h3>Risk distribution</h3><p>Counts returned by the metrics endpoint.</p></div><Shield size={18} /></div><Distribution data={risk} /></section>
      <section className="panel"><div className="section-heading"><div><h3>Triggered rules</h3><p>Only persisted rule aggregates are shown.</p></div><FileSearch size={18} /></div>{rules.length ? <RuleBars rules={rules} /> : <EmptyState title="No triggered rules" detail="No rule aggregate was returned." />}</section>
    </div>
    <section className="panel"><div className="section-heading"><div><h3>Recent requests</h3><p>Prompt content is intentionally not returned by the requests API.</p></div><ChevronRight size={18} /></div>{recent.length ? <RequestTable rows={recent} onSelect={onSelectRequest} compact /> : <EmptyState />}</section>
  </>;
}

function Distribution({ data }) {
  const levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const total = levels.reduce((sum, level) => sum + Number(data?.[level] || 0), 0);
  if (!total) return <EmptyState title="No risk observations" detail="The API returned an empty risk distribution." />;
  return <div className="distribution">{levels.map((level) => { const value = Number(data[level] || 0); const width = Math.max(3, (value / total) * 100); return <div className="distribution-row" key={level}><div className="distribution-label"><span>{level}</span><strong>{value}</strong></div><div className="bar-track"><div className={`bar-fill ${riskTone(level)}`} style={{ width: `${width}%` }} /></div></div>; })}<div className="chart-caption">Total observations: {total}</div></div>;
}

function RuleBars({ rules }) {
  const max = Math.max(...rules.map((item) => Number(item.count || 0)), 1);
  return <div className="distribution">{rules.map((item) => { const value = Number(item.count || 0); return <div className="distribution-row" key={item.rule_flag}><div className="distribution-label"><span className="truncate">{textValue(item.rule_flag)}</span><strong>{value}</strong></div><div className="bar-track"><div className="bar-fill danger" style={{ width: `${Math.max(3, (value / max) * 100)}%` }} /></div></div>; })}</div>;
}

function cleanAssistantAnswer(response) {
  if (!response) return 'No response was returned.';

  const providerMetadata = response.final_output?.provider_metadata || {};
  if (response.execution?.status === 'PROVIDER_ERROR' || providerMetadata.mode === 'provider_error') {
    const provider = textValue(providerMetadata.failed_provider || providerMetadata.provider, 'configured provider');
    const reason = textValue(providerMetadata.error, 'provider call failed');
    return `AgentShield allowed this request, but the LLM provider is unavailable (${provider}: ${reason}). Try again after checking the provider configuration.`;
  }

  const decision = responseDecision(response);
  if (decision.label === 'OUTPUT BLOCKED') {
    return 'The request passed the initial security check, but the generated answer was withheld by final-output security validation.';
  }
  if (decision.label === 'BLOCKED') {
    return 'This request was blocked by AgentShield because it was detected as potentially malicious.';
  }
  if (decision.label === 'REVIEW REQUIRED') {
    return response.final_output?.reason || response.policy_decision?.reason || 'Execution paused because security review is required.';
  }
  if (response.execution?.status === 'SECURITY_BLOCKED') {
    return 'The request passed the initial security check, but a downstream agent handoff was blocked by AgentShield.';
  }

  if (decision.label === 'FAILED') {
    return response.final_output?.error || 'The workflow failed. This request did not complete successfully.';
  }

  const output = response.final_output || {};
  let raw = output.detailed_content || output.summary || output.content || '';

  if (!raw && output.error) {
    if (String(output.error).toUpperCase().includes('BLOCK') || String(output.error).includes('Policy Engine')) {
      return 'This request was blocked by AgentShield because it was detected as potentially malicious.';
    }
    return textValue(output.error);
  }

  if (!raw && response.policy_decision?.reason) {
    return textValue(response.policy_decision.reason);
  }

  let text = String(raw || '');

  // Strip internal security headers, tags, and inspection instructions
  text = text.replace(/TRUSTED APPLICATION INSTRUCTION:[^\n]*\n?/gi, '');
  text = text.replace(/<\/?(?:untrusted_content|untrusted_data|external_data|user_input|agent_data|system_prompt|system)[^>]*>/gi, '');
  text = text.replace(/\[(?:untrusted_content|untrusted_data|external_data|user_input|agent_data|boundary)_TAG_NEUTRALIZED\]/gi, '');
  text = text.replace(/=== Research Findings ===/gi, '');
  text = text.replace(/\[INSPECTED EXTERNAL DATA\]/gi, '');
  text = text.replace(/Source \[\d+\]:[^\n]*\n?/gi, '');
  text = text.replace(/URL:[^\n]*\n?/gi, '');
  text = text.replace(/Summary:\s*/gi, '');
  text = text.replace(/OFFLINE SEARCH FALLBACK[^\n]*\n?/gi, '');
  text = text.replace(/^\s*\*\*Summary for [^:]+:\*\*\s*/gi, '');
  text = text.replace(/DEMO \/ FALLBACK MODE — No external LLM provider output is represented\./gi, '');
  text = text.replace(/Verified safe and processed securely by AgentShield\./gi, '');
  text = text.replace(/\n{3,}/g, '\n\n').trim();

  return text || 'The request was evaluated and verified safe by AgentShield.';
}

function responseText(response) {
  return cleanAssistantAnswer(response);
}

function Chat({ chatTurns, onSubmit, pending, onClear, lastResponse, lifecycle, onRefresh, refreshing, provider, providerError }) {
  const [query, setQuery] = useState('');

  const submit = async (event) => {
    if (event) event.preventDefault();
    if (!query.trim() || pending) return;
    const current = query.trim();
    setQuery('');
    await onSubmit(current);
  };

  const handleKeyDown = (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      submit();
    }
  };

  return <>
    <PageHeader title="Live Chat" description="Ask a question or enter a request. AgentShield evaluates prompts through its security gateway and multi-agent guards before answering." onRefresh={onRefresh} refreshing={refreshing} />
    <ChatProviderNotice provider={provider} error={providerError} />
    <div className="chat-layout">
      <section className="panel chat-panel">
        <div className="section-heading">
          <div>
            <h3>Guarded conversation</h3>
            <p>Every response is verified through the AgentShield security pipeline.</p>
          </div>
          <Bot size={18} />
        </div>
        <div className="chat-stream">
          {chatTurns.length ? (
            chatTurns.map((turn, index) => <ChatTurn turn={turn} key={`${turn.kind}-${index}`} />)
          ) : (
            <EmptyState title="No conversation yet" detail="Enter a complete question or request below to evaluate it with AgentShield." />
          )}
          {pending && (
            <div className="pending-line">
              <RefreshCw size={16} className="spin" />
              <span>Analyzing security rules and processing response…</span>
            </div>
          )}
        </div>
        <form className="chat-form" onSubmit={submit}>
          <div className="input-wrapper">
            <textarea
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask AgentShield a question (e.g., 'What are the main risks of prompt injection in multi-agent systems?')..."
              rows={3}
              disabled={pending}
            />
          </div>
          <div className="form-actions">
            <button className="button button-subtle" type="button" onClick={onClear} disabled={pending || chatTurns.length === 0}>
              <X size={15} /> Clear
            </button>
            <button className="button button-primary" type="submit" disabled={!query.trim() || pending}>
              <Send size={15} /> Send
            </button>
          </div>
        </form>
      </section>
      <section className="panel">
        <div className="section-heading">
          <div>
            <h3>Security Inspection</h3>
            <p>Decision provenance and telemetry returned by the backend.</p>
          </div>
          <Shield size={18} />
        </div>
        {lastResponse ? (
          <>
            <DecisionDetail response={lastResponse} />
            <div className="chat-trace">
              <h4>Persisted Security Trace</h4>
              {lifecycle ? <EventList events={lifecycle.events || []} /> : <EmptyState title="Trace not loaded" detail="The request lifecycle is still being fetched." />}
            </div>
          </>
        ) : (
          <EmptyState title="No decision selected" detail="Security telemetry for the latest chat turn will appear here." />
        )}
      </section>
    </div>
  </>;
}

function ChatTurn({ turn }) {
  if (turn.kind === 'user') {
    return (
      <div className="chat-turn user-turn">
        <div className="turn-header">
          <span className="turn-author">You</span>
        </div>
        <div className="turn-content">{turn.text}</div>
      </div>
    );
  }

  const response = turn.response;
  if (!response && turn.text?.startsWith('API error')) {
    return (
      <div className="chat-turn assistant-turn error-turn">
        <div className="turn-author-row">
          <AlertTriangle size={15} />
          <span>API Error</span>
        </div>
        <div className="turn-content">{turn.text}</div>
      </div>
    );
  }

  const decision = responseDecision(response);
  const isBlocked = decision.label === 'BLOCKED';
  const isOutputBlocked = decision.label === 'OUTPUT BLOCKED';
  const isSanitized = decision.label === 'SANITIZED';
  const isProviderError = response.execution?.status === 'PROVIDER_ERROR';
  const answerText = cleanAssistantAnswer(response);

  return (
    <div className={`chat-turn assistant-turn ${isBlocked ? 'assistant-blocked' : ''}`}>
      {/* 1. Answer or Blocked Banner */}
      {isBlocked ? (
        <div className="blocked-message-box">
          <div className="blocked-title">
            <ShieldAlert size={18} />
            <span>Request Blocked</span>
          </div>
          <p className="blocked-desc">{answerText}</p>
        </div>
      ) : (
        <div className="answer-section">
          <div className="answer-label">{decision.label === 'REVIEW REQUIRED' ? 'Review required' : isOutputBlocked ? 'Answer withheld' : isProviderError ? 'Unable to generate an answer' : decision.label === 'FAILED' ? 'Workflow failed' : 'Answer'}</div>
          <div className="turn-content">{answerText}</div>
        </div>
      )}

      {/* Keep the conversation clean: detailed telemetry belongs in the
          adjacent security panel and dashboard, not beneath every answer. */}
      <div className="turn-actions-card">
        <div className="actions-body">
          <div className="action-decision-pill">
            <span>Security:</span>
            <Badge tone={decision.tone}>{decision.label}</Badge>
          </div>
        </div>
        {isSanitized && (
          <p className="action-note">
            Input was sanitized to neutralize potential injection patterns before safe execution.
          </p>
        )}
      </div>
    </div>
  );
}

function DecisionDetail({ response }) {
  const summary = response.risk_summary || {};
  const metadata = response.final_output?.provider_metadata || {};
  const findings = [...(summary.rule_flags || []), ...(summary.context_flags || []), ...(summary.findings || [])];
  const uniqueFindings = [...new Set(findings)];
  return <div className="detail-stack"><div className="decision-callout"><div><span className="eyebrow">POLICY DECISION</span><strong>{textValue(response.policy_decision?.action)}</strong></div><Badge tone={decisionTone(response.policy_decision?.action)}>{textValue(response.policy_decision?.action)}</Badge></div><dl className="detail-list"><dt>Request ID</dt><dd className="mono">{textValue(response.request_id)}</dd><dt>Risk</dt><dd><Badge tone={riskTone(summary.level)}>{textValue(summary.level)} · {numberValue(summary.score, 3)}</Badge></dd><dt>Reason</dt><dd>{textValue(response.policy_decision?.reason)}</dd><dt>Findings</dt><dd>{uniqueFindings.length ? <div className="tag-list">{uniqueFindings.map((finding) => <span className="tag" key={finding}>{finding}</span>)}</div> : 'No findings recorded'}</dd><dt>Provider / model</dt><dd>{textValue(metadata.provider || response.final_output?.provider)} / {textValue(metadata.model || response.final_output?.model)}</dd><dt>Mode / real_llm</dt><dd>{textValue(metadata.mode || response.final_output?.mode)} / {response.final_output?.real_llm === true ? 'true' : 'false'}</dd></dl><div className="output-box"><span className="eyebrow">FINAL ANSWER</span><p>{cleanAssistantAnswer(response)}</p></div></div>;
}


function RequestTable({ rows, onSelect, compact = false }) {
  return <div className="table-wrap"><table><thead><tr><th>Request ID</th><th>Timestamp</th><th>Risk</th><th>Decision</th><th>Latency</th></tr></thead><tbody>{rows.map((row) => <tr key={row.request_id || row.id} onClick={() => onSelect?.(row.request_id)} className={onSelect ? 'clickable' : ''}><td className="mono">{textValue(row.request_id || row.id)}</td><td>{dateValue(row.timestamp)}</td><td><Badge tone={riskTone(row.risk_level)}>{textValue(row.risk_level)} {row.risk_score === undefined ? '' : `· ${numberValue(row.risk_score, 3)}`}</Badge></td><td><Badge tone={decisionTone(row.decision || row.policy_decision)}>{textValue(row.decision || row.policy_decision)}</Badge></td><td>{row.latency_ms === undefined ? 'N/A' : `${numberValue(row.latency_ms, 2)} ms`}</td></tr>)}</tbody></table>{compact && <p className="table-note">Select a row to inspect its persisted lifecycle.</p>}</div>;
}

function Requests({ snapshot, selectedRequestId, lifecycle, onSelect, onRefresh, refreshing }) {
  return <><PageHeader title="Requests" description="Persisted request summaries and server-reconstructed lifecycle detail." onRefresh={onRefresh} refreshing={refreshing} /><section className="panel"><div className="section-heading"><div><h3>Request ledger</h3><p>Prompt text and sensitive payloads are intentionally omitted by the API contract.</p></div><Search size={18} /></div>{snapshot.requests.length ? <RequestTable rows={snapshot.requests} onSelect={onSelect} /> : <EmptyState title="No request records" detail="The requests endpoint returned no persisted security logs." />}</section>{selectedRequestId && <LifecyclePanel lifecycle={lifecycle} requestId={selectedRequestId} />}</>;
}

function LifecyclePanel({ lifecycle, requestId }) {
  if (!lifecycle) return <section className="panel"><EmptyState title="Loading lifecycle" detail={`Fetching records for ${requestId}.`} /></section>;
  const request = lifecycle.request || {};
  return <section className="panel"><div className="section-heading"><div><h3>Lifecycle · {requestId}</h3><p>Records are joined by the server-owned request ID.</p></div><Database size={18} /></div><div className="lifecycle-grid"><dl className="detail-list"><dt>Source / target</dt><dd>{textValue(request.source)} → {textValue(request.target)}</dd><dt>Decision</dt><dd><Badge tone={decisionTone(request.decision)}>{textValue(request.decision)}</Badge></dd><dt>Risk</dt><dd>{textValue(request.risk_level)} · {numberValue(request.risk_score, 3)}</dd><dt>Latency</dt><dd>{request.latency_ms === undefined ? 'N/A' : `${numberValue(request.latency_ms, 2)} ms`}</dd></dl><div><h4>Persisted events</h4><EventList events={lifecycle.events || []} /></div></div></section>;
}

function EventList({ events = [] }) {
  const safeEvents = events || [];
  if (!safeEvents.length) return <EmptyState title="No event recorded" detail="This request has no persisted platform events." />;
  return <div className="event-list">{safeEvents.map((event) => <div className="event-row" key={event.event_id}><div><strong>{textValue(event.event_type)}</strong><span>{textValue(event.component)} · {dateValue(event.timestamp)}</span></div><div className="event-meta"><Badge tone={decisionTone(event.decision)}>{textValue(event.decision)}</Badge>{event.risk_level && <Badge tone={riskTone(event.risk_level)}>{event.risk_level}</Badge>}<span className="mono">{textValue(event.event_id)}</span></div></div>)}</div>;
}

function Events({ events = [], onRefresh, refreshing }) {
  const safeEvents = events || [];
  const [filter, setFilter] = useState('');
  const filtered = safeEvents.filter((event) => !filter || `${event.event_type} ${event.component} ${event.decision}`.toLowerCase().includes(filter.toLowerCase()));
  return <><PageHeader title="Security Events" description="Platform events persisted by EventLogger, with server-side redaction already applied." onRefresh={onRefresh} refreshing={refreshing} /><section className="panel"><div className="toolbar"><div className="search-box"><Search size={16} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter event type, component, decision" /></div><span className="muted">{safeEvents.length ? `${safeEvents.length} events loaded` : 'No events loaded'}</span></div>{filtered.length ? <EventList events={filtered} /> : <EmptyState title={safeEvents.length ? 'No matching events' : 'No persisted security events'} detail="Try another filter or wait for the next API record." />}</section></>;
}

function Traces({ events = [], lifecycle, selectedRequestId, onSelectRequest, requests = [], onRefresh, refreshing }) {
  const safeEvents = events || [];
  const safeRequests = requests || [];
  const handoffs = safeEvents.filter((event) => String(event.event_type || '').toUpperCase() === 'HANDOFF_SECURITY');
  const lifecycleHandoffs = lifecycle?.handoffs || [];
  return <><PageHeader title="Agent Traces" description="Inter-agent guard evidence only; missing stages remain explicitly unrecorded." onRefresh={onRefresh} refreshing={refreshing} /><section className="panel"><div className="trace-selector"><div><h3>Request scope</h3><p>Select a request to reconstruct its trace.</p></div><select value={selectedRequestId || ''} onChange={(event) => onSelectRequest(event.target.value)}><option value="">Choose a request</option>{safeRequests.map((request) => <option key={request.request_id} value={request.request_id}>{request.request_id}</option>)}</select></div>{selectedRequestId && lifecycle ? <TraceForRequest lifecycle={lifecycle} /> : handoffs.length ? <div><h3>Observed handoff events</h3><EventList events={handoffs} /></div> : <EmptyState title="No handoff events recorded" detail="The events API has not returned a HANDOFF_SECURITY record." />}</section></>;
}

function TraceForRequest({ lifecycle }) {
  const events = lifecycle?.events || [];
  const blockedEvent = events.find((event) => decisionTone(event.decision) === 'danger');
  const blocked = Boolean(blockedEvent);
  const stages = ['REQUEST_RECEIVED', 'NORMALIZATION', 'DETECTOR_FINDINGS', 'RISK_SCORED', 'POLICY_DECISION'];
  return <div className="trace-stack"><div className="trace-boundary"><span>Security boundary</span><strong>{blocked ? `Execution stopped at ${textValue(blockedEvent.event_type)}` : 'Security events recorded before downstream execution'}</strong></div><div className="trace-stages">{stages.map((stage) => { const event = events.find((item) => String(item.event_type).toUpperCase() === stage); return <div className={`trace-stage ${event ? 'recorded' : 'missing'}`} key={stage}><div className="stage-marker">{event ? <Check size={14} /> : '—'}</div><div><strong>{stage.replace(/_/g, ' ')}</strong><span>{event ? `Recorded · ${textValue(event.component)}` : 'No event recorded'}</span></div><Badge tone={event ? decisionTone(event.decision) : 'neutral'}>{event ? textValue(event.decision) : 'NOT RECORDED'}</Badge></div>; })}</div>{lifecycle?.handoffs?.length ? <div><h4>Inter-agent handoffs</h4>{lifecycle.handoffs.map((handoff) => { const evidence = events.find((event) => String(event.event_type).toUpperCase() === 'HANDOFF_SECURITY' && event.handoff_id === handoff.handoff_id); const risk = evidence?.risk_level ? `${evidence.risk_level} · ${numberValue(evidence.risk_score, 3)}` : 'N/A'; const metadata = evidence?.metadata || {}; const findings = metadata.findings || metadata.rule_flags || []; return <div className="handoff-card" key={handoff.handoff_id}><div><strong>{textValue(handoff.from_agent)} → {textValue(handoff.to_agent)}</strong><span>{dateValue(handoff.timestamp)} · {textValue(handoff.handoff_id)}</span></div><div><Badge tone={decisionTone(handoff.decision)}>{textValue(handoff.decision)}</Badge><span>Risk: {risk} · Findings: {Array.isArray(findings) && findings.length ? findings.join(', ') : 'N/A'} · Latency: N/A</span></div></div>; })}</div> : <EmptyState title="No handoff record" detail="No Phase 7 handoff was persisted for this request." />}</div>;
}

function Tools({ events = [], lifecycle, selectedRequestId, onSelectRequest, requests = [], onRefresh, refreshing }) {
  const safeEvents = events || [];
  const safeRequests = requests || [];
  const tools = lifecycle?.tools || safeEvents.filter((event) => String(event.event_type || '').toUpperCase().startsWith('TOOL_')).map((event) => ({ tool_call_id: event.tool_call_id, tool_name: event.metadata?.tool_name, status: event.decision, timestamp: event.timestamp }));
  return <><PageHeader title="Tool Activity" description="Guarded tool events with secret arguments omitted from this dashboard." onRefresh={onRefresh} refreshing={refreshing} /><section className="panel"><div className="trace-selector"><div><h3>Request scope</h3><p>Choose a request for server-reconstructed tool details, or view the loaded event window.</p></div><select value={selectedRequestId || ''} onChange={(event) => onSelectRequest(event.target.value)}><option value="">All loaded events</option>{safeRequests.map((request) => <option key={request.request_id} value={request.request_id}>{request.request_id}</option>)}</select></div>{tools.length ? <div className="table-wrap"><table><thead><tr><th>Tool</th><th>Call ID</th><th>Status</th><th>Execution</th><th>Time</th></tr></thead><tbody>{tools.map((tool, index) => <tr key={`${tool.tool_call_id || tool.tool_name}-${index}`}><td>{textValue(tool.tool_name)}</td><td className="mono">{textValue(tool.tool_call_id)}</td><td><Badge tone={decisionTone(tool.status)}>{textValue(tool.status)}</Badge></td><td>{textValue(tool.execution_status, 'N/A')}</td><td>{dateValue(tool.timestamp)}</td></tr>)}</tbody></table></div> : <EmptyState title="No tool events recorded" detail="The API has not returned a guarded tool execution record." />}</section></>;
}

function Approvals({ approvals = [], onAction, busyApproval, onRefresh, refreshing }) {
  const safeApprovals = approvals || [];
  return <><PageHeader title="Approvals" description="Stateful HITL decisions handled by server-owned approval records." onRefresh={onRefresh} refreshing={refreshing} /><section className="panel"><div className="section-heading"><div><h3>Approval queue</h3><p>Tool names, arguments, and roles are never editable in this UI.</p></div><LockKeyhole size={18} /></div>{safeApprovals.length ? <div className="approval-list">{safeApprovals.map((approval) => <div className="approval-card" key={approval.approval_id}><div><strong>{textValue(approval.approval_id)}</strong><span>{textValue(approval.tool_name)} · requested by {textValue(approval.requested_by)}</span></div><div className="approval-actions"><Badge tone={decisionTone(approval.status)}>{textValue(approval.status)}</Badge>{String(approval.status).toUpperCase() === 'PENDING' && <><button className="button button-success" disabled={busyApproval === approval.approval_id} onClick={() => onAction(approval.approval_id, 'approve')}>Approve</button><button className="button button-danger" disabled={busyApproval === approval.approval_id} onClick={() => onAction(approval.approval_id, 'reject')}>Reject</button></>}</div></div>)}</div> : <EmptyState title="No pending approvals" detail="The approvals endpoint returned no records for this identity." />}</section></>;
}

function Analytics({ snapshot, onRefresh, refreshing }) {
  const overview = snapshot.metrics?.overview || {};
  const risk = snapshot.metrics?.risk_distribution || {};
  const rules = arrayValue(snapshot.metrics?.top_triggered_rules);
  return <><PageHeader title="Analytics" description="Descriptive aggregates returned by the backend. Research quality metrics are not inferred from production traffic." onRefresh={onRefresh} refreshing={refreshing} /><div className="metric-grid analytics-grid"><MetricCard label="Requests" value={numberValue(overview.total_requests)} detail="Persisted SecurityLog rows" icon={Activity} /><MetricCard label="Sanitized" value={numberValue(overview.sanitized_requests)} detail="Policy decisions marked SANITIZE" icon={Shield} tone="amber" /><MetricCard label="Average latency" value={overview.avg_latency_ms === undefined ? 'No data yet' : `${numberValue(overview.avg_latency_ms, 2)} ms`} detail="Persisted gateway latency" icon={Clock3} tone="green" /><MetricCard label="Block rate" value={overview.block_rate_percent === undefined ? 'No data yet' : `${numberValue(overview.block_rate_percent, 1)}%`} detail="Calculated by the metrics API" icon={ShieldAlert} tone="red" /></div><div className="content-grid two-column"><section className="panel"><div className="section-heading"><div><h3>Risk distribution</h3><p>Descriptive request counts.</p></div></div><Distribution data={risk} /></section><section className="panel"><div className="section-heading"><div><h3>Top triggered rules</h3><p>Detector flags aggregated server-side.</p></div></div>{rules.length ? <RuleBars rules={rules} /> : <EmptyState />}</section></div><section className="panel note-panel"><AlertTriangle size={18} /><p>FPR, recall, F1, calibration quality, and benchmark claims belong to the separate research/experiment artifacts. This production view does not manufacture them from ordinary traffic.</p></section></>;
}

function Experiments({ onRefresh, refreshing }) {
  return <><PageHeader title="Experiments" description="Research artifacts remain separate from operational observability." onRefresh={onRefresh} refreshing={refreshing} /><section className="panel"><EmptyState title="No experiment API data" detail="No experiment metadata or results endpoint is exposed by the current backend contract. Use the checked-in research artifacts for reproducible evaluation." /><div className="research-note"><Gauge size={18} /><span>Operational metrics on this page are intentionally absent until a versioned experiment API is available.</span></div></section></>;
}

function Settings({ health, provider, onRefresh, refreshing, onProbe, probing }) {
  const providerList = Object.entries(provider?.providers || {});
  return <>
    <PageHeader title="Settings" description="Read-only deployment and provider facts. Secrets and threshold editing are not available here." onRefresh={onRefresh} refreshing={refreshing} />
    <div className="content-grid two-column">
      <section className="panel">
        <div className="section-heading">
          <div>
            <h3>Runtime</h3>
            <p>Safe values returned by /health.</p>
          </div>
          <Activity size={18} />
        </div>
        <dl className="detail-list">
          <dt>API base URL</dt><dd className="mono">{API_BASE_URL}</dd>
          <dt>Status</dt><dd><Badge tone={health?.status === 'HEALTHY' ? 'success' : 'warning'}>{textValue(health?.status, 'Unavailable')}</Badge></dd>
          <dt>Version</dt><dd>{textValue(health?.version)}</dd>
          <dt>Database connected</dt><dd>{health?.database_connected === true ? 'true' : health?.database_connected === false ? 'false' : 'N/A'}</dd>
          <dt>Security logs</dt><dd>{numberValue(health?.total_security_logs)}</dd>
          <dt>Alerts</dt><dd>{numberValue(health?.total_alerts)}</dd>
        </dl>
      </section>
      <section className="panel">
        <div className="section-heading">
          <div>
            <h3>Provider verification</h3>
            <p>Secret-free status from /providers/status.</p>
          </div>
          <button className="button button-subtle" onClick={onProbe} disabled={probing || refreshing}>
            <Zap size={14} className={probing ? 'spin' : ''} /> {probing ? 'Probing…' : 'Probe Providers'}
          </button>
        </div>
        <dl className="detail-list">
          <dt>Selected provider</dt><dd>{textValue(provider?.selected_provider)}</dd>
          <dt>Active provider</dt><dd>{textValue(provider?.active_provider)}</dd>
          <dt>Active status</dt><dd><Badge tone={provider?.real_llm ? 'success' : provider?.active_status === 'configured_but_unverified' ? 'info' : 'warning'}>{textValue(provider?.active_status)}</Badge></dd>
          <dt>Mode</dt><dd>{textValue(provider?.mode)}</dd>
          <dt>real_llm</dt><dd>{provider?.real_llm === true ? 'true' : provider?.real_llm === false ? 'false' : 'N/A'}</dd>
          <dt>Support note</dt><dd>{textValue(provider?.support_note)}</dd>
        </dl>
        {providerList.length > 0 && (
          <div className="provider-grid">
            {providerList.map(([name, details]) => (
              <div className="provider-item-card" key={name}>
                <div className="provider-item-header">
                  <span className="provider-item-name">{name}</span>
                  <Badge tone={details.runtime_verified ? 'success' : details.configured ? 'info' : 'neutral'}>
                    {details.runtime_verified ? 'Verified' : details.configured ? 'Configured' : 'Not Configured'}
                  </Badge>
                </div>
                <div className="provider-item-model">{textValue(details.model, 'default')}</div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
    <section className="panel">
      <div className="section-heading">
        <div>
          <h3>Active guards</h3>
          <p>Names reported by the backend health contract.</p>
        </div>
        <Shield size={18} />
      </div>
      {health?.active_guards?.length ? (
        <div className="tag-list">
          {health.active_guards.map((guard) => <span className="tag" key={guard}>{guard}</span>)}
        </div>
      ) : (
        <EmptyState title="Guard inventory unavailable" />
      )}
    </section>
  </>;
}

export function App() {
  const [page, setPage] = useState(pageFromLocation);
  const [mobileNav, setMobileNav] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [probing, setProbing] = useState(false);
  const [snapshot, setSnapshot] = useState({ health: null, metrics: null, requests: [], events: [], alerts: [], approvals: [], provider: null });
  const [loadError, setLoadError] = useState(null);
  const [healthError, setHealthError] = useState(null);
  const [selectedRequestId, setSelectedRequestId] = useState('');
  const [lifecycle, setLifecycle] = useState(null);
  const [chatTurns, setChatTurns] = useState([]);
  const [lastResponse, setLastResponse] = useState(null);
  const [chatPending, setChatPending] = useState(false);
  const [busyApproval, setBusyApproval] = useState(null);

  const navigate = useCallback((nextPage) => {
    const target = PAGE_IDS.has(nextPage) ? nextPage : 'overview';
    setPage(target);
    if (typeof window !== 'undefined') {
      const hash = `#/${target}`;
      if (window.location.hash !== hash) window.history.replaceState(null, '', hash);
    }
  }, []);

  useEffect(() => {
    const handleHashChange = () => setPage(pageFromLocation());
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const refresh = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    const needed = new Set(pageResources(page));
    const calls = await Promise.allSettled(
      ['health', 'metrics', 'requests', 'events', 'alerts', 'approvals', 'providersStatus']
        .map((name) => needed.has(name) ? api[name]() : Promise.resolve(null)),
    );
    const [health, metrics, requests, events, alerts, approvals, provider] = calls;
    const failures = calls.filter((result) => result.status === 'rejected');
    setHealthError(health.status === 'rejected' ? health.reason : null);
    setSnapshot((current) => ({
      health: health.status === 'fulfilled' ? health.value : current.health,
      metrics: metrics.status === 'fulfilled' ? metrics.value : current.metrics,
      requests: requests.status === 'fulfilled' ? arrayValue(requests.value, 'requests') : current.requests,
      events: events.status === 'fulfilled' ? arrayValue(events.value, 'events') : current.events,
      alerts: alerts.status === 'fulfilled' ? arrayValue(alerts.value, 'alerts') : current.alerts,
      approvals: approvals.status === 'fulfilled' ? arrayValue(approvals.value, 'approvals') : current.approvals,
      provider: provider.status === 'fulfilled' ? provider.value : current.provider,
    }));
    setLoadError(failures.length ? failures[0].reason : null);
    if (!silent) setRefreshing(false);
  }, [page]);

  useEffect(() => { refresh(); }, [refresh]);

  const handleProbe = useCallback(async () => {
    setProbing(true);
    try {
      const result = await api.providersStatus(true);
      setSnapshot((current) => ({ ...current, provider: result }));
    } catch (err) {
      setLoadError(err);
    } finally {
      setProbing(false);
    }
  }, []);

  const selectRequest = useCallback(async (requestId) => {
    setSelectedRequestId(requestId || '');
    setLifecycle(null);
    if (!requestId) return;
    try { setLifecycle(await api.requestLifecycle(requestId)); } catch (error) { setLoadError(error); }
  }, []);

  const submitChat = async (query, context = null) => {
    setChatPending(true);
    setChatTurns((current) => [...current, { kind: 'user', text: query }]);
    try {
      const response = await api.chat(query, context);
      setLastResponse(response);
      setChatTurns((current) => [...current, { kind: 'assistant', text: cleanAssistantAnswer(response), response }]);
      await refresh(true);
      // The chat response already contains its security result. Detailed
      // persisted lifecycle access belongs to the protected telemetry pages.
      setSelectedRequestId(response.request_id || '');
      setLifecycle(null);
    } catch (error) {
      setLoadError(error);
      setChatTurns((current) => [...current, { kind: 'assistant', text: `API error: ${error.message}`, response: null }]);
    } finally { setChatPending(false); }
  };

  const approvalAction = async (approvalId, action) => {
    setBusyApproval(approvalId);
    try { if (action === 'approve') await api.approve(approvalId, DEV_IDENTITY); else await api.reject(approvalId, DEV_IDENTITY); await refresh(true); } catch (error) { setLoadError(error); } finally { setBusyApproval(null); }
  };

  const pageContent = useMemo(() => {
    const props = { snapshot, onRefresh: refresh, refreshing };
    switch (page) {
      case 'chat': return <Chat chatTurns={chatTurns} onSubmit={submitChat} pending={chatPending} onClear={() => { setChatTurns([]); setLastResponse(null); }} lastResponse={lastResponse} lifecycle={lifecycle} onRefresh={refresh} refreshing={refreshing} provider={snapshot.provider} providerError={healthError || (!snapshot.provider ? loadError : null)} />;
      case 'requests': return <Requests {...props} selectedRequestId={selectedRequestId} lifecycle={lifecycle} onSelect={selectRequest} />;
      case 'events': return <Events events={snapshot.events} onRefresh={refresh} refreshing={refreshing} />;
      case 'traces': return <Traces events={snapshot.events} lifecycle={lifecycle} selectedRequestId={selectedRequestId} onSelectRequest={selectRequest} requests={snapshot.requests} onRefresh={refresh} refreshing={refreshing} />;
      case 'tools': return <Tools events={snapshot.events} lifecycle={lifecycle} selectedRequestId={selectedRequestId} onSelectRequest={selectRequest} requests={snapshot.requests} onRefresh={refresh} refreshing={refreshing} />;
      case 'approvals': return <Approvals approvals={snapshot.approvals} onAction={approvalAction} busyApproval={busyApproval} onRefresh={refresh} refreshing={refreshing} />;
      case 'analytics': return <Analytics {...props} />;
      case 'experiments': return <Experiments onRefresh={refresh} refreshing={refreshing} />;
      case 'settings': return <Settings health={snapshot.health} provider={snapshot.provider} onRefresh={refresh} refreshing={refreshing} onProbe={handleProbe} probing={probing} />;
      default: return <Overview {...props} onSelectRequest={selectRequest} />;
    }
  }, [page, snapshot, refreshing, refresh, selectedRequestId, lifecycle, selectRequest, chatTurns, chatPending, lastResponse, busyApproval, handleProbe, probing, healthError, loadError]);

  const apiStatus = healthError ? 'Backend unavailable' : snapshot.health?.status === 'HEALTHY' ? 'API connected' : snapshot.health ? `API ${textValue(snapshot.health.status, 'degraded')}` : 'Connecting…';
  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} /></div>
          <div><strong>AgentShield</strong><span>Security control center</span></div>
        </div>
        <nav>
          {NAVIGATION.map(({ id, label, icon: Icon }) => (
            <button key={id} className={page === id ? 'nav-item active' : 'nav-item'} onClick={() => { navigate(id); setMobileNav(false); }}>
              <Icon size={17} /><span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="status-dot" /> API-backed telemetry
          <div className="muted">No local operational fixtures</div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setMobileNav((open) => !open)}>
            <Menu size={20} />
          </button>
          <div className="topbar-title">
            <span className="live-indicator"><span className="status-dot" /> {apiStatus}</span>
            <span className="muted">{snapshot.health ? `v${textValue(snapshot.health.version)}` : 'Connecting…'}</span>
          </div>
          <div className="topbar-right">
            <ProviderBadge provider={snapshot.provider} error={healthError || (!snapshot.provider ? loadError : null)} />
            <button className="button button-subtle" onClick={() => refresh()} disabled={refreshing}>
              <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Sync
            </button>
          </div>
        </header>
        <main className="main-content">
          <ErrorState error={loadError} onRetry={() => refresh()} />
          {pageContent}
        </main>
      </div>
    </div>
  );
}

export default App;
