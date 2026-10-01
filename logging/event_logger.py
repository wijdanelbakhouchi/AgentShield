"""
logging/event_logger.py
=======================
AgentShield Phase 5 — Event Logger & Telemetry Collector

Provides structured, persistent audit logging for every entry request,
inter-agent state handoff, tool execution, and security policy action.

Uses function-level lazy database session imports to ensure clean module initialization.
"""

import datetime as dt
import hashlib
import json
import logging
import re
import uuid
from typing import Any, Mapping, Optional
from schema.interception import AgentHandoffEvent, ToolExecutionEvent
from state import PolicyDecision, RiskScoreResult, SecurityAnalysisResult, SecurityPayload


_SENSITIVE_KEY = re.compile(r"(?i)(password|secret|token|api[_-]?key|authorization|credential)")
_SENSITIVE_VALUE = re.compile(
    r"(?i)(bearer\s+)[^\s,;]+|(AGENTSHIELD_TEST_SECRET_[A-Za-z0-9_-]+)|((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;]+"
)
_PROVIDER_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{20,}|AIzaSy[A-Za-z0-9_-]{33}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{16,})\b")
logger = logging.getLogger("agentshield.telemetry")


def _telemetry_failure(event_type: str, request_id: Optional[str], exc: Exception) -> None:
    """Make persistence degradation observable without leaking exception text."""
    logger.warning(
        "telemetry_persist_failed event_type=%s request_id=%s exception_type=%s",
        event_type,
        request_id or "unknown",
        exc.__class__.__name__,
    )


def redact_sensitive(value: Any) -> Any:
    """Redact credentials recursively before any persisted event is built."""

    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return _PROVIDER_KEY.sub("[REDACTED]", _SENSITIVE_VALUE.sub(lambda match: (match.group(1) or match.group(3) or "") + "[REDACTED]", value))
    return value


def redact_operational_content(value: str) -> str:
    """Store a bounded redacted preview only when explicitly configured."""
    from config import OPERATIONAL_LOG_MAX_CHARS, OPERATIONAL_LOG_PROMPTS

    redacted = str(redact_sensitive(value))
    if not OPERATIONAL_LOG_PROMPTS:
        return (
            "[CONTENT_WITHHELD "
            f"length={len(redacted)} sha256={hashlib.sha256(redacted.encode('utf-8')).hexdigest()}]"
        )
    return redacted[:OPERATIONAL_LOG_MAX_CHARS]


class EventLogger:
    """Structured, persistent, and secret-safe telemetry writer.

    It persists gateway, tool, handoff, alert, and canonical platform events
    without changing the security decisions that produced them.
    """

    @classmethod
    def log_platform_event(
        cls,
        *,
        request_id: Optional[str],
        event_type: str,
        component: str,
        risk_score: Optional[float] = None,
        risk_level: Optional[str] = None,
        decision: Optional[str] = None,
        tool_call_id: Optional[str] = None,
        handoff_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        timestamp: Optional[str] = None,
        session: Optional[Any] = None,
    ):
        """Persist the one canonical, secret-safe observability envelope."""

        from storage.db import get_db_session, init_db
        from storage.models import PlatformEvent

        if session is None:
            try:
                init_db()
            except Exception as exc:
                _telemetry_failure("INIT", request_id, exc)
        event = PlatformEvent(
            event_id=f"event-{uuid.uuid4().hex}",
            request_id=request_id,
            event_type=event_type,
            timestamp=timestamp or dt.datetime.now(dt.timezone.utc).isoformat(),
            component=component,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            tool_call_id=tool_call_id,
            handoff_id=handoff_id,
            approval_id=approval_id,
            metadata_json=json.dumps(redact_sensitive(dict(metadata or {})), sort_keys=True),
        )
        if session is not None:
            try:
                session.add(event)
            except Exception as exc:
                _telemetry_failure(event.event_type, request_id, exc)
            return event
        try:
            with get_db_session() as s:
                s.add(event)
        except Exception as exc:
            # Observability must never expose DB internals or break security flow,
            # but a structured warning keeps the degraded state diagnosable.
            _telemetry_failure(event.event_type, request_id, exc)
        return event

    @classmethod
    def log_security_event(
        cls,
        payload: SecurityPayload,
        analysis_result: SecurityAnalysisResult,
        risk_metrics: RiskScoreResult,
        policy_decision: PolicyDecision,
        latency_ms: float = 0.0,
    ):
        """
        Logs an entry security gateway event (Phases 1–3) into SecurityLog table.
        """
        from storage.db import get_db_session, init_db
        from storage.models import SecurityLog

        try:
            init_db()
        except Exception as exc:
            _telemetry_failure("INIT_SECURITY_EVENT", payload.request_id, exc)

        rule_flags_json = json.dumps(redact_sensitive(analysis_result.rule_flags))
        llm_flags_json = json.dumps(redact_sensitive(analysis_result.llm_classification))

        log_entry = SecurityLog(
            request_id=payload.request_id,
            timestamp=payload.timestamp,
            source=payload.source,
            target=payload.target,
            raw_input=redact_operational_content(payload.raw_input),
            sanitized_input=redact_operational_content(policy_decision.modified_input or payload.normalized_input),
            risk_score=risk_metrics.score,
            risk_level=risk_metrics.level.value,
            policy_decision=policy_decision.action.value,
            rule_flags=rule_flags_json,
            llm_flags=llm_flags_json,
            latency_ms=round(latency_ms, 2),
        )

        try:
            with get_db_session() as session:
                session.add(log_entry)
        except Exception as exc:
            _telemetry_failure("SECURITY_EVENT", payload.request_id, exc)

        event_metadata = {
            "source": payload.source,
            "target": payload.target,
            "rule_flags": analysis_result.rule_flags,
            "context_flags": analysis_result.context_flags,
        }
        for event_type, component in (
            ("REQUEST_RECEIVED", "SecurityGateway"),
            ("NORMALIZATION", "SecurityGateway"),
            ("DETECTOR_FINDINGS", "RiskAnalyzer"),
            ("RISK_SCORED", "RiskScorer"),
            ("POLICY_DECISION", "PolicyEngine"),
        ):
            cls.log_platform_event(
                request_id=payload.request_id,
                event_type=event_type,
                component=component,
                risk_score=risk_metrics.score,
                risk_level=risk_metrics.level.value,
                decision=policy_decision.action.value,
                metadata=event_metadata,
                timestamp=payload.timestamp,
            )

        return log_entry

    @classmethod
    def log_tool_event(
        cls,
        tool_event: ToolExecutionEvent,
        request_id: str,
    ):
        """
        Logs a Phase 4 tool execution event into ToolLog table.
        """
        from storage.db import get_db_session, init_db
        from storage.models import ToolLog

        try:
            init_db()
        except Exception as exc:
            _telemetry_failure("INIT_TOOL_EVENT", request_id, exc)

        raw_args_json = json.dumps(redact_sensitive(tool_event.raw_args))
        pre_flags_json = json.dumps(redact_sensitive(tool_event.pre_exec_flags))
        post_flags_json = json.dumps(redact_sensitive(tool_event.post_exec_flags))
        findings_json = json.dumps(redact_sensitive(tool_event.findings))
        transforms_json = json.dumps(redact_sensitive(tool_event.transforms))

        log_entry = ToolLog(
            request_id=request_id,
            timestamp=tool_event.timestamp,
            tool_name=tool_event.tool_name,
            agent_caller=tool_event.agent_caller,
            raw_args=raw_args_json,
            pre_exec_status=tool_event.pre_exec_status,
            post_exec_status=tool_event.post_exec_status,
            status=tool_event.status,
            output_sanitized=tool_event.output_sanitized,
            threat_detected=redact_sensitive(tool_event.mitigated_threat),
            pre_exec_flags=pre_flags_json,
            post_exec_flags=post_flags_json,
            tool_execution_id=tool_event.tool_execution_id,
            content_id=tool_event.content_id,
            source_type=tool_event.source_type,
            source_name=tool_event.source_name,
            trust_level=tool_event.trust_level,
            risk_score=tool_event.risk_score,
            risk_level=(tool_event.risk_level.value if tool_event.risk_level else None),
            decision=(tool_event.decision.value if tool_event.decision else None),
            findings=findings_json,
            transforms=transforms_json,
            latency_ms=tool_event.latency_ms,
            tool_call_id=tool_event.tool_call_id,
            subject_id=tool_event.subject_id,
            resolved_role=tool_event.resolved_role,
            authorization_decision=tool_event.authorization_decision,
            argument_security_decision=tool_event.argument_security_decision,
            execution_status=tool_event.execution_status,
            output_security_decision=tool_event.output_security_decision,
        )

        try:
            with get_db_session() as session:
                session.add(log_entry)
        except Exception as exc:
            _telemetry_failure("TOOL_EVENT", request_id, exc)

        for event_type, decision in (
            ("TOOL_REQUEST", tool_event.authorization_decision),
            ("TOOL_AUTHORIZATION", tool_event.authorization_decision),
            ("TOOL_EXECUTION", tool_event.execution_status),
            ("TOOL_OUTPUT_SECURITY", tool_event.output_security_decision),
        ):
            cls.log_platform_event(
                request_id=request_id,
                event_type=event_type,
                component="ToolGuard",
                risk_score=tool_event.risk_score,
                risk_level=(tool_event.risk_level.value if tool_event.risk_level else None),
                decision=decision,
                tool_call_id=tool_event.tool_call_id,
                metadata={"tool_name": tool_event.tool_name, "agent_caller": tool_event.agent_caller},
                timestamp=tool_event.timestamp,
            )

        return log_entry

    @classmethod
    def log_handoff_event(
        cls,
        handoff_event: AgentHandoffEvent,
        request_id: str,
    ):
        """
        Logs a Phase 4 inter-agent state handoff event into HandoffLog table.
        """
        from storage.db import get_db_session, init_db
        from storage.models import HandoffLog

        try:
            init_db()
        except Exception as exc:
            _telemetry_failure("INIT_HANDOFF_EVENT", request_id, exc)

        flags_json = json.dumps(redact_sensitive(handoff_event.detected_flags))

        log_entry = HandoffLog(
            request_id=request_id,
            handoff_id=handoff_event.handoff_id,
            timestamp=handoff_event.timestamp,
            from_agent=handoff_event.from_agent,
            to_agent=handoff_event.to_agent,
            intercepted_field=handoff_event.intercepted_field,
            risk_score=handoff_event.risk_score,
            risk_level=handoff_event.risk_level.value,
            action_taken=handoff_event.action_taken.value,
            sanitized=handoff_event.sanitized,
            detected_flags=flags_json,
            reason=redact_sensitive(handoff_event.reason),
            latency_ms=handoff_event.latency_ms,
        )

        try:
            with get_db_session() as session:
                session.add(log_entry)
        except Exception as exc:
            _telemetry_failure("HANDOFF_EVENT", request_id, exc)
        cls.log_platform_event(
            request_id=request_id,
            event_type="HANDOFF_SECURITY",
            component="InterAgentGuard",
            risk_score=handoff_event.risk_score,
            risk_level=handoff_event.risk_level.value,
            decision=handoff_event.action_taken.value,
            handoff_id=handoff_event.handoff_id,
            metadata={"from_agent": handoff_event.from_agent, "to_agent": handoff_event.to_agent},
            timestamp=handoff_event.timestamp,
        )

        return log_entry

    @classmethod
    def log_alert(
        cls,
        severity: str,
        title: str,
        description: str,
        request_id: str = None,
        alert_type: str = "SECURITY_ALERT",
        source_component: str = "PolicyEngine",
        timestamp: str = None,
    ):
        """
        Logs a security alert into AlertLog table.
        """
        import datetime
        from storage.db import get_db_session, init_db
        from storage.models import AlertLog

        try:
            init_db()
        except Exception as exc:
            _telemetry_failure("INIT_ALERT", request_id, exc)
        ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()

        log_entry = AlertLog(
            timestamp=ts,
            severity=severity,
            title=redact_sensitive(title),
            description=redact_sensitive(description),
            request_id=request_id,
            alert_type=alert_type,
            source_component=source_component,
        )

        try:
            with get_db_session() as session:
                session.add(log_entry)
        except Exception as exc:
            _telemetry_failure("ALERT", request_id, exc)
        cls.log_platform_event(
            request_id=request_id,
            event_type="ALERT_RAISED",
            component=source_component,
            decision=severity,
            metadata={"alert_type": alert_type, "title": title},
            timestamp=ts,
        )

        return log_entry
