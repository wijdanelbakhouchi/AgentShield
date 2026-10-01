"""Read-only request lifecycle reconstruction from real persisted records."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select

from storage.db import get_db_session, init_db
from storage.models import AlertLog, ApprovalAuditLog, PlatformEvent, SecurityLog, ToolApproval, ToolLog, HandoffLog


def _json(value: str | None) -> Any:
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


def list_requests(limit: int = 50) -> list[dict[str, Any]]:
    """Return real request summaries without exposing persisted prompt content."""

    init_db()
    with get_db_session() as session:
        rows = session.scalars(select(SecurityLog).order_by(SecurityLog.id.desc()).limit(limit)).all()
        return [
            {
                "request_id": row.request_id,
                "timestamp": row.timestamp,
                "source": row.source,
                "target": row.target,
                "risk_score": row.risk_score,
                "risk_level": row.risk_level,
                "decision": row.policy_decision,
                "latency_ms": row.latency_ms,
            }
            for row in rows
        ]


def request_lifecycle(request_id: str) -> dict[str, Any] | None:
    """Reconstruct only records actually persisted with a matching request ID."""

    init_db()
    with get_db_session() as session:
        request = session.scalar(select(SecurityLog).where(SecurityLog.request_id == request_id).order_by(SecurityLog.id.desc()))
        events = session.scalars(select(PlatformEvent).where(PlatformEvent.request_id == request_id).order_by(PlatformEvent.id)).all()
        tools = session.scalars(select(ToolLog).where(ToolLog.request_id == request_id).order_by(ToolLog.id)).all()
        handoffs = session.scalars(select(HandoffLog).where(HandoffLog.request_id == request_id).order_by(HandoffLog.id)).all()
        approvals = session.scalars(select(ToolApproval).where(ToolApproval.request_id == request_id).order_by(ToolApproval.id)).all()
        approval_ids = [approval.approval_id for approval in approvals]
        audits = session.scalars(select(ApprovalAuditLog).where(ApprovalAuditLog.request_id == request_id).order_by(ApprovalAuditLog.id)).all()
        alerts = session.scalars(select(AlertLog).where(AlertLog.request_id == request_id).order_by(AlertLog.id)).all()
        if request is None and not any((events, tools, handoffs, approvals, audits, alerts)):
            return None
        return {
            "request_id": request_id,
            "request": None if request is None else {
                "timestamp": request.timestamp, "source": request.source, "target": request.target,
                "risk_score": request.risk_score, "risk_level": request.risk_level,
                "decision": request.policy_decision, "latency_ms": request.latency_ms,
            },
            "events": [{
                "event_id": event.event_id, "event_type": event.event_type, "timestamp": event.timestamp,
                "component": event.component, "risk_score": event.risk_score, "risk_level": event.risk_level,
                "decision": event.decision, "tool_call_id": event.tool_call_id, "handoff_id": event.handoff_id,
                "approval_id": event.approval_id, "metadata": _json(event.metadata_json),
            } for event in events],
            "tools": [{"tool_call_id": tool.tool_call_id, "tool_name": tool.tool_name, "status": tool.status, "execution_status": tool.execution_status, "output_security_decision": tool.output_security_decision, "timestamp": tool.timestamp} for tool in tools],
            "handoffs": [{"handoff_id": handoff.handoff_id, "from_agent": handoff.from_agent, "to_agent": handoff.to_agent, "decision": handoff.action_taken, "timestamp": handoff.timestamp} for handoff in handoffs],
            "approvals": [{"approval_id": approval.approval_id, "tool_call_id": approval.tool_call_id, "tool_name": approval.tool_name, "status": approval.status, "requested_by": approval.requested_by, "decided_by": approval.decided_by} for approval in approvals],
            "approval_audit": [{"approval_id": audit.approval_id, "event_type": audit.event_type, "status": audit.status, "timestamp": audit.timestamp} for audit in audits if audit.approval_id in approval_ids],
            "alerts": [{"severity": alert.severity, "title": alert.title, "alert_type": alert.alert_type, "timestamp": alert.timestamp} for alert in alerts],
        }


def list_events(request_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    with get_db_session() as session:
        statement = select(PlatformEvent).order_by(PlatformEvent.id.desc()).limit(limit)
        if request_id:
            statement = select(PlatformEvent).where(PlatformEvent.request_id == request_id).order_by(PlatformEvent.id.desc()).limit(limit)
        rows = session.scalars(statement).all()
        return [{"event_id": row.event_id, "request_id": row.request_id, "event_type": row.event_type, "timestamp": row.timestamp, "component": row.component, "risk_score": row.risk_score, "risk_level": row.risk_level, "decision": row.decision, "tool_call_id": row.tool_call_id, "handoff_id": row.handoff_id, "approval_id": row.approval_id, "metadata": _json(row.metadata_json)} for row in rows]
