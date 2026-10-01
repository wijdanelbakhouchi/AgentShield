"""Persistent, fail-closed approvals for privileged disposable sandbox tools.

This module deliberately stores a canonical *request*, rather than accepting a
second client-supplied request at decision time.  Authentication remains the
development server-side identity context provided by Phase 10.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from enum import Enum
from typing import Any, Callable, Optional

from pydantic import BaseModel
from sqlalchemy import select, update

from schema.interception import ToolRequest
from storage.db import get_db_session, init_db
from storage.models import ApprovalAuditLog, ToolApproval


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class ApprovalDecision(BaseModel):
    """Controlled response for approve/reject endpoints; contains no arguments."""

    approval_id: str
    status: str
    result_status: str
    reason: Optional[str] = None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _timestamp(value: Optional[dt.datetime] = None) -> str:
    return (value or _now()).isoformat()


def _ttl_seconds() -> int:
    from config import APPROVAL_TTL_SECONDS

    return APPROVAL_TTL_SECONDS


def _canonical_arguments(arguments: dict[str, Any]) -> str:
    """Serialize a stable request and reject secret-like fields fail-closed."""

    secret_markers = {"password", "secret", "token", "api_key", "apikey", "authorization"}
    if any(str(key).lower() in secret_markers for key in arguments):
        raise ValueError("Sensitive arguments are not accepted for pending approvals")
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class HITLApprovalService:
    """Single state machine for request, approval, rejection, expiry and resume."""

    # Explicit test/development implementations are never persisted.  Production
    # restart/readback uses the active safe registry implementation instead.
    _implementation_overrides: dict[str, Callable[..., Any]] = {}
    _requester_identities: dict[str, Any] = {}

    @classmethod
    def reset_runtime_state(cls) -> None:
        cls._implementation_overrides.clear()
        cls._requester_identities.clear()
        # Approval workflows can be exercised outside the HTTP middleware in
        # integration tests and maintenance jobs. Their request-local tool
        # budget must not leak into the next independent approval workflow.
        from security.tool_security import reset_tool_usage

        reset_tool_usage()

    @staticmethod
    def _audit(
        session: Any,
        record: ToolApproval,
        event_type: str,
        status: str,
        *,
        decided_by: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        session.add(
            ApprovalAuditLog(
                approval_id=record.approval_id,
                request_id=record.request_id,
                tool_call_id=record.tool_call_id,
                tool_name=record.tool_name,
                event_type=event_type,
                status=status,
                requested_by=record.requested_by,
                decided_by=decided_by,
                timestamp=_timestamp(),
                detail=detail,
            )
        )
        try:
            from logging.event_logger import EventLogger

            EventLogger.log_platform_event(
                request_id=record.request_id,
                event_type=event_type,
                component="HITLApprovalService",
                decision=status,
                tool_call_id=record.tool_call_id,
                approval_id=record.approval_id,
                metadata={"tool_name": record.tool_name, "requested_by": record.requested_by},
                session=session,
            )
        except Exception:
            pass

    @staticmethod
    def _result_from_request(
        request: ToolRequest,
        identity: Any,
        status: str,
        decision: str,
        *,
        approval_id: Optional[str] = None,
        reason: Optional[str] = None,
    ):
        from security.tool_security import ToolResult

        return ToolResult(
            tool_call_id=request.tool_call_id,
            request_id=request.request_id,
            tool_name=request.tool_name,
            status=status,
            security_decision=decision,
            timestamp=_timestamp(),
            subject_id=getattr(identity, "subject_id", None),
            resolved_role=getattr(identity, "role", None),
            authorization_decision="ALLOW",
            argument_security_decision="ALLOW",
            execution_status="NOT_EXECUTED",
            output_security_decision="NOT_RUN",
            approval_id=approval_id,
            reason=reason,
        )

    def create_pending(
        self,
        *,
        request: ToolRequest,
        identity: Any,
        agent_caller: str,
        source_type: str,
        implementation: Optional[Callable[..., Any]],
        pre_event: Any,
    ):
        """Durably pause an already-authorized request before its implementation."""

        from hooks.tool_guard import ToolGuard

        try:
            # The executor is also used outside the FastAPI startup path.
            # create_all is idempotent and makes the new narrow tables
            # available before a privileged request can be accepted.
            init_db()
            arguments_json = _canonical_arguments(dict(request.arguments))
            created = _now()
            approval_id = f"approval-{uuid.uuid4().hex}"
            record = ToolApproval(
                approval_id=approval_id,
                request_id=request.request_id,
                tool_call_id=request.tool_call_id,
                tool_name=request.tool_name,
                arguments_json=arguments_json,
                requested_by=identity.subject_id,
                requested_role=getattr(identity.role, "value", str(identity.role)),
                agent_caller=agent_caller,
                source_type=source_type,
                status=ApprovalStatus.PENDING.value,
                created_at=_timestamp(created),
                expires_at=_timestamp(created + dt.timedelta(seconds=_ttl_seconds())),
            )
            with get_db_session() as session:
                session.add(record)
                # The audit row has a real FK to approval_id in fresh Phase 12
                # schemas. Flush the immutable parent before appending its
                # first lifecycle event; the surrounding transaction remains
                # atomic and fails closed on any database error.
                session.flush()
                self._audit(session, record, "APPROVAL_REQUESTED", ApprovalStatus.PENDING.value)
            if implementation is not None:
                self._implementation_overrides[approval_id] = implementation
            self._requester_identities[approval_id] = identity
            ToolGuard.record_pending_approval(pre_event, approval_id)
            return self._result_from_request(
                request,
                identity,
                "REQUIRES_APPROVAL",
                "REQUIRES_APPROVAL",
                approval_id=approval_id,
                reason="Privileged sandbox operation is pending ADMIN approval",
            )
        except Exception as exc:
            return self._result_from_request(
                request,
                identity,
                "FAILED",
                "FAIL_CLOSED",
                reason=f"Approval creation failed safely ({exc.__class__.__name__})",
            )

    def _expire_if_due(self, approval_id: str) -> bool:
        """Atomically expire only a still-pending record whose TTL elapsed."""

        now = _now()
        with get_db_session() as session:
            record = session.scalar(select(ToolApproval).where(ToolApproval.approval_id == approval_id))
            if record is None or record.status != ApprovalStatus.PENDING.value:
                return record is not None and record.status == ApprovalStatus.EXPIRED.value
            try:
                expires_at = dt.datetime.fromisoformat(record.expires_at)
            except (TypeError, ValueError):
                expires_at = now
            if expires_at > now:
                return False
            changed = session.execute(
                update(ToolApproval)
                .where(ToolApproval.id == record.id, ToolApproval.status == ApprovalStatus.PENDING.value)
                .values(status=ApprovalStatus.EXPIRED.value, reason="Approval request expired")
            ).rowcount
            if changed:
                record.status = ApprovalStatus.EXPIRED.value
                self._audit(session, record, "APPROVAL_EXPIRED", ApprovalStatus.EXPIRED.value, detail="TTL elapsed")
            return bool(changed)

    def _record(self, approval_id: str) -> Optional[ToolApproval]:
        with get_db_session() as session:
            return session.scalar(select(ToolApproval).where(ToolApproval.approval_id == approval_id))

    @staticmethod
    def _is_admin(identity: Any) -> bool:
        from security.tool_security import ToolRole

        return bool(identity and identity.authenticated and identity.role == ToolRole.ADMIN)

    def list_for_identity(self, identity: Any) -> list[dict[str, Any]]:
        """List metadata only; requester sees own records, ADMIN sees all."""

        try:
            with get_db_session() as session:
                statement = select(ToolApproval).order_by(ToolApproval.id.desc())
                if not self._is_admin(identity):
                    statement = statement.where(ToolApproval.requested_by == identity.subject_id)
                records = session.scalars(statement).all()
                return [
                    {
                        "approval_id": record.approval_id,
                        "request_id": record.request_id,
                        "tool_call_id": record.tool_call_id,
                        "tool_name": record.tool_name,
                        "requested_by": record.requested_by,
                        "requested_role": record.requested_role,
                        "status": record.status,
                        "decided_by": record.decided_by,
                        "created_at": record.created_at,
                        "decided_at": record.decided_at,
                        "expires_at": record.expires_at,
                    }
                    for record in records
                ]
        except Exception:
            return []

    def _decision_failure(self, approval_id: str, reason: str) -> ApprovalDecision:
        return ApprovalDecision(approval_id=approval_id, status="DENIED", result_status="DENIED", reason=reason)

    def reject(self, approval_id: str, decider: Any) -> ApprovalDecision:
        if not self._is_admin(decider):
            return self._decision_failure(approval_id, "Only a server-resolved ADMIN may reject")
        try:
            self._expire_if_due(approval_id)
            with get_db_session() as session:
                record = session.scalar(select(ToolApproval).where(ToolApproval.approval_id == approval_id))
                if record is None:
                    return self._decision_failure(approval_id, "Unknown approval")
                changed = session.execute(
                    update(ToolApproval)
                    .where(ToolApproval.id == record.id, ToolApproval.status == ApprovalStatus.PENDING.value)
                    .values(
                        status=ApprovalStatus.REJECTED.value,
                        decided_by=decider.subject_id,
                        decided_at=_timestamp(),
                        reason="Rejected by ADMIN",
                    )
                ).rowcount
                if not changed:
                    return self._decision_failure(approval_id, f"Approval is {record.status}")
                record.status = ApprovalStatus.REJECTED.value
                self._audit(session, record, "APPROVAL_REJECTED", ApprovalStatus.REJECTED.value, decided_by=decider.subject_id)
            return ApprovalDecision(approval_id=approval_id, status="REJECTED", result_status="REJECTED")
        except Exception as exc:
            return self._decision_failure(approval_id, f"Reject failed safely ({exc.__class__.__name__})")

    def approve(self, approval_id: str, decider: Any):
        """Claim one pending record, then execute exactly its stored request once."""

        from security.tool_security import (
            ACTIVE_TOOL_REGISTRY,
            SecureToolExecutor,
            ToolSecurityPolicy,
            resolve_server_identity,
        )

        if not self._is_admin(decider):
            return self._decision_failure(approval_id, "Only a server-resolved ADMIN may approve")
        try:
            self._expire_if_due(approval_id)
            with get_db_session() as session:
                record = session.scalar(select(ToolApproval).where(ToolApproval.approval_id == approval_id))
                if record is None:
                    return self._decision_failure(approval_id, "Unknown approval")
                claimed = session.execute(
                    update(ToolApproval)
                    .where(ToolApproval.id == record.id, ToolApproval.status == ApprovalStatus.PENDING.value)
                    .values(
                        status=ApprovalStatus.APPROVED.value,
                        decided_by=decider.subject_id,
                        decided_at=_timestamp(),
                    )
                ).rowcount
                if not claimed:
                    return self._decision_failure(approval_id, f"Approval is {record.status}")
                record.status = ApprovalStatus.APPROVED.value
                record.decided_by = decider.subject_id
                self._audit(session, record, "APPROVAL_APPROVED", ApprovalStatus.APPROVED.value, decided_by=decider.subject_id)
                self._audit(session, record, "APPROVAL_EXECUTION_STARTED", ApprovalStatus.APPROVED.value, decided_by=decider.subject_id)
        except Exception as exc:
            return self._decision_failure(approval_id, f"Approval lookup failed safely ({exc.__class__.__name__})")

        record = self._record(approval_id)
        if record is None:
            return self._decision_failure(approval_id, "Approval readback failed")
        requester = self._requester_identities.get(approval_id) or resolve_server_identity(record.requested_by)
        allowed, authorization_reason = ToolSecurityPolicy.authorize(requester, record.tool_name)
        if (
            not requester.authenticated
            or getattr(requester.role, "value", str(requester.role)) != record.requested_role
            or not allowed
            or not ToolSecurityPolicy.requires_approval(record.tool_name)
            or record.tool_name not in ACTIVE_TOOL_REGISTRY
        ):
            return self._fail_after_claim(record, decider.subject_id, f"Revalidation failed: {authorization_reason}")
        try:
            arguments = json.loads(record.arguments_json)
            stored_request = ToolRequest(
                request_id=record.request_id,
                tool_call_id=record.tool_call_id,
                tool_name=record.tool_name,
                arguments=arguments,
            )
        except Exception:
            return self._fail_after_claim(record, decider.subject_id, "Stored request is invalid")

        result = SecureToolExecutor().execute(
            stored_request,
            identity=requester,
            agent_caller=record.agent_caller,
            source_type=record.source_type,
            implementation=self._implementation_overrides.get(approval_id),
            approved_execution=True,
            approval_id=approval_id,
            raise_on_block=False,
        )
        if result.status == "COMPLETED":
            self._complete(record, decider.subject_id, result)
        else:
            self._fail_after_claim(record, decider.subject_id, "Execution did not complete", result=result)
        return result

    def _complete(self, record: ToolApproval, decider: str, result: Any) -> None:
        try:
            with get_db_session() as session:
                current = session.scalar(select(ToolApproval).where(ToolApproval.id == record.id))
                if current is None:
                    return
                current.status = ApprovalStatus.EXECUTED.value
                current.executed_at = _timestamp()
                current.result_status = result.status
                current.security_decision = result.security_decision
                self._audit(session, current, "APPROVAL_EXECUTED", ApprovalStatus.EXECUTED.value, decided_by=decider)
        except Exception:
            # The output already went through ToolGuard; do not retry it.
            pass

    def _fail_after_claim(
        self, record: ToolApproval, decider: str, reason: str, *, result: Any = None
    ):
        try:
            with get_db_session() as session:
                current = session.scalar(select(ToolApproval).where(ToolApproval.id == record.id))
                if current is not None:
                    current.status = ApprovalStatus.FAILED.value
                    current.executed_at = _timestamp()
                    current.result_status = getattr(result, "status", "FAILED")
                    current.security_decision = getattr(result, "security_decision", "FAIL_CLOSED")
                    current.reason = reason
                    self._audit(session, current, "APPROVAL_FAILED", ApprovalStatus.FAILED.value, decided_by=decider, detail=reason)
        except Exception:
            pass
        if result is not None:
            return result
        return self._decision_failure(record.approval_id, reason)

    def audit_events(self, approval_id: str) -> list[dict[str, str]]:
        with get_db_session() as session:
            events = session.scalars(
                select(ApprovalAuditLog)
                .where(ApprovalAuditLog.approval_id == approval_id)
                .order_by(ApprovalAuditLog.id)
            ).all()
            return [
                {"event_type": event.event_type, "status": event.status, "approval_id": event.approval_id}
                for event in events
            ]


__all__ = ["ApprovalDecision", "ApprovalStatus", "HITLApprovalService"]
