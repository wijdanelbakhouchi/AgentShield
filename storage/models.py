"""
storage/models.py
=================
AgentShield Phase 5 — SQLAlchemy ORM Table Definitions

Defines four persistent tables that capture the complete security telemetry
of every pipeline run:

  SecurityLog  — Entry gateway interception events (one per user request)
  ToolLog      — Per-tool-call guard events (one per tool invocation)
  HandoffLog   — Inter-agent boundary events (one per agent handoff)
  AlertLog     — Generated security alerts (one per triggered alert)

All timestamps are stored as ISO-8601 UTC strings for portability.
JSON columns (rule_flags, llm_flags, detected_flags, raw_args) are stored
as TEXT with JSON serialization handled by the EventLogger.
"""

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase


# ---------------------------------------------------------------------------
# SQLAlchemy 2.x Declarative Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Shared declarative base for all AgentShield ORM models."""
    pass


# ---------------------------------------------------------------------------
# Table 1: SecurityLog — Entry Gateway Events
# ---------------------------------------------------------------------------

class SecurityLog(Base):
    """
    Records one row for every request intercepted at the entry security gateway.
    Captures the full Phase 1–3 analysis result in a single flat row.
    """
    __tablename__ = "security_logs"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    request_id    = Column(String(64),  nullable=False, index=True,
                           comment="Unique UUID for this pipeline run")
    timestamp     = Column(String(40),  nullable=False, index=True,
                           comment="ISO-8601 UTC timestamp of interception")
    source        = Column(String(64),  nullable=False, default="user",
                           comment="Origin of the request, e.g. 'user'")
    target        = Column(String(64),  nullable=False, default="agent_orchestrator")

    # Raw vs sanitized input
    raw_input       = Column(Text, nullable=False, comment="Unmodified user input")
    sanitized_input = Column(Text, nullable=True,  comment="Sanitized/modified input forwarded to agents")

    # Risk analysis results
    risk_score      = Column(Float,      nullable=False, default=0.0,
                             comment="Composite risk score 0.0–1.0")
    risk_level      = Column(String(16), nullable=False, default="LOW",
                             comment="LOW | MEDIUM | HIGH | CRITICAL")
    policy_decision = Column(String(16), nullable=False, default="ALLOW",
                             comment="ALLOW | SANITIZE | REVIEW | BLOCK")

    # JSON-encoded flag lists (stored as TEXT)
    rule_flags = Column(Text, nullable=True,
                        comment="JSON list of triggered rule-based flags")
    llm_flags  = Column(Text, nullable=True,
                        comment="JSON dict of LLM classification result")

    # Performance telemetry
    latency_ms = Column(Float, nullable=True,
                        comment="Total gateway processing time in milliseconds")

    def __repr__(self) -> str:
        return (
            f"<SecurityLog id={self.id} request_id={self.request_id} "
            f"risk={self.risk_score:.2f} [{self.risk_level}] "
            f"decision={self.policy_decision}>"
        )


# ---------------------------------------------------------------------------
# Table 2: ToolLog — Tool Execution Guard Events
# ---------------------------------------------------------------------------

class ToolLog(Base):
    """
    Records one row for each tool invocation guarded by Phase 4 ToolGuard.
    Captures both pre-execution (input validation) and post-execution
    (output injection scan) guard results.
    """
    __tablename__ = "tool_logs"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    request_id   = Column(String(64), nullable=False, index=True,
                          comment="Links to the SecurityLog row for this pipeline run")
    timestamp    = Column(String(40), nullable=False, index=True)
    tool_name    = Column(String(128), nullable=False,
                          comment="Registered tool name, e.g. 'web_search_tool'")
    agent_caller = Column(String(64),  nullable=False,
                          comment="Agent that invoked this tool, e.g. 'researcher'")

    # Raw args as JSON text (always the original, pre-sanitization args)
    raw_args = Column(Text, nullable=True,
                      comment="JSON-encoded keyword arguments passed to the tool")

    # Guard outcomes
    pre_exec_status  = Column(String(16), nullable=False, default="PASSED",
                               comment="PASSED | BLOCKED | SANITIZED")
    post_exec_status = Column(String(16), nullable=False, default="PASSED")
    status           = Column(String(16), nullable=False, default="PASSED",
                               comment="Worst-case overall: PASSED | BLOCKED | SANITIZED")
    output_sanitized = Column(Boolean, nullable=False, default=False)

    # Threat details
    threat_detected = Column(Text, nullable=True,
                             comment="Human-readable description of detected/mitigated threat")
    pre_exec_flags  = Column(Text, nullable=True, comment="JSON list of pre-exec flag IDs")
    post_exec_flags = Column(Text, nullable=True, comment="JSON list of post-exec flag IDs")

    # Phase 8 indirect-content inspection correlation.  No raw tool result is
    # stored here: these columns keep only provenance and security evidence.
    tool_execution_id = Column(String(64), nullable=True, index=True)
    content_id = Column(String(64), nullable=True, index=True)
    source_type = Column(String(64), nullable=True)
    source_name = Column(String(128), nullable=True)
    trust_level = Column(String(32), nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(16), nullable=True)
    decision = Column(String(16), nullable=True)
    findings = Column(Text, nullable=True)
    transforms = Column(Text, nullable=True)
    latency_ms = Column(Float, nullable=True)

    # Phase 10 server-side identity/RBAC and execution correlation.  These are
    # metadata only; secrets and raw tool outputs are never persisted.
    tool_call_id = Column(String(64), nullable=True, index=True)
    subject_id = Column(String(128), nullable=True)
    resolved_role = Column(String(16), nullable=True)
    authorization_decision = Column(String(32), nullable=True)
    argument_security_decision = Column(String(32), nullable=True)
    execution_status = Column(String(32), nullable=True)
    output_security_decision = Column(String(32), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ToolLog id={self.id} tool={self.tool_name} "
            f"caller={self.agent_caller} status={self.status}>"
        )


# ---------------------------------------------------------------------------
# Phase 11 — Stateful HITL approvals and audit events
# ---------------------------------------------------------------------------

class ToolApproval(Base):
    """Persistent immutable request awaiting an ADMIN HITL decision."""

    __tablename__ = "tool_approvals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    approval_id = Column(String(64), nullable=False, unique=True, index=True)
    request_id = Column(String(64), nullable=False, index=True)
    tool_call_id = Column(String(64), nullable=False, index=True)
    tool_name = Column(String(128), nullable=False)
    arguments_json = Column(Text, nullable=False)
    requested_by = Column(String(128), nullable=False, index=True)
    requested_role = Column(String(16), nullable=False)
    agent_caller = Column(String(64), nullable=False, default="unknown_agent")
    source_type = Column(String(64), nullable=False, default="tool_output")
    status = Column(String(16), nullable=False, index=True, default="PENDING")
    decided_by = Column(String(128), nullable=True)
    created_at = Column(String(40), nullable=False, index=True)
    decided_at = Column(String(40), nullable=True)
    executed_at = Column(String(40), nullable=True)
    expires_at = Column(String(40), nullable=True, index=True)
    result_status = Column(String(32), nullable=True)
    security_decision = Column(String(32), nullable=True)
    reason = Column(Text, nullable=True)


class ApprovalAuditLog(Base):
    """Append-only state-transition audit for a persistent tool approval."""

    __tablename__ = "approval_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    approval_id = Column(
        String(64),
        ForeignKey("tool_approvals.approval_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    request_id = Column(String(64), nullable=False, index=True)
    tool_call_id = Column(String(64), nullable=False, index=True)
    tool_name = Column(String(128), nullable=False)
    event_type = Column(String(32), nullable=False, index=True)
    status = Column(String(16), nullable=False, index=True)
    requested_by = Column(String(128), nullable=False)
    decided_by = Column(String(128), nullable=True)
    timestamp = Column(String(40), nullable=False, index=True)
    detail = Column(Text, nullable=True)


class PlatformEvent(Base):
    """Canonical secret-safe event envelope used to reconstruct a request."""

    __tablename__ = "platform_events"
    __table_args__ = (
        CheckConstraint("length(event_type) > 0", name="ck_platform_events_type"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), nullable=False, unique=True, index=True)
    request_id = Column(String(64), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    timestamp = Column(String(40), nullable=False, index=True)
    component = Column(String(64), nullable=False)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(16), nullable=True)
    decision = Column(String(32), nullable=True)
    tool_call_id = Column(String(64), nullable=True, index=True)
    handoff_id = Column(String(64), nullable=True, index=True)
    approval_id = Column(String(64), nullable=True, index=True)
    metadata_json = Column(Text, nullable=False, default="{}")


# ---------------------------------------------------------------------------
# Table 3: HandoffLog — Inter-Agent Boundary Events
# ---------------------------------------------------------------------------

class HandoffLog(Base):
    """
    Records one row for each inter-agent state handoff inspected by Phase 4
    InterAgentGuard.  Three rows per pipeline run (researcher→planner,
    planner→writer, writer→finalizer).
    """
    __tablename__ = "handoff_logs"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    request_id   = Column(String(64), nullable=False, index=True)
    handoff_id   = Column(String(64), nullable=True, index=True, unique=True,
                          comment="Unique identifier for this request transition")
    timestamp    = Column(String(40), nullable=False, index=True)
    from_agent   = Column(String(64), nullable=False)
    to_agent     = Column(String(64), nullable=False)
    intercepted_field = Column(String(64), nullable=True,
                               comment="AgentState key that was inspected")

    # Risk assessment
    risk_score  = Column(Float,      nullable=False, default=0.0)
    risk_level  = Column(String(16), nullable=False, default="LOW")
    action_taken = Column(String(16), nullable=False, default="ALLOW",
                          comment="ALLOW | SANITIZE | REVIEW | BLOCK")
    sanitized   = Column(Boolean, nullable=False, default=False)

    # Flags as JSON text
    detected_flags = Column(Text, nullable=True,
                            comment="JSON list of rule + context flags triggered")
    reason         = Column(Text, nullable=True, comment="Policy decision reason text")
    latency_ms     = Column(Float, nullable=True,
                            comment="Inter-agent guard processing latency")

    def __repr__(self) -> str:
        return (
            f"<HandoffLog id={self.id} {self.from_agent}→{self.to_agent} "
            f"risk={self.risk_score:.2f} action={self.action_taken}>"
        )


# ---------------------------------------------------------------------------
# Table 4: AlertLog — Generated Security Alerts
# ---------------------------------------------------------------------------

class AlertLog(Base):
    """
    Records one row for each security alert emitted by the Phase 5 AlertEngine.
    Alerts are generated for BLOCK decisions, high-severity injections, and
    repeated tool abuse patterns.

    Severity levels: CRITICAL > HIGH > MEDIUM > LOW
    """
    __tablename__ = "alert_logs"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(String(40), nullable=False, index=True)
    severity    = Column(String(16), nullable=False, index=True,
                         comment="CRITICAL | HIGH | MEDIUM | LOW")
    title       = Column(String(256), nullable=False)
    description = Column(Text,        nullable=False)
    request_id  = Column(String(64),  nullable=True, index=True,
                         comment="Associated pipeline run request_id, if applicable")
    alert_type  = Column(String(64),  nullable=True,
                         comment="GATEWAY_BLOCK | TOOL_BLOCK | HANDOFF_BLOCK | INJECTION | etc.")
    source_component = Column(String(64), nullable=True,
                              comment="Which component triggered the alert")

    def __repr__(self) -> str:
        return (
            f"<AlertLog id={self.id} severity={self.severity} "
            f"title='{self.title[:40]}...'>"
        )
