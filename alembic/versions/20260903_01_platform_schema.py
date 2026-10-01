"""Create the Phase 12 migration-managed platform schema safely."""

from alembic import op
import sqlalchemy as sa


revision = "20260903_01"
down_revision = None
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade() -> None:
    # Existing developer databases may contain Phase 5-11 tables without an
    # Alembic version.  This initial migration creates only missing tables and
    # never drops or rewrites existing user data.
    if not _has_table("security_logs"):
        op.create_table("security_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("request_id", sa.String(64), nullable=False), sa.Column("timestamp", sa.String(40), nullable=False), sa.Column("source", sa.String(64), nullable=False), sa.Column("target", sa.String(64), nullable=False), sa.Column("raw_input", sa.Text(), nullable=False), sa.Column("sanitized_input", sa.Text()), sa.Column("risk_score", sa.Float(), nullable=False), sa.Column("risk_level", sa.String(16), nullable=False), sa.Column("policy_decision", sa.String(16), nullable=False), sa.Column("rule_flags", sa.Text()), sa.Column("llm_flags", sa.Text()), sa.Column("latency_ms", sa.Float()))
        op.create_index("ix_security_logs_request_id", "security_logs", ["request_id"])
        op.create_index("ix_security_logs_timestamp", "security_logs", ["timestamp"])
    if not _has_table("tool_logs"):
        op.create_table("tool_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("request_id", sa.String(64), nullable=False), sa.Column("timestamp", sa.String(40), nullable=False), sa.Column("tool_name", sa.String(128), nullable=False), sa.Column("agent_caller", sa.String(64), nullable=False), sa.Column("raw_args", sa.Text()), sa.Column("pre_exec_status", sa.String(16), nullable=False), sa.Column("post_exec_status", sa.String(16), nullable=False), sa.Column("status", sa.String(16), nullable=False), sa.Column("output_sanitized", sa.Boolean(), nullable=False), sa.Column("threat_detected", sa.Text()), sa.Column("pre_exec_flags", sa.Text()), sa.Column("post_exec_flags", sa.Text()), sa.Column("tool_execution_id", sa.String(64)), sa.Column("content_id", sa.String(64)), sa.Column("source_type", sa.String(64)), sa.Column("source_name", sa.String(128)), sa.Column("trust_level", sa.String(32)), sa.Column("risk_score", sa.Float()), sa.Column("risk_level", sa.String(16)), sa.Column("decision", sa.String(16)), sa.Column("findings", sa.Text()), sa.Column("transforms", sa.Text()), sa.Column("latency_ms", sa.Float()), sa.Column("tool_call_id", sa.String(64)), sa.Column("subject_id", sa.String(128)), sa.Column("resolved_role", sa.String(16)), sa.Column("authorization_decision", sa.String(32)), sa.Column("argument_security_decision", sa.String(32)), sa.Column("execution_status", sa.String(32)), sa.Column("output_security_decision", sa.String(32)))
        for column in ("request_id", "timestamp", "tool_execution_id", "content_id", "tool_call_id"):
            op.create_index(f"ix_tool_logs_{column}", "tool_logs", [column])
    if not _has_table("handoff_logs"):
        op.create_table("handoff_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("request_id", sa.String(64), nullable=False), sa.Column("handoff_id", sa.String(64), unique=True), sa.Column("timestamp", sa.String(40), nullable=False), sa.Column("from_agent", sa.String(64), nullable=False), sa.Column("to_agent", sa.String(64), nullable=False), sa.Column("intercepted_field", sa.String(64)), sa.Column("risk_score", sa.Float(), nullable=False), sa.Column("risk_level", sa.String(16), nullable=False), sa.Column("action_taken", sa.String(16), nullable=False), sa.Column("sanitized", sa.Boolean(), nullable=False), sa.Column("detected_flags", sa.Text()), sa.Column("reason", sa.Text()), sa.Column("latency_ms", sa.Float()))
        for column in ("request_id", "handoff_id", "timestamp"):
            op.create_index(f"ix_handoff_logs_{column}", "handoff_logs", [column])
    if not _has_table("alert_logs"):
        op.create_table("alert_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("timestamp", sa.String(40), nullable=False), sa.Column("severity", sa.String(16), nullable=False), sa.Column("title", sa.String(256), nullable=False), sa.Column("description", sa.Text(), nullable=False), sa.Column("request_id", sa.String(64)), sa.Column("alert_type", sa.String(64)), sa.Column("source_component", sa.String(64)))
        for column in ("timestamp", "severity", "request_id"):
            op.create_index(f"ix_alert_logs_{column}", "alert_logs", [column])
    if not _has_table("tool_approvals"):
        op.create_table("tool_approvals", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("approval_id", sa.String(64), nullable=False, unique=True), sa.Column("request_id", sa.String(64), nullable=False), sa.Column("tool_call_id", sa.String(64), nullable=False), sa.Column("tool_name", sa.String(128), nullable=False), sa.Column("arguments_json", sa.Text(), nullable=False), sa.Column("requested_by", sa.String(128), nullable=False), sa.Column("requested_role", sa.String(16), nullable=False), sa.Column("agent_caller", sa.String(64), nullable=False), sa.Column("source_type", sa.String(64), nullable=False), sa.Column("status", sa.String(16), nullable=False), sa.Column("decided_by", sa.String(128)), sa.Column("created_at", sa.String(40), nullable=False), sa.Column("decided_at", sa.String(40)), sa.Column("executed_at", sa.String(40)), sa.Column("expires_at", sa.String(40)), sa.Column("result_status", sa.String(32)), sa.Column("security_decision", sa.String(32)), sa.Column("reason", sa.Text()), sa.CheckConstraint("status IN ('PENDING','APPROVED','REJECTED','EXECUTED','EXPIRED','FAILED')", name="ck_tool_approvals_status"))
        for column in ("approval_id", "request_id", "tool_call_id", "requested_by", "status", "created_at", "expires_at"):
            op.create_index(f"ix_tool_approvals_{column}", "tool_approvals", [column])
    if not _has_table("approval_audit_logs"):
        op.create_table("approval_audit_logs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("approval_id", sa.String(64), sa.ForeignKey("tool_approvals.approval_id", ondelete="RESTRICT"), nullable=False), sa.Column("request_id", sa.String(64), nullable=False), sa.Column("tool_call_id", sa.String(64), nullable=False), sa.Column("tool_name", sa.String(128), nullable=False), sa.Column("event_type", sa.String(32), nullable=False), sa.Column("status", sa.String(16), nullable=False), sa.Column("requested_by", sa.String(128), nullable=False), sa.Column("decided_by", sa.String(128)), sa.Column("timestamp", sa.String(40), nullable=False), sa.Column("detail", sa.Text()))
        for column in ("approval_id", "request_id", "tool_call_id", "event_type", "status", "timestamp"):
            op.create_index(f"ix_approval_audit_logs_{column}", "approval_audit_logs", [column])
    if not _has_table("platform_events"):
        op.create_table("platform_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("event_id", sa.String(64), nullable=False, unique=True), sa.Column("request_id", sa.String(64)), sa.Column("event_type", sa.String(64), nullable=False), sa.Column("timestamp", sa.String(40), nullable=False), sa.Column("component", sa.String(64), nullable=False), sa.Column("risk_score", sa.Float()), sa.Column("risk_level", sa.String(16)), sa.Column("decision", sa.String(32)), sa.Column("tool_call_id", sa.String(64)), sa.Column("handoff_id", sa.String(64)), sa.Column("approval_id", sa.String(64)), sa.Column("metadata_json", sa.Text(), nullable=False), sa.CheckConstraint("length(event_type) > 0", name="ck_platform_events_type"))
        for column in ("event_id", "request_id", "event_type", "timestamp", "tool_call_id", "handoff_id", "approval_id"):
            op.create_index(f"ix_platform_events_{column}", "platform_events", [column])


def downgrade() -> None:
    # Deliberately non-destructive: this migration can adopt a pre-Alembic DB.
    # Downgrading must never remove developer telemetry or approval history.
    pass
