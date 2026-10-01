"""
schema/interception.py
======================
AgentShield Phase 4 — Structured Audit Event Schemas

Defines Pydantic models for logging all Phase 4 security interception events:
  - AgentHandoffEvent  : Audit record for every inter-agent boundary crossing.
  - ToolExecutionEvent : Audit record for every guarded tool invocation.

These models serve as the canonical data contract between security hooks and
the audit trail / logging subsystem. They are intentionally lean and serializable
to JSON for downstream SIEM / observability integrations.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from state import Decision, RiskLevel


# ---------------------------------------------------------------------------
# AgentHandoffEvent
# ---------------------------------------------------------------------------

class AgentHandoffEvent(BaseModel):
    """
    Captures the security disposition of a single inter-agent state handoff.

    Lifecycle:
        researcher → planner → writer → finalizer

    One event is recorded at each boundary transition. The event is emitted by
    InterAgentGuard.inspect_handoff() before the receiving agent node begins
    execution.
    """

    source_agent: str = Field(
        description="Name of the agent that produced the outgoing payload."
    )
    target_agent: str = Field(
        description="Name of the agent that will consume the payload."
    )
    request_id: str = Field(description="Ingress request correlation identifier")
    handoff_id: str = Field(description="Unique identifier for this transition")
    timestamp: str = Field(
        description="ISO-8601 UTC timestamp at which the handoff was intercepted."
    )
    intercepted_field: str = Field(description="Inspected AgentState key")
    risk_score: float = Field(
        description="Composite risk score (0.0 – 1.0) computed by RiskScorer "
                    "for the intercepted payload."
    )
    risk_level: RiskLevel = Field(
        description="Human-readable risk severity band: LOW | MEDIUM | HIGH | CRITICAL."
    )
    decision: Decision = Field(
        description="Policy enforcement decision: ALLOW | SANITIZE | REVIEW | BLOCK."
    )
    sanitized: bool = Field(
        description="True if the payload was modified/sanitized before forwarding."
    )
    flags: List[str] = Field(
        default_factory=list,
        description="Rule-based and context flags triggered during analysis."
    )
    findings: List[str] = Field(
        default_factory=list,
        description="Normalized finding categories emitted by the canonical stack."
    )
    latency_ms: float = Field(default=0.0, description="Guard processing latency")
    blocked: bool = Field(default=False)
    reason: str = Field(
        default="",
        description="Human-readable explanation of the policy action taken."
    )

    # Compatibility properties for Phase 4/5 callers and the existing UI.
    @property
    def from_agent(self) -> str:
        return self.source_agent

    @property
    def to_agent(self) -> str:
        return self.target_agent

    @property
    def action_taken(self) -> Decision:
        return self.decision

    @property
    def detected_flags(self) -> List[str]:
        return self.flags


# ---------------------------------------------------------------------------
# ToolExecutionEvent
# ---------------------------------------------------------------------------

class ToolExecutionEvent(BaseModel):
    """
    Captures the security disposition of a single tool invocation.

    A ToolExecutionEvent is composed of two sub-phases recorded as a single
    combined audit record:
      - Pre-execution  : input argument validation (SQL injection, path traversal, …)
      - Post-execution : indirect prompt injection scan on raw tool output

    The 'status' field reflects the worst-case outcome across both phases.
    """

    tool_name: str = Field(
        description="Registered name of the invoked tool, "
                    "e.g. 'web_search_tool', 'mock_database_tool'."
    )
    agent_caller: str = Field(
        description="Name of the agent that triggered the tool call, "
                    "e.g. 'researcher'."
    )
    timestamp: str = Field(
        description="ISO-8601 UTC timestamp at which the tool call was intercepted."
    )
    raw_args: Dict[str, Any] = Field(
        description="Raw keyword arguments passed to the tool before sanitization."
    )
    pre_exec_status: str = Field(
        description="Pre-execution guard outcome: PASSED | BLOCKED | SANITIZED."
    )
    post_exec_status: str = Field(
        default="PASSED",
        description="Post-execution guard outcome: PASSED | SANITIZED."
    )
    status: str = Field(
        description="Overall tool execution status (worst-case): PASSED | BLOCKED | SANITIZED."
    )
    mitigated_threat: Optional[str] = Field(
        default=None,
        description="Description of the specific threat neutralized, or None if no threat detected."
    )
    pre_exec_flags: List[str] = Field(
        default_factory=list,
        description="Security flags raised by pre-execution argument validation."
    )
    post_exec_flags: List[str] = Field(
        default_factory=list,
        description="Indirect injection flags raised by post-execution output scan."
    )
    output_sanitized: bool = Field(
        default=False,
        description="True if the tool output was modified before returning to the agent."
    )
    # Phase 8: output inspection is a separate, correlated boundary.  These
    # fields deliberately contain metadata and finding categories only; raw
    # external content and secret values are not persisted in the audit event.
    event_id: Optional[str] = Field(default=None)
    request_id: Optional[str] = Field(default=None)
    tool_execution_id: Optional[str] = Field(default=None)
    content_id: Optional[str] = Field(default=None)
    source_type: Optional[str] = Field(default=None)
    source_name: Optional[str] = Field(default=None)
    trust_level: Optional[str] = Field(default=None)
    risk_score: Optional[float] = Field(default=None)
    risk_level: Optional[RiskLevel] = Field(default=None)
    decision: Optional[Decision] = Field(default=None)
    findings: List[str] = Field(default_factory=list)
    transforms: List[str] = Field(default_factory=list)
    latency_ms: float = Field(default=0.0)
    # Phase 10 server-side tool-security correlation.  These values are
    # resolved by the executor, never accepted from tool arguments.
    tool_call_id: Optional[str] = Field(default=None)
    subject_id: Optional[str] = Field(default=None)
    resolved_role: Optional[str] = Field(default=None)
    authorization_decision: str = Field(default="NOT_RUN")
    argument_security_decision: str = Field(default="NOT_RUN")
    execution_status: str = Field(default="NOT_RUN")
    output_security_decision: str = Field(default="NOT_RUN")


class ToolRequest(BaseModel):
    """Server-created structured request accepted by the tool executor.

    Authorization metadata is intentionally absent: the caller cannot place a
    role or privilege claim in this model and have it trusted.
    """

    request_id: str = Field(min_length=1)
    tool_call_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments: Dict[str, Any] = Field(default_factory=dict)
