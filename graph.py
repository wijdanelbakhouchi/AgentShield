"""Server-controlled, zero-trust LangGraph workflow.

Active topology::

    START → researcher → guard_researcher_planner → planner
          → guard_planner_writer → writer → guard_writer_finalizer
          → finalizer → END

Each explicit guard node uses the one canonical ``InterAgentGuard`` service.
Conditional edges terminate safely on BLOCK/REVIEW; target agents are never
invoked after a rejected handoff.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Callable, Dict, Mapping

from langgraph.graph import END, START, StateGraph

from agents import finalizer_node, planner_node, research_node, writer_node
from config import PROVENANCE_ENABLED
from hooks.inter_agent_guard import InterAgentGuard
from security.provenance import Origin, ProvenanceTracker, get_provenance_tracker
from state import AgentHandoff, AgentState, Decision, HandoffSecurityResult, RiskLevel, TrustLevel

# Which prior state fields feed each agent node.  This topology is frozen for
# the research testbed; provenance derivation relies on it to compute taint.
AGENT_INPUT_FIELDS: Mapping[str, tuple[str, ...]] = {
    "researcher": ("user_query", "external_context"),
    "planner": ("user_query", "research_data"),
    "writer": ("user_query", "research_data", "plan"),
    "finalizer": ("user_query", "draft_response"),
}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _request_id(state: AgentState) -> str:
    return str(state.get("request_id") or f"req-{uuid.uuid4().hex[:12]}")


def _register_agent_provenance(
    tracker: ProvenanceTracker,
    state: AgentState,
    *,
    agent_name: str,
    output_field: str,
    value: str,
) -> Dict[str, object]:
    """Derive message-level provenance for one agent's produced field.

    The output inherits the taint of its declared inputs (see
    ``AGENT_INPUT_FIELDS``).  The researcher additionally consumes guarded
    tool outputs, so its output is always derived from at least one TOOL-
    origin message.  Returns a state delta with ``provenance_by_field`` and
    ``provenance_events`` updates.
    """
    if not PROVENANCE_ENABLED or not value:
        return {}
    request_id = _request_id(state)
    provenance_by_field = dict(state.get("provenance_by_field") or {})
    provenance_events = list(state.get("provenance_events") or [])
    parent_ids: list[str] = []
    for field in AGENT_INPUT_FIELDS.get(agent_name, ()):
        record = provenance_by_field.get(field)
        if record and record.get("message_id"):
            parent_ids.append(str(record["message_id"]))
            continue
        # Lazily register ingress provenance for content that entered the
        # system at this request (user task, uploaded/inspected context).
        if field == "user_query" and state.get("user_query"):
            ingress = tracker.ingress(
                tracker=tracker,
                field="user_query",
                origin=Origin.USER,
                request_id=request_id,
                trust_level=TrustLevel.USER_CONTROLLED,
                attack_id=state.get("attack_id") or None,
            )
            provenance_by_field[field] = ingress.summary()
            parent_ids.append(ingress.message_id)
        elif field == "external_context" and state.get("external_context"):
            ingress = tracker.ingress(
                tracker=tracker,
                field="external_context",
                origin=Origin.DOCUMENT,
                request_id=request_id,
                trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
                attack_id=state.get("attack_id") or None,
            )
            provenance_by_field[field] = ingress.summary()
            parent_ids.append(ingress.message_id)
    if agent_name == "researcher":
        tool_message_id = f"tool-output-{request_id}"
        if tracker.get(tool_message_id) is None:
            tracker.ingress(
                tracker=tracker,
                field="tool_outputs",
                origin=Origin.TOOL,
                request_id=request_id,
                trust_level=TrustLevel.EXTERNAL_UNTRUSTED,
                message_id=tool_message_id,
            )
        parent_ids.append(tool_message_id)
    provenance = tracker.derive(
        parent_ids=parent_ids,
        field=output_field,
        origin=Origin.AGENT,
        source_agent=agent_name,
        request_id=request_id,
        attack_id=state.get("attack_id") or None,
    )
    return {
        "provenance_by_field": {**provenance_by_field, output_field: provenance.summary()},
        "provenance_events": provenance_events + [provenance.summary()],
    }


def _agent_node(
    agent_name: str,
    node_fn: Callable[[AgentState], dict],
    output_field: str,
) -> Callable[[AgentState], dict]:
    """Run an agent while allowing it to write only its declared output field."""

    def invoke(state: AgentState) -> dict:
        request_id = _request_id(state)
        try:
            raw_output = node_fn(state) or {}
            # Security and graph-control fields are server-owned. Natural
            # language agent output cannot replace request IDs, decisions,
            # roles, routes, or handoff metadata.
            raw_value = raw_output.get(output_field, "")
            value = (
                dict(raw_value)
                if output_field == "final_output" and isinstance(raw_value, dict)
                else str(raw_value or "")
            )
            update = {output_field: value}
            if "evidence_items" in raw_output:
                update["evidence_items"] = raw_output["evidence_items"]
            if "rejected_evidence" in raw_output:
                update["rejected_evidence"] = raw_output["rejected_evidence"]
            if "answer_validation" in raw_output:
                update["answer_validation"] = raw_output["answer_validation"]
            if "output_security" in raw_output:
                update["output_security"] = raw_output["output_security"]
            if not state.get("request_id"):
                update["request_id"] = request_id
            if agent_name == "finalizer":
                update["workflow_status"] = "COMPLETED"
            update.update(
                _register_agent_provenance(
                    get_provenance_tracker(),
                    state,
                    agent_name=agent_name,
                    output_field=output_field,
                    value=str(value or ""),
                )
            )
            return update
        except Exception as exc:
            # A tool-output boundary has already emitted its canonical event;
            # preserve its containment decision instead of collapsing it into a
            # generic workflow failure. No handoff/target agent is invoked.
            from hooks.tool_guard import ToolOutputBlockedError

            if isinstance(exc, ToolOutputBlockedError):
                decision = exc.result.decision
                return {
                    "request_id": request_id,
                    "workflow_status": (
                        "REVIEW_REQUIRED" if decision == Decision.REVIEW else "BLOCKED"
                    ),
                    "blocked_at": f"{agent_name} tool output",
                    "blocked_reason": exc.result.reason,
                    output_field: "",
                }
            return {
                "request_id": request_id,
                "workflow_status": "FAILED",
                "blocked_at": agent_name,
                "blocked_reason": f"{agent_name} execution failed safely ({exc.__class__.__name__})",
                output_field: "",
            }

    invoke.__name__ = agent_name
    return invoke


def _handoff_guard_node(
    source_agent: str,
    target_agent: str,
    field_name: str,
    security_enabled: bool = True,
) -> Callable[[AgentState], dict]:
    """Build an explicit graph boundary that delegates to InterAgentGuard."""

    def guard(state: AgentState) -> dict:
        if state.get("workflow_status") in {"FAILED", "BLOCKED", "REVIEW_REQUIRED"}:
            return {}
        request_id = _request_id(state)
        content = str(state.get(field_name, "") or "")
        provenance_by_field = dict(state.get("provenance_by_field") or {})
        source_provenance = provenance_by_field.get(field_name) or {}
        handoff = AgentHandoff(
            handoff_id=f"handoff-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            source_agent=source_agent,
            target_agent=target_agent,
            content=content,
            timestamp=_utc_now(),
            provenance=source_provenance,
        )
        if not security_enabled:
            # Explicit experiment configuration: execute the same graph and
            # agents while omitting AgentShield intervention boundaries. The
            # baseline never reaches the production API path.
            result = HandoffSecurityResult(
                request_id=request_id,
                handoff_id=handoff.handoff_id,
                source_agent=source_agent,
                target_agent=target_agent,
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                decision=Decision.ALLOW,
                original_content=content,
                safe_content=content,
                timestamp=_utc_now(),
                reason="Baseline experiment: AgentShield handoff intervention disabled",
            )
        else:
            try:
                result = InterAgentGuard.evaluate_handoff(
                    handoff,
                    intercepted_field=field_name,
                )
            except Exception as exc:  # defense-in-depth if the service boundary itself is replaced
                result = HandoffSecurityResult(
                    request_id=request_id,
                    handoff_id=handoff.handoff_id,
                    source_agent=source_agent,
                    target_agent=target_agent,
                    risk_score=1.0,
                    risk_level=RiskLevel.CRITICAL,
                    decision=Decision.BLOCK,
                    flags=["SECURITY_ERROR"],
                    findings=["SECURITY_ERROR"],
                    original_content=content,
                    timestamp=_utc_now(),
                    blocked=True,
                    reason=f"Inter-agent security evaluation failed closed: {exc.__class__.__name__}",
                )
                InterAgentGuard._emit_audit(result, intercepted_field=field_name)

        events = list(state.get("handoff_events", []))
        event = None
        # The service already emitted the authoritative event. Copy the newest
        # event by matching this handoff ID rather than trusting agent state.
        from hooks.inter_agent_guard import AGENT_HANDOFF_AUDIT_LOG

        if AGENT_HANDOFF_AUDIT_LOG and AGENT_HANDOFF_AUDIT_LOG[-1].handoff_id == result.handoff_id:
            event = AGENT_HANDOFF_AUDIT_LOG[-1].model_dump(mode="json")
        if event is not None:
            events.append(event)

        result_state: Dict[str, object] = {
            "request_id": request_id,
            "handoff_events": events,
            "handoff_results": list(state.get("handoff_results", []))
            + [result.model_dump(mode="json", exclude={"original_content", "safe_content"})],
            "security_context": {
                **dict(state.get("security_context", {})),
                "request_id": request_id,
                "last_handoff_id": result.handoff_id,
                "last_decision": result.decision.value,
                "last_source_agent": source_agent,
                "last_target_agent": target_agent,
            },
        }

        if result.decision in {Decision.ALLOW, Decision.SANITIZE}:
            # Only the exact content returned by the canonical policy decision
            # is forwarded. For SANITIZE this is never the original unsafe text.
            result_state[field_name] = result.safe_content or ""
            result_state["workflow_status"] = "RUNNING"
        elif result.decision == Decision.REVIEW:
            result_state.update(
                {
                    "workflow_status": "REVIEW_REQUIRED",
                    "blocked_at": f"{source_agent} → {target_agent}",
                    "blocked_reason": result.reason or "Human review is required before continuation.",
                }
            )
        else:
            result_state.update(
                {
                    "workflow_status": "BLOCKED",
                    "blocked_at": f"{source_agent} → {target_agent}",
                    "blocked_reason": result.reason or "Inter-agent handoff blocked by policy.",
                }
            )
        return result_state

    guard.__name__ = f"guard_{source_agent}_{target_agent}"
    return guard


def _route_guard(state: AgentState) -> str:
    return "continue" if state.get("workflow_status") == "RUNNING" else "terminate"


def _workflow_terminated(state: AgentState) -> dict:
    status = str(state.get("workflow_status") or "FAILED")
    if status == "BLOCKED":
        message = "Inter-agent handoff blocked by AgentShield policy."
    elif status == "REVIEW_REQUIRED":
        message = "Inter-agent handoff requires human review before continuation."
    else:
        status = "FAILED"
        message = "Agent workflow terminated safely before downstream execution."
    return {
        "workflow_status": status,
        "final_output": {
            "status": status,
            "request_id": state.get("request_id"),
            "blocked_at": state.get("blocked_at"),
            "reason": state.get("blocked_reason") or message,
        },
    }


def build_graph(
    agent_nodes: Mapping[str, Callable[[AgentState], dict]] | None = None,
    *,
    security_enabled: bool = True,
):
    """Build and compile the guarded workflow.

    ``agent_nodes`` is a development-test seam for deterministic agent output;
    production uses the four repository agent implementations above.
    """
    functions = {
        "researcher": research_node,
        "planner": planner_node,
        "writer": writer_node,
        "finalizer": finalizer_node,
    }
    if agent_nodes:
        functions.update(agent_nodes)

    workflow = StateGraph(AgentState)
    workflow.add_node("researcher", _agent_node("researcher", functions["researcher"], "research_data"))
    workflow.add_node("guard_researcher_planner", _handoff_guard_node("researcher", "planner", "research_data", security_enabled))
    workflow.add_node("planner", _agent_node("planner", functions["planner"], "plan"))
    workflow.add_node("guard_planner_writer", _handoff_guard_node("planner", "writer", "plan", security_enabled))
    workflow.add_node("writer", _agent_node("writer", functions["writer"], "draft_response"))
    workflow.add_node("guard_writer_finalizer", _handoff_guard_node("writer", "finalizer", "draft_response", security_enabled))
    workflow.add_node("finalizer", _agent_node("finalizer", functions["finalizer"], "final_output"))
    workflow.add_node("workflow_terminated", _workflow_terminated)

    workflow.add_edge(START, "researcher")
    workflow.add_edge("researcher", "guard_researcher_planner")
    workflow.add_conditional_edges(
        "guard_researcher_planner",
        _route_guard,
        {"continue": "planner", "terminate": "workflow_terminated"},
    )
    workflow.add_edge("planner", "guard_planner_writer")
    workflow.add_conditional_edges(
        "guard_planner_writer",
        _route_guard,
        {"continue": "writer", "terminate": "workflow_terminated"},
    )
    workflow.add_edge("writer", "guard_writer_finalizer")
    workflow.add_conditional_edges(
        "guard_writer_finalizer",
        _route_guard,
        {"continue": "finalizer", "terminate": "workflow_terminated"},
    )
    workflow.add_edge("finalizer", END)
    workflow.add_edge("workflow_terminated", END)
    return workflow.compile()


app = build_graph()
