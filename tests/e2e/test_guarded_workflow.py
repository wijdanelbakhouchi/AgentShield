"""Small deterministic end-to-end workflow smoke test."""

from __future__ import annotations

import pytest

from graph import build_graph
from hooks.inter_agent_guard import reset_handoff_audit_log

pytestmark = pytest.mark.e2e


def test_safe_workflow_reaches_finalizer_through_all_guard_boundaries():
    reset_handoff_audit_log()
    calls = []
    graph = build_graph(
        {
            "researcher": lambda _state: calls.append("researcher") or {"research_data": "facts"},
            "planner": lambda _state: calls.append("planner") or {"plan": "steps"},
            "writer": lambda _state: calls.append("writer") or {"draft_response": "draft"},
            "finalizer": lambda _state: calls.append("finalizer") or {"final_output": {"summary": "ok"}},
        }
    )
    events = list(graph.stream({"user_query": "safe", "request_id": "req-e2e"}))
    assert calls == ["researcher", "planner", "writer", "finalizer"]
    assert events[-1]["finalizer"]["final_output"] == {"summary": "ok"}
