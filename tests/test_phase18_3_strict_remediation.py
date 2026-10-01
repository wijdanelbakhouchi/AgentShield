"""Focused tests for the post-final-audit scientific remediation."""

from __future__ import annotations

import logging
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient

import api.server as api_server
import config
from experiments.e2e_evaluation.harness import run_case
from hooks.inter_agent_guard import AGENT_HANDOFF_AUDIT_LOG
from hooks.tool_guard import (
    TOOL_EXECUTION_AUDIT_LOG,
    ToolGuard,
    reset_current_identity,
    reset_current_request_id,
    reset_tool_audit_log,
    set_current_identity,
    set_current_request_id,
)
from logging.alerting import AlertEngine
from logging.event_logger import EventLogger
from security.tool_security import ToolRole, resolve_server_identity
from state import Decision, PolicyDecision, RiskLevel, RiskScoreResult, SecurityAnalysisResult


def _isolated_worker(subject: str, request_id: str) -> tuple[str, str, list[str], list[str]]:
    reset_tool_audit_log()
    AGENT_HANDOFF_AUDIT_LOG.clear()
    reset_current_identity()
    reset_current_request_id()
    identity = resolve_server_identity(subject)
    set_current_identity(identity)
    set_current_request_id(request_id)
    event = ToolGuard.pre_tool_execution(
        "read_document",
        "concurrency-test",
        {"path": "safe.txt"},
    )
    TOOL_EXECUTION_AUDIT_LOG.append(event)
    AGENT_HANDOFF_AUDIT_LOG.append(request_id)  # proxy isolation check
    time.sleep(0.02)
    return (
        identity.subject_id,
        event.request_id or "",
        [item.request_id or "" for item in TOOL_EXECUTION_AUDIT_LOG],
        [str(item) for item in AGENT_HANDOFF_AUDIT_LOG],
    )


def test_concurrent_identity_request_and_audit_state_are_isolated() -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda args: _isolated_worker(*args),
                [("user_demo", "req-user"), ("analyst_demo", "req-analyst")],
            )
        )
    assert {row[0] for row in results} == {"user_demo", "analyst_demo"}
    assert {row[1] for row in results} == {"req-user", "req-analyst"}
    assert all(len(row[2]) == 1 and row[2][0] == row[1] for row in results)
    assert all(len(row[3]) == 1 and row[3][0] == row[1] for row in results)


def test_development_admin_identity_is_rejected_outside_explicit_dev_mode(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "DEVELOPMENT_AUTH_ENABLED", False)
    identity = resolve_server_identity("admin_demo", auth_token="dev-admin-token")
    assert identity.role == ToolRole.USER
    assert identity.authenticated is False
    assert "disabled" in identity.auth_source


def test_internal_workflow_exception_is_redacted(monkeypatch) -> None:
    class ExplodingGraph:
        def stream(self, state):
            raise RuntimeError("DATABASE_PASSWORD=do-not-disclose")

    monkeypatch.setattr(api_server, "graph_app", ExplodingGraph())
    response = TestClient(api_server.app).post(
        "/api/v1/chat", json={"query": "Explain audit trails"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "FAILED"
    assert body["final_output"]["error_code"] == "WORKFLOW_ERROR"
    assert "DATABASE_PASSWORD" not in response.text
    assert body["final_output"]["request_id"] == body["request_id"]


def test_telemetry_failure_is_observable_without_secret_leak(monkeypatch, caplog) -> None:
    import storage.db as db

    monkeypatch.setattr(db, "init_db", lambda: None)

    def fail_session():
        raise RuntimeError("secret database internals")

    monkeypatch.setattr(db, "get_db_session", fail_session)
    with caplog.at_level(logging.WARNING, logger="agentshield.telemetry"):
        EventLogger.log_platform_event(
            request_id="req-telemetry",
            event_type="TEST_TELEMETRY",
            component="test",
            metadata={"secret": "CLIENT_SECRET_VALUE"},
        )
    messages = " ".join(record.getMessage() for record in caplog.records)
    assert "telemetry_persist_failed" in messages
    assert "req-telemetry" in messages
    assert "CLIENT_SECRET_VALUE" not in messages
    assert "secret database internals" not in messages


def test_blank_chat_and_analyze_inputs_are_rejected() -> None:
    client = TestClient(api_server.app)
    chat = client.post("/api/v1/chat", json={"query": "   \t"})
    analyze = client.post("/api/v1/analyze", json={"prompt": "\n  "})
    assert chat.status_code == 422
    assert analyze.status_code == 422
    assert chat.json()["error"]["code"] == "VALIDATION_ERROR"
    assert chat.json()["error"]["request_id"]


def test_alert_wording_matches_allow_decision(monkeypatch) -> None:
    captured: list[dict] = []
    monkeypatch.setattr(EventLogger, "log_alert", lambda **payload: captured.append(payload))
    risk = RiskScoreResult(score=0.16, level=RiskLevel.HIGH)
    analysis = SecurityAnalysisResult(
        request_id="req-alert",
        timestamp="2026-01-01T00:00:00+00:00",
        normalized_input="high but below block threshold",
        rule_flags=["SEMANTIC_SIMILARITY:TEST:0.86"],
    )
    policy = PolicyDecision(
        action=Decision.ALLOW,
        reason="below calibrated block threshold",
        risk_metrics=risk,
    )
    alert = AlertEngine.evaluate_security_event(analysis, risk, policy, "req-alert")
    assert alert is not None
    assert "ALLOWED" in alert["title"]
    assert "SANITIZED" not in alert["title"]
    assert alert["alert_type"] == "GATEWAY_OBSERVED"
    assert captured and captured[0]["alert_type"] == "GATEWAY_OBSERVED"


def _offline_search(monkeypatch) -> None:
    """Keep the test bounded while still executing the real tool boundary."""
    import agents.researcher as researcher
    import security.tool_security as tool_security
    import tools

    monkeypatch.setattr(tool_security, "search_web_impl", lambda query: f"source for {query}")
    monkeypatch.setattr(researcher, "search_web_impl", tool_security.search_web_impl)
    monkeypatch.setattr(tools, "search_web_impl", tool_security.search_web_impl)


def test_real_graph_harness_records_guarded_tools_and_handoffs(monkeypatch) -> None:
    _offline_search(monkeypatch)
    result = run_case(
        "Explain why request correlation identifiers improve audit observability.",
        security_enabled=True,
        label="benign",
        group="benign_hard_negative",
    )
    nodes = [item["node"] for item in result["trace"]]
    assert "researcher" in nodes
    assert "planner" in nodes
    assert "writer" in nodes
    assert "finalizer" in nodes
    assert len(result["tool_events"]) >= 2
    assert len(result["handoff_events"]) == 3


def test_baseline_uses_same_real_graph_nodes_without_security_intervention(monkeypatch) -> None:
    _offline_search(monkeypatch)
    prompt = "Describe a simple audit log schema for a small application."
    baseline = run_case(prompt, security_enabled=False, label="benign", group="benign_hard_negative")
    protected = run_case(prompt, security_enabled=True, label="benign", group="benign_hard_negative")
    baseline_nodes = [item["node"] for item in baseline["trace"]]
    protected_nodes = [item["node"] for item in protected["trace"]]
    assert baseline_nodes == protected_nodes
    assert baseline["security_enabled"] is False
    assert protected["security_enabled"] is True
    assert baseline["handoff_events"] == []
    assert baseline["tool_events"] == []


def test_independent_dataset_is_frozen_and_distinct() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = root / "experiments" / "e2e_evaluation" / "datasets" / "post_remediation_final_v1.manifest.json"
    dataset = root / "experiments" / "e2e_evaluation" / "datasets" / "post_remediation_final_v1.json"
    assert manifest.exists() and dataset.exists()
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_data["frozen"] is True
    assert hashlib.sha256(dataset.read_bytes()).hexdigest() == manifest_data["sha256"]
    assert "4bbcc382db9d70108c3f084ed9bd9247e51fb40947c56b85ba330b6c57c2234a" not in dataset.read_text(encoding="utf-8")


def test_legacy_ui_has_no_stale_allow_warn_label() -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in ("ui/chat_app.py", "ui/unified_app.py", "dashboard/app.py", "ui/index.html"):
        target = root / relative
        if target.exists():
            assert "ALLOW_WARN" not in target.read_text(encoding="utf-8")
