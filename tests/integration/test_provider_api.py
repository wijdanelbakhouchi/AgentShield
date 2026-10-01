"""API/provider integration coverage (no network or real credentials)."""

from __future__ import annotations

from fastapi.testclient import TestClient

import api.server as server
from state import (
    Decision,
    PolicyDecision,
    RiskLevel,
    RiskScoreResult,
    SecurityAnalysisResult,
    SecurityPayload,
    SecurityPipelineResult,
)


def _safe_result() -> SecurityPipelineResult:
    payload = SecurityPayload(
        request_id="req-provider-api",
        timestamp="2026-01-01T00:00:00+00:00",
        source="test",
        target="agent_orchestrator",
        raw_input="safe",
        normalized_input="safe",
    )
    analysis = SecurityAnalysisResult(
        request_id=payload.request_id,
        timestamp=payload.timestamp,
        normalized_input=payload.normalized_input,
    )
    risk = RiskScoreResult(score=0.01, level=RiskLevel.LOW)
    policy = PolicyDecision(
        action=Decision.ALLOW,
        modified_input="safe",
        reason="safe",
        risk_metrics=risk,
    )
    return SecurityPipelineResult(payload=payload, analysis=analysis, risk=risk, policy=policy, latency_ms=1.0)


def test_provider_status_is_structured_and_secret_free(monkeypatch):
    monkeypatch.setattr(server, "LLM_PROVIDER", "invalid-provider-value")
    response = TestClient(server.app).get("/api/v1/providers/status")
    assert response.status_code == 200
    body = response.json()
    assert body["active_provider"] == "fallback"
    assert body["mode"] == "demo"
    assert set(body["providers"]) == {"openai", "gemini", "groq", "ollama"}
    assert all("api_key" not in str(item).lower() for item in body["providers"].values())


def test_chat_final_output_explicitly_identifies_demo_fallback(monkeypatch):
    monkeypatch.setattr(server.SecurityPipeline, "evaluate", classmethod(lambda cls, *a, **k: _safe_result()))
    monkeypatch.setattr(server.EventLogger, "log_security_event", lambda **_: None)
    monkeypatch.setattr(server.AlertEngine, "evaluate_security_event", lambda **_: None)
    monkeypatch.setattr(
        server.graph_app,
        "stream",
        lambda _state: [{"final": {"final_output": {"title": "safe"}}}],
    )
    response = TestClient(server.app).post("/api/v1/chat", json={"query": "safe"})
    assert response.status_code == 200
    output = response.json()["final_output"]
    assert output["provider"] == "fallback"
    assert output["mode"] == "demo"
    assert output["real_llm"] is False
    assert output["provider_metadata"]["provider_status"] == "demo_fallback"
    assert "DEMO / FALLBACK MODE" in output["notice"]


def test_provider_status_probe_endpoint(monkeypatch):
    import config
    import providers.service as provider_module

    class FakeProbeClient:
        def invoke(self, _prompt, **_kwargs):
            return "OK"

    monkeypatch.setattr(config, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(config, "GROQ_API_KEY", "gsk-test-valid-key")
    monkeypatch.setattr(server, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(provider_module, "_build_client", lambda *_: FakeProbeClient())

    # 1. Unprobed status
    client = TestClient(server.app)
    resp = client.get("/api/v1/providers/status")
    assert resp.status_code == 200
    assert resp.json()["providers"]["groq"]["status"] == "configured_but_unverified"

    # 2. Probe status
    probe_resp = client.get("/api/v1/providers/status?probe=true")
    assert probe_resp.status_code == 200
    data = probe_resp.json()
    assert data["providers"]["groq"]["status"] == "ready"
    assert data["providers"]["groq"]["runtime_verified"] is True
    assert data["active_status"] == "ready"

    # 3. Subsequent unprobed query reflects verified state
    after_resp = client.get("/api/v1/providers/status")
    assert after_resp.status_code == 200
    assert after_resp.json()["providers"]["groq"]["status"] == "ready"
    assert after_resp.json()["providers"]["groq"]["runtime_verified"] is True

