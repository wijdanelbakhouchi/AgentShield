"""API-edge regression tests for authentication, ownership, and size limits."""

from __future__ import annotations

from fastapi.testclient import TestClient

import api.server as server
import config


def test_production_rejects_unauthenticated_chat(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "DEVELOPMENT_AUTH_ENABLED", False)
    monkeypatch.setattr(config, "DEVELOPMENT_ANONYMOUS_DEMO", False)
    monkeypatch.setattr(config, "API_AUTH_REQUIRED", True)
    response = TestClient(server.app).post("/api/v1/chat", json={"query": "Explain authorization."})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"


def test_operational_telemetry_requires_privileged_role(monkeypatch) -> None:
    monkeypatch.setattr(config, "APP_ENV", "development")
    monkeypatch.setattr(config, "DEVELOPMENT_AUTH_ENABLED", True)
    monkeypatch.setattr(config, "DEVELOPMENT_ANONYMOUS_DEMO", True)
    monkeypatch.setattr(config, "API_AUTH_REQUIRED", False)
    response = TestClient(server.app).get("/api/v1/events")
    assert response.status_code == 403
    assert TestClient(server.app).get("/api/v1/requests").status_code == 403
    assert TestClient(server.app).get("/api/v1/telemetry").status_code == 403


def test_request_body_limit_is_enforced_before_endpoint_work(monkeypatch) -> None:
    monkeypatch.setattr(server.runtime_config, "MAX_REQUEST_BODY_BYTES", 32)
    response = TestClient(server.app).post(
        "/api/v1/chat", json={"query": "x" * 200}
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"
