"""Reproductions for authentication and resource issues found on 2026-09-18."""
import pytest
from fastapi.testclient import TestClient

import api.server as server
import config
from api.security import RATE_LIMITER


@pytest.fixture(autouse=True)
def development_edge(monkeypatch):
    monkeypatch.setattr(config, "APP_ENV", "development")
    monkeypatch.setattr(config, "DEVELOPMENT_AUTH_ENABLED", True)
    monkeypatch.setattr(config, "DEVELOPMENT_ANONYMOUS_DEMO", False)
    monkeypatch.setattr(config, "API_AUTH_REQUIRED", True)
    RATE_LIMITER.reset()
    yield
    RATE_LIMITER.reset()


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid-token"}, {"Authorization": "Basic invalid"}])
def test_required_auth_cannot_fall_back_to_development_identity(headers):
    response = TestClient(server.app).get("/api/v1/providers/status", headers=headers)
    assert response.status_code == 401


def test_browser_preflight_does_not_require_bearer_token(monkeypatch):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "DEVELOPMENT_AUTH_ENABLED", False)
    response = TestClient(server.app).options("/api/v1/chat", headers={
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_variable_paths_share_admin_rate_budget(monkeypatch):
    monkeypatch.setattr(config, "API_RATE_LIMIT_ADMIN_PER_MINUTE", 2)
    client = TestClient(server.app)
    headers = {"Authorization": "Bearer dev-analyst-token"}
    assert client.get("/api/v1/requests/missing-one", headers=headers).status_code == 404
    assert client.get("/api/v1/requests/missing-two", headers=headers).status_code == 404
    assert client.get("/api/v1/requests/missing-three", headers=headers).status_code == 429
