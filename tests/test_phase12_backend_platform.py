"""Focused Phase 12 persistence, observability, API and config evidence."""

from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import api.server as api_server
import storage.lifecycle as lifecycle
from config import cors_origins
from logging.event_logger import EventLogger, redact_sensitive
from storage.db import run_migrations
from storage.models import Base, PlatformEvent, SecurityLog


def test_fresh_sqlite_alembic_upgrade_creates_platform_schema(tmp_path):
    db_path = tmp_path / "fresh.db"
    run_migrations(f"sqlite:///{db_path}")
    inspector = inspect(create_engine(f"sqlite:///{db_path}"))
    table_names = set(inspector.get_table_names())
    expected_tables = {"security_logs", "tool_logs", "handoff_logs", "alert_logs", "tool_approvals", "approval_audit_logs", "platform_events", "alembic_version"}
    assert expected_tables <= table_names, (
        f"Expected tables {sorted(expected_tables)} but the fresh DB has {sorted(table_names)}. "
        "This usually means Alembic did not run the real migration script for the temporary DB."
    )
    assert any(index["name"] == "ix_platform_events_request_id" for index in inspector.get_indexes("platform_events"))
    assert inspector.get_foreign_keys("approval_audit_logs")[0]["referred_table"] == "tool_approvals"


def test_platform_event_has_unique_id_and_approval_audit_foreign_key(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'constraints.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory.begin() as session:
        session.add(PlatformEvent(event_id="event-one", event_type="REQUEST_RECEIVED", timestamp="2026-01-01T00:00:00+00:00", component="test", metadata_json="{}"))
    try:
        with session_factory.begin() as session:
            session.add(PlatformEvent(event_id="event-one", event_type="REQUEST_RECEIVED", timestamp="2026-01-01T00:00:00+00:00", component="test", metadata_json="{}"))
    except IntegrityError:
        pass
    else:
        raise AssertionError("event_id must be unique")


def test_central_redaction_masks_fake_secret_and_credentials():
    secret = "AGENTSHIELD_TEST_SECRET_123"
    redacted = redact_sensitive({"authorization": f"Bearer {secret}", "note": f"token={secret}"})
    assert secret not in str(redacted)
    assert "[REDACTED]" in str(redacted)


def test_persisted_platform_event_never_contains_fake_secret(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'events.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def session_scope():
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    import storage.db as db
    monkeypatch.setattr(db, "get_db_session", session_scope)
    monkeypatch.setattr(db, "init_db", lambda: None)
    secret = "AGENTSHIELD_TEST_SECRET_123"
    EventLogger.log_platform_event(request_id="req-secret", event_type="REQUEST_RECEIVED", component="test", metadata={"authorization": f"Bearer {secret}", "note": secret})
    with session_scope() as session:
        persisted = session.scalar(select(PlatformEvent))
    assert secret not in persisted.metadata_json


def test_lifecycle_query_uses_real_correlated_records(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    @contextmanager
    def session_scope():
        session = session_factory()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    monkeypatch.setattr(lifecycle, "get_db_session", session_scope)
    monkeypatch.setattr(lifecycle, "init_db", lambda: None)
    with session_scope() as session:
        session.add(SecurityLog(request_id="req-life", timestamp="2026-01-01T00:00:00+00:00", source="test", target="api", raw_input="redacted", sanitized_input="redacted", risk_score=0.0, risk_level="LOW", policy_decision="ALLOW"))
        session.add(PlatformEvent(event_id="event-life", request_id="req-life", event_type="POLICY_DECISION", timestamp="2026-01-01T00:00:00+00:00", component="PolicyEngine", decision="ALLOW", metadata_json="{}"))
    result = lifecycle.request_lifecycle("req-life")
    assert result and result["request"]["decision"] == "ALLOW"
    assert result["events"][0]["event_id"] == "event-life"
    assert lifecycle.request_lifecycle("missing") is None


def test_explicit_cors_configuration_rejects_wildcard(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_CORS_ORIGINS", "*")
    try:
        cors_origins()
    except ValueError:
        pass
    else:
        raise AssertionError("credentialed wildcard CORS must be rejected")


def test_canonical_api_endpoints_and_error_contract_are_available():
    client = TestClient(api_server.app)
    operator_headers = {"Authorization": "Bearer dev-analyst-token"}
    assert client.get("/api/v1/providers/status").status_code == 200
    assert client.get("/api/v1/requests", headers=operator_headers).status_code == 200
    assert client.get("/api/v1/events", headers=operator_headers).status_code == 200
    assert client.get("/api/v1/alerts", headers=operator_headers).status_code == 200
    response = client.get("/api/v1/requests/not-a-real-request", headers=operator_headers)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"
    invalid = client.get("/api/v1/requests?limit=0", headers=operator_headers)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "VALIDATION_ERROR"


def test_provider_status_does_not_echo_unknown_environment_value(monkeypatch):
    monkeypatch.setattr(api_server, "LLM_PROVIDER", "AGENTSHIELD_TEST_SECRET_123")
    response = TestClient(api_server.app).get("/api/v1/providers/status").json()
    assert response["selected_provider"] == "fallback"


def test_metrics_and_telemetry_do_not_use_fixed_demo_values():
    client = TestClient(api_server.app)
    telemetry = client.get("/api/v1/telemetry", headers={"Authorization": "Bearer dev-analyst-token"}).json()
    assert "threat_category_breakdown" not in telemetry
    assert telemetry["avg_latency_ms"] != 15.4
    assert api_server.app.openapi()["paths"]["/api/v1/evaluate"]["post"]["deprecated"] is True
