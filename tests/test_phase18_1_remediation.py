"""Focused regression checks for the Phase 18.1 audit remediations."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import api.server as api_server
from api.server import _approval_identity
from security.tool_security import ToolRole


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CLIENT = TestClient(api_server.app)


def _assert_error_envelope(response, code: str) -> None:
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert set(payload) == {"error"}
    assert payload["error"]["code"] == code
    assert isinstance(payload["error"]["message"], str)
    assert "Traceback" not in response.text


def test_unknown_route_uses_canonical_404_error_envelope() -> None:
    response = CLIENT.get("/api/v1/no-such-route")
    assert response.status_code == 404
    _assert_error_envelope(response, "NOT_FOUND")


def test_wrong_method_uses_canonical_405_error_envelope() -> None:
    response = CLIENT.post("/api/v1/health")
    assert response.status_code == 405
    _assert_error_envelope(response, "METHOD_NOT_ALLOWED")


def test_server_identity_rejects_caller_role_spoof() -> None:
    identity = _approval_identity("user_demo", None, None, "ADMIN")
    assert identity.role == ToolRole.USER


def test_root_metadata_points_to_production_frontend() -> None:
    payload = CLIENT.get("/").json()
    assert payload["react_control_center"] == "http://localhost:3000/"
    assert "8000/react" not in json.dumps(payload)


def test_legacy_compatibility_page_is_fenced_without_static_kpis() -> None:
    page = (REPOSITORY_ROOT / "ui" / "index.html").read_text(encoding="utf-8")
    assert "Legacy compatibility page" in page
    for claim in ("100% Protected", "100% Intercepted", "100% Blocked", "Sub-20ms SLA Guaranteed", "Rating:100/100"):
        assert claim not in page
    assert "operational, security, or research metrics" in page


def test_calibration_metadata_uses_repository_relative_source_path() -> None:
    metadata = json.loads((REPOSITORY_ROOT / "experiments" / "calibration" / "datasets" / "split_metadata.json").read_text(encoding="utf-8"))
    source_dataset = metadata["source_dataset"]
    assert source_dataset == "tests/benchmark_dataset.json"
    assert not Path(source_dataset).is_absolute()


def test_tracked_json_metadata_has_no_developer_absolute_paths() -> None:
    offenders = []
    for path in REPOSITORY_ROOT.rglob("*.json"):
        if any(part in {".git", "node_modules", ".venv", "__pycache__"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        if "C:/Users/" in text or "C:\\Users\\" in text:
            offenders.append(path.relative_to(REPOSITORY_ROOT).as_posix())
    assert offenders == []
