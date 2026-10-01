"""Lightweight test taxonomy without moving the established test modules."""

from pathlib import Path
import pytest

import config
from providers.service import reset_provider_metadata, reset_runtime_provider_state


@pytest.fixture(autouse=True)
def _isolate_provider_state_between_tests(request, monkeypatch):
    """Keep ordinary tests deterministic even when a developer `.env` has keys.

    Live credentials are available only to tests that explicitly opt into the
    ``real_provider`` marker. This prevents the default/no-provider suite from
    making network calls, consuming quota, or changing outcomes by host.
    """
    if request.node.get_closest_marker("real_provider") is None:
        monkeypatch.setattr(config, "LLM_PROVIDER", "auto")
        monkeypatch.setattr(config, "OPENAI_API_KEY", "")
        monkeypatch.setattr(config, "GEMINI_API_KEY", "")
        monkeypatch.setattr(config, "GROQ_API_KEY", "")
        monkeypatch.setattr(config, "OLLAMA_MODEL", "")
        monkeypatch.setattr(config, "LLM_MAX_TRANSIENT_RETRIES", 0)
        monkeypatch.setattr(config, "LLM_MIN_REQUEST_INTERVAL_SECONDS", 0.0)
    reset_runtime_provider_state()
    reset_provider_metadata()
    yield
    reset_runtime_provider_state()
    reset_provider_metadata()


def pytest_collection_modifyitems(config, items):  # noqa: ARG001
    for item in items:
        path = Path(str(item.fspath)).as_posix()
        if "/tests/security/" in path or any(
            token in Path(path).name
            for token in (
                "normalizer",
                "detector",
                "semantic",
                "policy",
                "threat",
                "phase7",
                "phase8",
                "phase9",
                "phase10",
                "phase11",
            )
        ):
            item.add_marker("security")
        if "/tests/integration/" in path or "phase12" in Path(path).name:
            item.add_marker("integration")
        if "/tests/e2e/" in path or "canonical_pipeline" in Path(path).name:
            item.add_marker("e2e")
        if "/tests/experiments/" in path or "calibration" in Path(path).name:
            item.add_marker("experiment")
        if "/tests/unit/" in path:
            item.add_marker("unit")
