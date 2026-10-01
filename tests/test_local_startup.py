"""Focused checks for the local development launcher configuration."""

import pytest

from scripts.run_backend import development_settings


def test_local_launcher_defaults_to_loopback_port_8001(monkeypatch):
    monkeypatch.delenv("AGENTSHIELD_DEV_HOST", raising=False)
    monkeypatch.delenv("AGENTSHIELD_DEV_PORT", raising=False)

    assert development_settings() == ("127.0.0.1", 8001)


def test_local_launcher_accepts_valid_overrides(monkeypatch):
    monkeypatch.setenv("AGENTSHIELD_DEV_HOST", "localhost")
    monkeypatch.setenv("AGENTSHIELD_DEV_PORT", "8010")

    assert development_settings() == ("localhost", 8010)


@pytest.mark.parametrize("value", ["0", "65536", "not-a-port"])
def test_local_launcher_rejects_invalid_port(monkeypatch, value):
    monkeypatch.setenv("AGENTSHIELD_DEV_PORT", value)

    with pytest.raises(ValueError, match="AGENTSHIELD_DEV_PORT"):
        development_settings()
