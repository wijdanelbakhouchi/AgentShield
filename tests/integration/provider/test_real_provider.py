"""Opt-in real-provider checks; never part of credential-free CI."""

from __future__ import annotations

import os

import pytest

import config
from providers.service import validate_provider

pytestmark = [pytest.mark.integration, pytest.mark.provider, pytest.mark.real_provider, pytest.mark.live]


def _configured(provider: str) -> bool:
    if provider == "openai":
        return bool(config.OPENAI_API_KEY and not config.OPENAI_API_KEY.startswith("your_"))
    if provider == "gemini":
        return bool(config.GEMINI_API_KEY and not config.GEMINI_API_KEY.startswith("your_"))
    if provider == "groq":
        return bool(config.GROQ_API_KEY and not config.GROQ_API_KEY.startswith("your_"))
    return bool(config.OLLAMA_MODEL)


@pytest.mark.parametrize("provider", ["openai", "gemini", "groq", "ollama"])
def test_real_provider_safe_completion(provider):
    if os.getenv("AGENTSHIELD_RUN_LIVE_PROVIDER_TESTS", "").strip() != "1":
        pytest.skip("live provider checks are opt-in; set AGENTSHIELD_RUN_LIVE_PROVIDER_TESTS=1")
    if not _configured(provider):
        pytest.skip(f"{provider} is genuinely not configured in this environment")
    snapshot = validate_provider(provider)
    assert snapshot.runtime_verified is True, f"{provider} validation failed: {snapshot.status}"
    assert snapshot.status == "ready"
