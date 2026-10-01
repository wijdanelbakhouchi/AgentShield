"""Research-integrity checks for provider/fallback labeling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.experiment


def test_post_hardening_calibration_records_provider_verification_boundary():
    path = Path(__file__).resolve().parents[2] / "experiments/post_hardening_calibration/results/calibration_metadata.json"
    metadata = json.loads(path.read_text(encoding="utf-8"))
    runtime = metadata["classifier_runtime"]
    assert runtime["external_provider_available"] is False
    assert "NOT RUNTIME VERIFIED" in runtime["calibration_status"]
    assert metadata["heldout_used"] is False
    assert metadata["final_test_used"] is False
