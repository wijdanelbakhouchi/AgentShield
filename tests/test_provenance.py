"""Unit tests for message-level provenance tracking."""

from __future__ import annotations

import pytest

from security.provenance import (
    Origin,
    ProvenanceTracker,
    is_untrusted,
    provenance_adjustment,
    provenance_labels,
)
from state import TrustLevel


def test_ingress_taint_and_depth():
    tracker = ProvenanceTracker()
    ingress = tracker.ingress(
        tracker=tracker,
        field="user_query",
        origin=Origin.USER,
        request_id="req-1",
        trust_level=TrustLevel.USER_CONTROLLED,
    )
    assert ingress.tainted is True
    assert ingress.propagation_depth == 1
    assert ingress.origins == ["user"]
    assert "PROVENANCE:TAINTED" in ingress.security_labels


def test_system_ingress_is_not_tainted():
    tracker = ProvenanceTracker()
    system = tracker.ingress(
        tracker=tracker,
        field="policy",
        origin=Origin.SYSTEM,
        request_id="req-1",
        trust_level=TrustLevel.TRUSTED_SYSTEM,
    )
    assert system.tainted is False
    assert system.propagation_depth == 0


def test_derivation_propagates_taint_and_depth():
    tracker = ProvenanceTracker()
    user = tracker.ingress(
        tracker=tracker,
        field="user_query",
        origin=Origin.USER,
        request_id="req-1",
        trust_level=TrustLevel.USER_CONTROLLED,
    )
    research = tracker.derive(
        parent_ids=[user.message_id],
        field="research_data",
        source_agent="researcher",
        request_id="req-1",
    )
    plan = tracker.derive(
        parent_ids=[research.message_id],
        field="plan",
        source_agent="planner",
        request_id="req-1",
    )
    assert research.tainted is True
    assert research.propagation_depth == 2
    assert plan.tainted is True
    assert plan.propagation_depth == 3
    assert research.trust_level == TrustLevel.AGENT_GENERATED_UNTRUSTED
    assert "agent" in plan.origins


def test_agent_output_is_never_trusted_even_from_system():
    tracker = ProvenanceTracker()
    system = tracker.ingress(
        tracker=tracker,
        field="policy",
        origin=Origin.SYSTEM,
        request_id="req-1",
        trust_level=TrustLevel.TRUSTED_SYSTEM,
    )
    agent_msg = tracker.derive(
        parent_ids=[system.message_id],
        field="output",
        source_agent="finalizer",
        request_id="req-1",
    )
    assert agent_msg.trust_level == TrustLevel.AGENT_GENERATED_UNTRUSTED
    assert agent_msg.tainted is False
    assert agent_msg.propagation_depth == 0


def test_provenance_adjustment_neutral_by_default():
    record = provenance_adjustment(
        base_score=0.10,
        tainted=True,
        propagation_depth=3,
        target_agent="finalizer",
    )
    assert record["applied"] is False
    assert record["effective_score"] == pytest.approx(0.10)


def test_provenance_adjustment_components():
    record = provenance_adjustment(
        base_score=0.10,
        tainted=True,
        propagation_depth=2,
        target_agent="finalizer",
        bonus_untrusted=0.03,
        bonus_per_depth=0.01,
        bonus_privileged_target=0.02,
    )
    assert record["applied"] is True
    assert record["effective_score"] == pytest.approx(0.10 + 0.03 + 0.02 + 0.02)
    assert "tainted(+0.030)" in record["contributions"]
    assert "privileged_target=finalizer(+0.020)" in record["contributions"]


def test_provenance_adjustment_clamped():
    record = provenance_adjustment(
        base_score=0.98,
        tainted=True,
        propagation_depth=4,
        target_agent="finalizer",
        bonus_untrusted=0.1,
        bonus_per_depth=0.1,
        bonus_privileged_target=0.1,
    )
    assert record["effective_score"] == 1.0


def test_privileged_target_bonus_only_for_privileged_agents():
    low = provenance_adjustment(
        base_score=0.1, tainted=True, propagation_depth=1, target_agent="planner",
        bonus_privileged_target=0.02,
    )
    high = provenance_adjustment(
        base_score=0.1, tainted=True, propagation_depth=1, target_agent="finalizer",
        bonus_privileged_target=0.02,
    )
    assert low["effective_score"] == pytest.approx(0.1)
    assert high["effective_score"] == pytest.approx(0.12)


def test_tracker_reset():
    tracker = ProvenanceTracker()
    tracker.ingress(
        tracker=tracker, field="f", origin=Origin.USER, request_id="r",
        trust_level=TrustLevel.USER_CONTROLLED,
    )
    assert tracker.count() == 1
    tracker.clear()
    assert tracker.count() == 0


def test_is_untrusted():
    assert is_untrusted(TrustLevel.USER_CONTROLLED)
    assert is_untrusted(TrustLevel.EXTERNAL_UNTRUSTED)
    assert is_untrusted(TrustLevel.AGENT_GENERATED_UNTRUSTED)
    assert not is_untrusted(TrustLevel.INSPECTED_SAFE)
    assert not is_untrusted(TrustLevel.TRUSTED_SYSTEM)


def test_provenance_labels():
    tracker = ProvenanceTracker()
    message = tracker.ingress(
        tracker=tracker, field="f", origin=Origin.USER, request_id="r",
        trust_level=TrustLevel.USER_CONTROLLED,
    )
    labels = provenance_labels(message)
    assert "PROVENANCE:TAINTED" in labels
    assert "PROVENANCE:ORIGIN:USER" in labels
    assert "PROVENANCE:DEPTH:1" in labels