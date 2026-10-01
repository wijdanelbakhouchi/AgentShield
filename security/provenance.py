"""Message-level provenance tracking for multi-agent prompt-propagation research.

The central research mechanism of AgentShield: every message that crosses a
trust boundary (user input, document/context, tool output, agent output)
carries a provenance record that answers three questions:

1. Where did this content originate?  (``origins`` chain)
2. How many propagation hops from an untrusted ingress is it?  (``propagation_depth``)
3. Is it tainted by untrusted content?  (``tainted``)

Agent output is *never* trusted by default.  A message derived from untrusted
content (user input, external documents, tool results, or another agent's
output) inherits an ``AGENT_GENERATED_UNTRUSTED`` label and a taint flag.
Downstream security decisions can then use this provenance evidence through
``apply_provenance_adjustment``, a pure, configurable risk adjustment.

The tracker is process-local and request-scoped.  Production callers reset it
at request boundaries exactly like the other request-local audit logs.
"""

from __future__ import annotations

import datetime
import uuid
from enum import Enum
from typing import Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from state import TrustLevel


class Origin(str, Enum):
    """Direct origin categories of a message at a trust boundary."""

    USER = "user"
    DOCUMENT = "document"
    TOOL = "tool"
    AGENT = "agent"
    SYSTEM = "system"


# Trust labels that mark a message as not trusted at face value.  Inspected
# content (``INSPECTED_SAFE``) is deliberately NOT in this set: it passed the
# canonical guard.  ``tainted`` below separately records whether inspected
# content still descends from an untrusted origin.
UNTRUSTED_TRUST_LEVELS = frozenset(
    {
        TrustLevel.USER_CONTROLLED,
        TrustLevel.EXTERNAL_UNTRUSTED,
        TrustLevel.AGENT_GENERATED_UNTRUSTED,
    }
)

PRIVILEGED_TARGETS = frozenset({"finalizer", "writer", "admin_agent"})


def is_untrusted(trust_level: TrustLevel) -> bool:
    """Return whether a trust label means the value is untrusted as-is."""
    return trust_level in UNTRUSTED_TRUST_LEVELS


class MessageProvenance(BaseModel):
    """Provenance envelope attached to one message crossing a trust boundary."""

    message_id: str = Field(description="Unique identifier for this message")
    request_id: str = Field(description="Ingress request correlation identifier")
    field: str = Field(description="State field or channel that carried the message")
    origin: Origin = Field(description="Direct origin of this message")
    origins: List[str] = Field(
        default_factory=list,
        description="Ordered origin chain (deduplicated) from ingress to this message",
    )
    parent_message_ids: List[str] = Field(
        default_factory=list,
        description="Provenance IDs of the messages this message was derived from",
    )
    source_agent: Optional[str] = Field(
        default=None, description="Agent that produced this message, if any"
    )
    trust_level: TrustLevel = Field(
        default=TrustLevel.AGENT_GENERATED_UNTRUSTED,
        description="Trust label; agent output is never trusted by default",
    )
    tainted: bool = Field(
        default=False,
        description=(
            "True when this message descends from any non-system origin "
            "(user, document, tool, or another agent). This is the propagation "
            "taint bit used by provenance-aware risk adjustment."
        ),
    )
    propagation_depth: int = Field(
        default=0,
        description="Number of hops from the nearest untrusted ingress (user/document/tool)",
    )
    attack_id: Optional[str] = Field(
        default=None, description="Correlated benchmark attack identifier, if any"
    )
    timestamp: str = Field(description="ISO-8601 UTC creation timestamp")
    risk_score: float = Field(
        default=0.0, description="Canonical pipeline risk score at this boundary"
    )
    security_labels: List[str] = Field(
        default_factory=list,
        description="Provenance-derived security labels (e.g. PROVENANCE:TAINTED)",
    )

    def summary(self) -> Dict[str, object]:
        """Return a compact, JSON-safe view used in audit records."""
        return {
            "message_id": self.message_id,
            "field": self.field,
            "origin": self.origin.value,
            "origins": self.origins,
            "source_agent": self.source_agent,
            "trust_level": self.trust_level.value,
            "tainted": self.tainted,
            "propagation_depth": self.propagation_depth,
            "parent_message_ids": self.parent_message_ids,
            "attack_id": self.attack_id,
        }


def provenance_labels(provenance: MessageProvenance) -> List[str]:
    """Derive deterministic security labels from one provenance record."""
    labels = []
    if provenance.tainted:
        labels.append("PROVENANCE:TAINTED")
    if provenance.propagation_depth > 0:
        labels.append(f"PROVENANCE:DEPTH:{provenance.propagation_depth}")
    for origin in provenance.origins:
        label = f"PROVENANCE:ORIGIN:{origin.upper()}"
        if label not in labels:
            labels.append(label)
    labels.append(f"PROVENANCE:TRUST:{provenance.trust_level.value}")
    if provenance.source_agent:
        labels.append(f"PROVENANCE:SOURCE:{provenance.source_agent.upper()}")
    return labels


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def derive_trust_for_agent_output(
    parents: Sequence[MessageProvenance],
) -> TrustLevel:
    """Trust label for agent output: trusted only if every parent was system-trusted."""
    if not parents:
        return TrustLevel.AGENT_GENERATED_UNTRUSTED
    if all(parent.trust_level == TrustLevel.TRUSTED_SYSTEM for parent in parents):
        return TrustLevel.AGENT_GENERATED_UNTRUSTED  # agents remain untrusted
    return TrustLevel.AGENT_GENERATED_UNTRUSTED


class ProvenanceTracker:
    """Request-scoped registry that derives provenance for derived messages.

    ``derive`` computes the child's origin chain, taint bit, and propagation
    depth from its parents:

    * ``origins`` — ordered union of parent origins plus the child's own origin.
    * ``tainted`` — True if any parent is tainted or carries an untrusted label.
    * ``propagation_depth`` — 1 + the maximum depth of any parent that
      contributes untrusted-origin content (0 for a fresh system message).
    """

    def __init__(self) -> None:
        self._messages: Dict[str, MessageProvenance] = {}

    def register(self, provenance: MessageProvenance) -> MessageProvenance:
        """Store a provenance record; re-registering the same ID returns it."""
        existing = self._messages.get(provenance.message_id)
        if existing is not None:
            return existing
        self._messages[provenance.message_id] = provenance
        return provenance

    def get(self, message_id: str) -> Optional[MessageProvenance]:
        return self._messages.get(message_id)

    def all(self) -> List[MessageProvenance]:
        return list(self._messages.values())

    def count(self) -> int:
        return len(self._messages)

    def clear(self) -> None:
        self._messages.clear()

    @classmethod
    def _parents(cls, tracker: "ProvenanceTracker", parent_ids: Sequence[str]) -> List[MessageProvenance]:
        found = []
        for parent_id in parent_ids:
            parent = tracker.get(parent_id)
            if parent is not None:
                found.append(parent)
        return found

    def derive(
        self,
        *,
        parent_ids: Sequence[str],
        field: str,
        origin: Origin = Origin.AGENT,
        source_agent: Optional[str] = None,
        attack_id: Optional[str] = None,
        request_id: str = "req-default",
        message_id: Optional[str] = None,
        risk_score: float = 0.0,
    ) -> MessageProvenance:
        """Create and register a child provenance record derived from parents."""
        parents = self._parents(self, list(parent_ids))
        origins: List[str] = []
        tainted = False
        untrusted_depths: List[int] = []
        for parent in parents:
            for item in parent.origins:
                if item not in origins:
                    origins.append(item)
            if parent.tainted or is_untrusted(parent.trust_level):
                tainted = True
                untrusted_depths.append(parent.propagation_depth)

        if origin.value not in origins:
            origins.append(origin.value)
        if not origins:
            origins.append(origin.value)

        # Depth counts hops from the nearest untrusted ancestor.  A message
        # derived only from SYSTEM-trusted parents has no untrusted influence,
        # so its depth stays 0 even though its trust label is untrusted.
        depth = max(untrusted_depths, default=-1) + 1
        depth = max(0, depth)

        provenance = MessageProvenance(
            message_id=message_id or f"msg-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            field=field,
            origin=origin,
            origins=origins,
            parent_message_ids=[parent.message_id for parent in parents],
            source_agent=source_agent,
            trust_level=derive_trust_for_agent_output(parents),
            tainted=tainted,
            propagation_depth=depth,
            attack_id=attack_id,
            timestamp=_utc_now(),
            risk_score=max(0.0, min(1.0, float(risk_score))),
            security_labels=[],
        )
        provenance.security_labels = provenance_labels(provenance)
        return self.register(provenance)

    @classmethod
    def ingress(
        cls,
        tracker: "ProvenanceTracker",
        *,
        field: str,
        origin: Origin,
        request_id: str,
        trust_level: TrustLevel,
        attack_id: Optional[str] = None,
        risk_score: float = 0.0,
        message_id: Optional[str] = None,
    ) -> MessageProvenance:
        """Create the first record for content entering the system."""
        tainted = origin != Origin.SYSTEM
        provenance = MessageProvenance(
            message_id=message_id or f"msg-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
            field=field,
            origin=origin,
            origins=[origin.value],
            source_agent=None,
            trust_level=trust_level,
            tainted=tainted,
            propagation_depth=1 if tainted else 0,
            attack_id=attack_id,
            timestamp=_utc_now(),
            risk_score=max(0.0, min(1.0, float(risk_score))),
            security_labels=[],
        )
        provenance.security_labels = provenance_labels(provenance)
        return tracker.register(provenance)


def provenance_adjustment(
    *,
    base_score: float,
    tainted: bool,
    propagation_depth: int,
    target_agent: Optional[str],
    bonus_untrusted: float = 0.0,
    bonus_per_depth: float = 0.0,
    bonus_privileged_target: float = 0.0,
    max_depth_bonus: int = 3,
) -> Dict[str, object]:
    """Compute a configurable, provenance-aware risk adjustment.

    All bonuses default to 0.0, which reproduces the frozen, calibration-only
    operating point exactly.  Experiments enable bonuses as an explicit axis
    (provenance-aware vs not).  The returned record explains every
    contribution so the adjustment is auditable.
    """
    adjustments: List[str] = []
    total = 0.0
    if tainted and bonus_untrusted > 0.0:
        total += bonus_untrusted
        adjustments.append(f"tainted(+{bonus_untrusted:.3f})")
    if bonus_per_depth > 0.0 and propagation_depth > 0:
        depth_bonus = bonus_per_depth * min(propagation_depth, max(1, max_depth_bonus))
        total += depth_bonus
        adjustments.append(f"depth={propagation_depth}(+{depth_bonus:.3f})")
    if bonus_privileged_target > 0.0 and target_agent and target_agent in PRIVILEGED_TARGETS:
        total += bonus_privileged_target
        adjustments.append(f"privileged_target={target_agent}(+{bonus_privileged_target:.3f})")

    effective = max(0.0, min(1.0, float(base_score) + total))
    return {
        "base_score": round(float(base_score), 4),
        "effective_score": round(effective, 4),
        "adjustment": round(effective - float(base_score), 4),
        "tainted": bool(tainted),
        "propagation_depth": int(propagation_depth),
        "target_agent": target_agent,
        "contributions": adjustments,
        "applied": bool(adjustments),
    }


# Module-level request-scoped tracker.  Guards and the graph reset it at the
# same boundaries as the other request-local audit logs.
_TRACKER = ProvenanceTracker()


def get_provenance_tracker() -> ProvenanceTracker:
    """Return the canonical process-local provenance tracker."""
    return _TRACKER


def reset_provenance_tracker() -> None:
    """Clear all registered provenance records (request boundary)."""
    _TRACKER.clear()


def taint_summary(
    parent_ids: Sequence[str],
    *,
    tracker: Optional[ProvenanceTracker] = None,
) -> Dict[str, object]:
    """Describe the taint status of a set of parent message IDs (pure helper)."""
    tracker = tracker or _TRACKER
    parents = [tracker.get(pid) for pid in parent_ids if tracker.get(pid) is not None]
    return {
        "parent_count": len(parents),
        "tainted_parents": sum(1 for p in parents if p.tainted or is_untrusted(p.trust_level)),
        "max_depth": max([p.propagation_depth for p in parents], default=0),
        "origins": list(dict.fromkeys(o for p in parents for o in p.origins)),
    }


__all__ = [
    "MessageProvenance",
    "Origin",
    "PRIVILEGED_TARGETS",
    "UNTRUSTED_TRUST_LEVELS",
    "ProvenanceTracker",
    "get_provenance_tracker",
    "is_untrusted",
    "provenance_adjustment",
    "provenance_labels",
    "reset_provenance_tracker",
    "taint_summary",
]