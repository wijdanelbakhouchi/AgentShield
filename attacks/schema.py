"""Typed attack-sample schema for the AgentShield propagation benchmark.

Every sample carries the metadata an evaluator needs to score a defense on a
multi-agent workflow: where the payload enters (``injection_point``), which
agent it targets (``target_agent``), how many hops that requires in the frozen
graph (``propagation_depth``), what the attacker wants (``attacker_goal``),
and the expected security disposition (``ground_truth`` / ``expected_policy`` /
``expected_layer``).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class InjectionPoint(str, Enum):
    """Where the attack payload enters the workflow."""

    USER_INPUT = "user_input"
    DOCUMENT = "document"
    TOOL_OUTPUT = "tool_output"


class AttackCategory(str, Enum):
    """Attack families used by the benchmark dataset builder."""

    DIRECT_INJECTION = "DIRECT_INJECTION"
    INDIRECT_DOCUMENT_INJECTION = "INDIRECT_DOCUMENT_INJECTION"
    TOOL_OUTPUT_INJECTION = "TOOL_OUTPUT_INJECTION"
    INTER_AGENT_PROPAGATION = "INTER_AGENT_PROPAGATION"
    MULTI_HOP_PROPAGATION = "MULTI_HOP_PROPAGATION"
    PLANNER_TARGETING = "PLANNER_TARGETING"
    TRIGGER_BASED = "TRIGGER_BASED"
    OBFUSCATED_INJECTION = "OBFUSCATED_INJECTION"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    TOOL_ABUSE = "TOOL_ABUSE"
    PARAMETER_MANIPULATION = "PARAMETER_MANIPULATION"
    DANGEROUS_SEQUENCE = "DANGEROUS_SEQUENCE"
    BENIGN_NORMAL = "BENIGN_NORMAL"
    BENIGN_DISTRACTOR = "BENIGN_DISTRACTOR"


class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


# Frozen graph order for the testbed.  Depth is measured in hops from the
# nearest untrusted ingress to the target agent.
AGENT_ORDER = ("researcher", "planner", "writer", "finalizer")


def expected_depth(injection_point: InjectionPoint, target_agent: str) -> int:
    """Compute the propagation depth of a payload in the frozen graph."""
    target_index = AGENT_ORDER.index(target_agent)
    if injection_point == InjectionPoint.USER_INPUT:
        return target_index + 1
    if injection_point == InjectionPoint.DOCUMENT:
        return target_index + 1
    if injection_point == InjectionPoint.TOOL_OUTPUT:
        return target_index + 1
    return 1


class AttackSample(BaseModel):
    """One benchmark row with full research metadata."""

    attack_id: str = Field(description="Stable unique identifier")
    category: AttackCategory = Field(description="Attack family")
    label: str = Field(description="malicious | benign")
    difficulty: Difficulty = Field(description="easy | medium | hard")
    injection_point: InjectionPoint = Field(
        description="Where the payload enters the workflow"
    )
    source: str = Field(
        description="Attacker control channel: user, document_author, compromised_tool, agent"
    )
    target_agent: str = Field(
        description="Agent the attack tries to influence (researcher/planner/writer/finalizer)"
    )
    target_tool: Optional[str] = Field(
        default=None, description="Tool the attack tries to invoke, if any"
    )
    attacker_goal: str = Field(description="One-line attacker objective")
    propagation_depth: int = Field(
        description="Hops from untrusted ingress to the target agent"
    )
    obfuscation: str = Field(
        default="none", description="Transformation family, or 'none'"
    )
    transformed_from: Optional[str] = Field(
        default=None, description="attack_id of the base sample, for transformed rows"
    )
    ground_truth: str = Field(
        description="True security disposition: attack reaches target (success) or is contained"
    )
    expected_policy: str = Field(
        description="Expected decision: ALLOW | SANITIZE | REVIEW | BLOCK"
    )
    expected_layer: str = Field(
        description="Defense layer expected to contain the attack: gateway | tool_guard | "
        "inter_agent_guard | provenance | context_isolation"
    )
    text: str = Field(description="Primary payload text evaluated by the detectors")
    untrusted_context: Optional[str] = Field(
        default=None,
        description="External/document/tool context carrying the payload when "
        "injection_point != user_input",
    )
    tool_arguments: Optional[Dict[str, Any]] = Field(
        default=None, description="Tool arguments for tool-abuse samples"
    )
    notes: str = Field(default="", description="Authoring notes / rationale")

    def to_row(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "AttackSample":
        return cls.model_validate(row)


__all__ = [
    "AGENT_ORDER",
    "AttackCategory",
    "AttackSample",
    "Difficulty",
    "InjectionPoint",
    "expected_depth",
]
