"""Immutable experiment configuration for the propagation study.

Each configuration is an ablation along the axes that answer the research
question: which defense layer closes the propagation gap, and at what cost?

Axes:

* ``gateway``        — inspect ingress user/context content with the canonical
                       normalize -> analyze -> score -> policy stack.
* ``inter_agent``    — inspect every inter-agent handoff (message-level
                       monitoring, the research focus of AgentShield).
* ``tool_security``  — inspect tool arguments (RBAC/parameter validation) and
                       tool outputs before the researcher consumes them.
* ``semantic``       — enable the frozen sentence-embedding detector.
* ``provenance``     — apply the provenance-aware risk adjustment at inter-agent
                       boundaries (taint + depth + privileged-target bonuses).
* ``policy_mode``    — ``score_threshold`` (frozen calibration) or ``banded``
                       (LOW/MEDIUM/HIGH/CRITICAL -> ALLOW/SANITIZE/BLOCK/BLOCK).
* ``alert_only``     — never block; record what *would* be flagged so detection
                       quality can be measured independently of mitigation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "configs"
DATASET_DIR = ROOT / "datasets"

CONFIG_NAMES = (
    "baseline_no_agentshield",
    "gateway_only",
    "full_no_semantic",
    "full_no_provenance",
    "full_provenance",
    "full_banded_sanitize",
    "alert_only_detection",
)


@dataclass(frozen=True)
class ExperimentConfig:
    name: str
    gateway: bool
    inter_agent: bool
    tool_security: bool
    semantic: bool
    provenance: bool
    policy_mode: str = "score_threshold"
    alert_only: bool = False
    provenance_bonus_untrusted: float = 0.0
    provenance_bonus_per_depth: float = 0.0
    provenance_bonus_privileged_target: float = 0.0
    notes: str = ""

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "ExperimentConfig":
        required = {"name", "gateway", "inter_agent", "tool_security", "semantic", "provenance"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"Experiment config missing fields: {sorted(missing)}")
        for field_name in required - {"name"}:
            if not isinstance(data[field_name], bool):
                raise ValueError(f"Experiment config field {field_name!r} must be boolean")
        policy_mode = str(data.get("policy_mode", "score_threshold"))
        if policy_mode not in {"score_threshold", "banded"}:
            raise ValueError("policy_mode must be score_threshold or banded")
        return cls(
            name=str(data["name"]),
            gateway=bool(data["gateway"]),
            inter_agent=bool(data["inter_agent"]),
            tool_security=bool(data["tool_security"]),
            semantic=bool(data["semantic"]),
            provenance=bool(data["provenance"]),
            policy_mode=policy_mode,
            alert_only=bool(data.get("alert_only", False)),
            provenance_bonus_untrusted=float(data.get("provenance_bonus_untrusted", 0.0)),
            provenance_bonus_per_depth=float(data.get("provenance_bonus_per_depth", 0.0)),
            provenance_bonus_privileged_target=float(data.get("provenance_bonus_privileged_target", 0.0)),
            notes=str(data.get("notes", "")),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            field_name: getattr(self, field_name)
            for field_name in self.__dataclass_fields__
        }

    def provenance_bonuses(self) -> dict[str, float]:
        return {
            "bonus_untrusted": self.provenance_bonus_untrusted,
            "bonus_per_depth": self.provenance_bonus_per_depth,
            "bonus_privileged_target": self.provenance_bonus_privileged_target,
        }


def load_config(name_or_path: str) -> ExperimentConfig:
    candidate = Path(name_or_path)
    if candidate.suffix != ".json":
        candidate = CONFIG_DIR / f"{name_or_path}.json"
    if not candidate.exists():
        raise FileNotFoundError(f"Unknown propagation config: {name_or_path}")
    with candidate.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Propagation config must be a JSON object")
    return ExperimentConfig.from_mapping(data)


def load_all_configs() -> list[ExperimentConfig]:
    return [load_config(name) for name in CONFIG_NAMES]