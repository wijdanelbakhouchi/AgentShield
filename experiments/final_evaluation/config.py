"""Immutable experiment configuration loading for Phase 15."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "configs"
CONFIG_NAMES = (
    "full",
    "no_normalization",
    "no_rules",
    "no_semantic_similarity",
    "no_tool_output_guard",
    "no_inter_agent_guard",
    "no_context_isolation",
    "baseline_no_agentshield",
)


@dataclass(frozen=True)
class ExperimentConfig:
    name: str
    normalization: bool
    rules: bool
    semantic_similarity: bool
    tool_output_guard: bool
    inter_agent_guard: bool
    context_isolation: bool
    agent_shield: bool

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "ExperimentConfig":
        required = {field for field in cls.__dataclass_fields__}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"Experiment config missing fields: {sorted(missing)}")
        values = {field: data[field] for field in required}
        if not isinstance(values["name"], str) or not values["name"]:
            raise ValueError("Experiment config name must be non-empty")
        for field in required - {"name"}:
            if not isinstance(values[field], bool):
                raise ValueError(f"Experiment config field {field!r} must be boolean")
        if not values["agent_shield"] and any(values[field] for field in required - {"name", "agent_shield"}):
            raise ValueError("A baseline config cannot enable a defense layer")
        return cls(**values)

    def as_dict(self) -> dict[str, Any]:
        return {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
        }


def load_config(name_or_path: str) -> ExperimentConfig:
    """Load one checked-in JSON config without mutating security settings."""

    candidate = Path(name_or_path)
    if candidate.suffix != ".json":
        candidate = CONFIG_DIR / f"{name_or_path}.json"
    if not candidate.is_absolute():
        candidate = ROOT / candidate if not candidate.exists() else candidate
    if not candidate.exists():
        raise FileNotFoundError(f"Unknown Phase 15 config: {name_or_path}")
    with candidate.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Experiment config must be a JSON object")
    return ExperimentConfig.from_mapping(data)


def load_all_configs() -> list[ExperimentConfig]:
    return [load_config(name) for name in CONFIG_NAMES]
