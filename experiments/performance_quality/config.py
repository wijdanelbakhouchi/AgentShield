"""Configuration and immutable paths for the Phase 16 experiments."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DATASETS_DIR = ROOT / "datasets"
CONFIGS_DIR = ROOT / "configs"
RUNNERS_DIR = ROOT / "runners"
RAW_DIR = ROOT / "raw_results"
PROCESSED_DIR = ROOT / "processed_results"
FIGURES_DIR = ROOT / "figures"
REPORTS_DIR = ROOT / "reports"

PERFORMANCE_DATASET = DATASETS_DIR / "performance_workload_v1.json"
QUALITY_DATASET = DATASETS_DIR / "quality_tasks_v1.json"
QUALITY_RUBRIC = DATASETS_DIR / "quality_rubric_v1.json"
SYSTEM_FREEZE = DATASETS_DIR / "system_freeze_phase16.json"

PERFORMANCE_CONFIG_NAMES = ("baseline_no_agentshield", "full_agentshield")


@dataclass(frozen=True)
class PerformanceConfig:
    """One checked-in workload configuration.

    ``agent_shield`` is the only intervention switch.  The baseline therefore
    keeps the same task stages and sandbox while disabling security controls.
    """

    name: str
    agent_shield: bool
    description: str

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "PerformanceConfig":
        required = {"name", "agent_shield", "description"}
        missing = required - data.keys()
        if missing:
            raise ValueError(f"Performance config missing fields: {sorted(missing)}")
        if not isinstance(data["name"], str) or not data["name"]:
            raise ValueError("Performance config name must be non-empty")
        if not isinstance(data["agent_shield"], bool):
            raise ValueError("agent_shield must be boolean")
        if not isinstance(data["description"], str) or not data["description"]:
            raise ValueError("Performance config description must be non-empty")
        return cls(data["name"], data["agent_shield"], data["description"])


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_config(name: str) -> PerformanceConfig:
    candidate = Path(name)
    if candidate.suffix != ".json":
        candidate = CONFIGS_DIR / f"{name}.json"
    if not candidate.is_absolute() and not candidate.exists():
        candidate = ROOT / candidate
    if not candidate.exists():
        raise FileNotFoundError(f"Unknown Phase 16 configuration: {name}")
    data = load_json(candidate)
    if not isinstance(data, dict):
        raise ValueError("Performance config must be an object")
    return PerformanceConfig.from_mapping(data)


def load_all_configs() -> list[PerformanceConfig]:
    return [load_config(name) for name in PERFORMANCE_CONFIG_NAMES]

