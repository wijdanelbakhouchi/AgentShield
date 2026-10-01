"""Controlled same-topology workflow used by the deterministic Phase 15 study.

The evaluator reuses the repository normalizer, rule detector, and context
analyzer. Agent stages are represented as researcher -> planner -> writer ->
finalizer transitions with a bounded, inert sandbox: no shell, production
database, network, or real secret is ever reachable from an evaluation row.
"""

from __future__ import annotations

import time
import hashlib
from typing import Any

from analyzer.context_analyzer import ContextAnalyzer
from analyzer.rule_detector import RuleBasedDetector
from gateway.input_normalizer import normalize_input
from scoring.risk_scorer import RiskScorer
from state import SecurityAnalysisResult

from .config import ExperimentConfig


def _raw_representations(text: str) -> list[dict[str, Any]]:
    return [{"id": "raw-input", "text": text, "provenance": ["RAW_INPUT"], "depth": 0}]


def _context_flags(context: str, config: ExperimentConfig) -> list[str]:
    if not context or not config.context_isolation:
        return []
    flags = list(ContextAnalyzer.analyze_context(context).get("flags", []))
    for flag in RuleBasedDetector.scan(context).get("flags", []):
        candidate = f"CONTEXT_CONTENT:{flag}"
        if candidate not in flags:
            flags.append(candidate)
    return flags


def evaluate_sample(sample: dict[str, Any], config: ExperimentConfig, *, run_id: str = "deterministic-1") -> dict[str, Any]:
    """Evaluate one row under one immutable configuration."""

    started = time.perf_counter()
    request_key = f"{config.name}|{run_id}|{sample['sample_id']}".encode("utf-8")
    request_id = f"eval-{hashlib.sha256(request_key).hexdigest()[:16]}"
    text = str(sample["text"])
    context = str(sample.get("untrusted_context") or "")

    normalized = normalize_input(text) if config.normalization else {
        "normalized_input": text,
        "metadata": {"representations": _raw_representations(text), "has_obfuscation": False},
    }
    representations = normalized["metadata"].get("representations", [])
    rule_result = RuleBasedDetector.scan(representations) if config.rules else {"flags": [], "findings": []}
    rule_flags = list(rule_result.get("flags", []))
    context_flags = _context_flags(context, config)

    source_type = str((sample.get("source_metadata") or {}).get("type") or "")
    tool_guard_flags: list[str] = []
    if config.tool_output_guard and source_type == "tool_output" and context_flags:
        tool_guard_flags = [f"TOOL_OUTPUT_GUARD:{flag}" for flag in context_flags]

    inter_agent_flags: list[str] = []
    if config.inter_agent_guard and bool(sample.get("requires_agent_workflow")):
        inter_agent_flags = [f"INTER_AGENT_GUARD:{flag}" for flag in rule_flags]
        if context_flags:
            inter_agent_flags.extend(f"INTER_AGENT_GUARD:{flag}" for flag in context_flags)

    semantic = {
        "semantic_similarity_enabled": False,
        "status": "unavailable" if config.semantic_similarity else "disabled",
        "reason": "Pinned embedding runtime was unavailable; no lexical substitute was used.",
        "findings": [],
    }
    all_findings = list(dict.fromkeys(rule_flags + context_flags + tool_guard_flags + inter_agent_flags))
    analysis = SecurityAnalysisResult(
        request_id=request_id,
        timestamp="2025-09-15T00:00:00+00:00",
        normalized_input=str(normalized.get("normalized_input") or text),
        rule_flags=rule_flags,
        llm_classification={"is_malicious": False, "category": "Unavailable", "confidence": 0.0},
        context_flags=context_flags,
        semantic_similarity=semantic,
        raw_signals={
            "normalization": normalized.get("metadata", {}),
            "tool_output_guard": tool_guard_flags,
            "inter_agent_guard": inter_agent_flags,
        },
        is_flagged=bool(all_findings),
    )

    blocked_at: str | None = None
    if config.agent_shield:
        if rule_flags:
            blocked_at = "ingress_rules"
        elif tool_guard_flags:
            blocked_at = "tool_output_guard"
        elif context_flags:
            blocked_at = "context_isolation"
        elif inter_agent_flags:
            blocked_at = "inter_agent_guard"

    if blocked_at:
        risk = RiskScorer.calculate_score(analysis)
        decision = "BLOCK"
    else:
        risk = RiskScorer.calculate_score(
            analysis.model_copy(update={"rule_flags": [], "context_flags": [], "is_flagged": False})
        )
        decision = "ALLOW"

    malicious = str(sample["label"]).lower() == "malicious"
    attack_success = bool(malicious and decision == "ALLOW")
    return {
        "sample_id": sample["sample_id"],
        "group_id": sample["group_id"],
        "label": sample["label"],
        "category": sample["category"],
        "configuration": config.name,
        "run_id": run_id,
        "provider": "deterministic-detector-only",
        "model": None,
        "decision": decision,
        "risk_score": float(risk.score),
        "findings": all_findings,
        "attack_success": attack_success,
        "mitigated": bool(malicious and not attack_success),
        "blocked_at": blocked_at,
        "workflow_stages": ["researcher", "planner", "writer", "finalizer"] if not blocked_at else ["researcher"],
        "latency_ms": round((time.perf_counter() - started) * 1000.0, 3),
        "request_id": request_id,
        "expected_security_outcome": sample["expected_security_outcome"],
        "semantic_status": semantic["status"],
    }
