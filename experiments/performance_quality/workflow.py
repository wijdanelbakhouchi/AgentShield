"""Safe, deterministic four-stage workload used for timing comparisons.

The harness deliberately does not call a provider, shell, network, production
database, or real tool.  It keeps the same researcher/planner/writer/finalizer
task contract so baseline and protected requests differ only in security
intervention and the measured security work.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from analyzer.context_analyzer import ContextAnalyzer
from analyzer.rule_detector import RuleBasedDetector
from analyzer.semantic_similarity import get_semantic_detector
from gateway.input_normalizer import normalize_input
from hooks.inter_agent_guard import InterAgentGuard
from hooks.untrusted_content_guard import UntrustedContentGuard
from policy.policy_engine import PolicyEngine
from scoring.risk_scorer import RiskScorer
from state import AgentHandoff, Decision, SecurityAnalysisResult, UntrustedContent

from .config import PerformanceConfig


STAGES = (
    "normalization_ms",
    "rules_ms",
    "semantic_ms",
    "scoring_ms",
    "policy_ms",
    "llm_ms",
    "tool_ms",
    "tool_output_guard_ms",
    "context_isolation_ms",
    "inter_agent_guard_ms",
    "database_ms",
    "agent_workflow_ms",
)


def _elapsed(started: float) -> float:
    return round(max((time.perf_counter() - started) * 1000.0, 0.001), 3)


def _timed(function: Callable[[], Any]) -> tuple[Any, float]:
    started = time.perf_counter()
    value = function()
    return value, _elapsed(started)


def _request_id(config: str, sample_id: str, run_number: int) -> str:
    material = f"phase16|{config}|{sample_id}|{run_number}".encode("utf-8")
    return f"perf-{hashlib.sha256(material).hexdigest()[:16]}"


def _sandbox_tool(sample: dict[str, Any]) -> str:
    """Return a deterministic in-memory result; never executes user text."""

    category = str(sample.get("category", "task"))
    return json.dumps({"sandbox": True, "category": category, "result": "bounded lookup complete"}, sort_keys=True)


@contextmanager
def _quiet_inter_agent_audit():
    """Keep timing runs out of application audit storage while using the guard."""

    original = InterAgentGuard.__dict__["_emit_audit"]
    InterAgentGuard._emit_audit = classmethod(lambda cls, result, *, intercepted_field: None)
    try:
        yield
    finally:
        setattr(InterAgentGuard, "_emit_audit", original)


def _persist(path: str | Path, record: dict[str, Any]) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS phase16_records (request_id TEXT PRIMARY KEY, configuration TEXT, decision TEXT, total_ms REAL)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO phase16_records(request_id, configuration, decision, total_ms) VALUES (?, ?, ?, ?)",
            (record["request_id"], record["configuration"], record["decision"], record["total_ms"]),
        )
        connection.commit()
    finally:
        connection.close()


def initialize_sandbox(path: str | Path) -> float:
    """Create only the temporary experiment table and return cold-init time."""

    started = time.perf_counter()
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS phase16_records (request_id TEXT PRIMARY KEY, configuration TEXT, decision TEXT, total_ms REAL)"
        )
        connection.commit()
    finally:
        connection.close()
    return _elapsed(started)


def _security(sample: dict[str, Any], config: PerformanceConfig, request_id: str, semantic_ready: bool) -> tuple[dict[str, Any], dict[str, float | None]]:
    timings = {stage: None for stage in STAGES}
    if not config.agent_shield:
        return {"decision": "ALLOW", "risk_score": None, "findings": [], "semantic_status": "not_run", "blocked_at": None}, timings

    normalized, timings["normalization_ms"] = _timed(lambda: normalize_input(str(sample.get("text", ""))))
    representations = normalized.get("metadata", {}).get("representations", [])
    rule_result, timings["rules_ms"] = _timed(lambda: RuleBasedDetector.scan(representations))
    rule_flags = list(rule_result.get("flags", []))

    context = str(sample.get("untrusted_context") or "")
    context_flags: list[str] = []
    if context:
        def inspect_context() -> list[str]:
            result = ContextAnalyzer.analyze_context(context)
            flags = list(result.get("flags", []))
            for flag in RuleBasedDetector.scan(context).get("flags", []):
                value = f"CONTEXT_CONTENT:{flag}"
                if value not in flags:
                    flags.append(value)
            return flags

        context_flags, timings["context_isolation_ms"] = _timed(inspect_context)

    semantic_status = "unavailable"
    semantic_result: dict[str, Any] = {
        "semantic_similarity_enabled": False,
        "status": "unavailable",
        "findings": [],
    }
    if semantic_ready:
        detector = get_semantic_detector()
        semantic_result, timings["semantic_ms"] = _timed(
            lambda: detector.detect(str(normalized.get("normalized_input") or ""), representations)
        )
        semantic_status = str(semantic_result.get("status", "unavailable"))
    else:
        semantic_status = "unavailable"

    analysis = SecurityAnalysisResult(
        request_id=request_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        normalized_input=str(normalized.get("normalized_input") or ""),
        rule_flags=rule_flags,
        llm_classification={"is_malicious": False, "category": "Unavailable", "confidence": 0.0},
        context_flags=context_flags,
        semantic_similarity=semantic_result,
        raw_signals={"normalization": normalized.get("metadata", {})},
        is_flagged=bool(rule_flags or context_flags or semantic_result.get("findings")),
    )
    risk, timings["scoring_ms"] = _timed(lambda: RiskScorer.calculate_score(analysis))
    policy, timings["policy_ms"] = _timed(lambda: PolicyEngine.evaluate(analysis, risk))
    findings = list(dict.fromkeys(rule_flags + context_flags + [str(item) for item in semantic_result.get("findings", [])]))
    return {
        "decision": policy.action.value,
        "risk_score": float(risk.score),
        "findings": findings,
        "semantic_status": semantic_status,
        "blocked_at": "security_policy" if policy.action in {Decision.BLOCK, Decision.REVIEW} else None,
    }, timings


def _run_agents(sample: dict[str, Any], *, protected: bool, request_id: str, timings: dict[str, float | None], semantic_ready: bool) -> tuple[str, bool]:
    started = time.perf_counter()
    query = str(sample.get("text", "")).strip()
    research = f"researcher: bounded notes for {query[:160]}"
    if sample.get("requires_tool"):
        tool_output, timings["tool_ms"] = _timed(lambda: _sandbox_tool(sample))
        research += f" | tool={tool_output}"
        if protected and semantic_ready:
            content = UntrustedContent(
                content_id=f"content-{request_id}",
                request_id=request_id,
                source_type=str((sample.get("source_metadata") or {}).get("type") or "tool_output"),
                source_name=str((sample.get("source_metadata") or {}).get("name") or "sandbox"),
                text=tool_output,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            with _quiet_inter_agent_audit():
                _guard_result, timings["tool_output_guard_ms"] = _timed(lambda: UntrustedContentGuard.inspect(content, tool_execution_id=f"tool-{request_id}"))
    plan = f"planner: answer the bounded task using {len(research)} research characters"
    draft = f"writer: {plan}; source notes retained"
    final = f"finalizer: {draft}"
    timings["agent_workflow_ms"] = _elapsed(started)
    return final, True


def run_request(
    sample: dict[str, Any],
    config: PerformanceConfig,
    *,
    run_number: int,
    semantic_ready: bool,
    sandbox_db: str | Path,
    measurement_phase: str = "warm",
    persist: bool = True,
) -> dict[str, Any]:
    """Run one comparable baseline/protected request and persist raw telemetry."""

    started = time.perf_counter()
    request_id = _request_id(config.name, str(sample["sample_id"]), run_number)
    security, timings = _security(sample, config, request_id, semantic_ready)
    blocked = config.agent_shield and security["decision"] in {"BLOCK", "REVIEW"}
    response = None
    workflow_completed = False
    if not blocked:
        response, workflow_completed = _run_agents(sample, protected=config.agent_shield, request_id=request_id, timings=timings, semantic_ready=semantic_ready)
        if config.agent_shield and semantic_ready and bool(sample.get("requires_agent_workflow")) and response:
            handoff = AgentHandoff(
                handoff_id=f"handoff-{request_id}",
                request_id=request_id,
                source_agent="researcher",
                target_agent="planner",
                content=response,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            with _quiet_inter_agent_audit():
                _handoff, timings["inter_agent_guard_ms"] = _timed(lambda: InterAgentGuard.evaluate_handoff(handoff, intercepted_field="research_data"))
    decision = str(security["decision"])
    total_without_persistence = _elapsed(started)
    record = {
        "run_id": f"phase16-{config.name.lower()}-{run_number}",
        "run_number": int(run_number),
        "measurement_phase": measurement_phase,
        "sample_id": sample["sample_id"],
        "configuration": config.name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": "none",
        "model": None,
        "real_llm": False,
        **timings,
        "decision": decision,
        "risk_score": security["risk_score"],
        "findings": security["findings"],
        "semantic_status": security["semantic_status"],
        "workflow_completed": workflow_completed,
        "response_available": bool(response),
        "request_id": request_id,
        "total_ms": total_without_persistence,
    }
    persistence_started = time.perf_counter()
    if persist:
        _persist(sandbox_db, record)
    timings["database_ms"] = _elapsed(persistence_started)
    record["database_ms"] = timings["database_ms"]
    record["total_ms"] = _elapsed(started)
    record["attack_safe_sandbox"] = True
    return record
