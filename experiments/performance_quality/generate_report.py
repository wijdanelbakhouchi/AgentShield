"""Generate the Phase 16 report from processed artifacts and Phase 15 metrics."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from .config import PROCESSED_DIR, REPORTS_DIR, ROOT, SYSTEM_FREEZE, load_json
from .runtime import sha256_file


REPO = ROOT.parent.parent
PHASE15_PROCESSED = REPO / "experiments" / "final_evaluation" / "processed_results"


def _fmt(value: Any, suffix: str = "") -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.3f}{suffix}"
    return f"{value}{suffix}"


def _stats_line(stats: dict[str, Any]) -> str:
    return "mean=" + _fmt(stats.get("mean")) + ", median=" + _fmt(stats.get("median")) + ", P50=" + _fmt(stats.get("p50")) + ", P95=" + _fmt(stats.get("p95")) + ", P99=" + _fmt(stats.get("p99")) + ", std=" + _fmt(stats.get("std"))


def generate() -> str:
    performance = load_json(PROCESSED_DIR / "performance_summary.json")
    quality = load_json(PROCESSED_DIR / "quality_summary.json")
    figures = load_json(ROOT / "figures" / "figures_manifest.json") if (ROOT / "figures" / "figures_manifest.json").exists() else {"generated_figures": []}
    freeze = load_json(SYSTEM_FREEZE)
    phase15_full = load_json(PHASE15_PROCESSED / "FULL_AGENTSHIELD.json")
    phase15_baseline = load_json(PHASE15_PROCESSED / "BASELINE_NO_AGENTSHIELD.json")
    full_metrics = phase15_full["metrics"]["overall"]
    baseline_metrics = phase15_baseline["metrics"]["overall"]
    status = "PASS" if performance.get("semantic_runtime", {}).get("classification") == "SEMANTIC_READY" and performance.get("provider_runtime", {}).get("real_llm") and quality.get("status") == "COMPLETE" else "PARTIAL"
    lines = [
        "# Phase 16 Performance + Quality Report",
        "",
        f"**Status: {status}**",
        "",
        "This report is generated from processed artifacts. Performance numbers derive from paired raw JSONL records; Phase 15 security numbers are read programmatically from its processed artifacts.",
        "",
        "## Runtime Availability",
        "",
        f"- Semantic model: {freeze.get('semantic_runtime', {}).get('classification', 'SEMANTIC_UNAVAILABLE')}",
        f"- Provider: {freeze.get('provider_runtime', {}).get('provider', 'none')} / model {freeze.get('provider_runtime', {}).get('model') or 'N/A'} / real_llm={bool(freeze.get('provider_runtime', {}).get('real_llm'))}",
        "- Demo/fallback output used as quality evidence: NO",
        "",
        "## Performance",
        "",
        f"- Status: {'COMPLETE' if freeze.get('semantic_runtime', {}).get('classification') == 'SEMANTIC_READY' and freeze.get('provider_runtime', {}).get('real_llm') else 'PARTIAL — deterministic/backend timing measured; unavailable semantic/provider stages remain N/A'}",
        f"- Workload: {performance['baseline']['count']} baseline records and {performance['protected']['count']} protected records; repetitions={performance.get('steady_state_repetitions_per_sample')}; warmup/configuration={performance.get('warmup_requests_per_configuration')}",
        f"- Cold sandbox initialization: {_fmt(performance.get('cold_start_ms'))} ms",
        "",
        "| Configuration | Mean | Median | P50 | P95 | P99 | Std |",
        "|---|---:|---:|---:|---:|---:|---:|",
        f"| Baseline | {_fmt(performance['baseline']['total']['mean'])} | {_fmt(performance['baseline']['total']['median'])} | {_fmt(performance['baseline']['total']['p50'])} | {_fmt(performance['baseline']['total']['p95'])} | {_fmt(performance['baseline']['total']['p99'])} | {_fmt(performance['baseline']['total']['std'])} |",
        f"| Protected | {_fmt(performance['protected']['total']['mean'])} | {_fmt(performance['protected']['total']['median'])} | {_fmt(performance['protected']['total']['p50'])} | {_fmt(performance['protected']['total']['p95'])} | {_fmt(performance['protected']['total']['p99'])} | {_fmt(performance['protected']['total']['std'])} |",
        "",
        f"- Security overhead: {_fmt(performance['overhead'].get('absolute_overhead_ms'))} ms ({_fmt(performance['overhead'].get('relative_overhead_percent'))}%).",
        "",
        "## Stage Latency",
        "",
        "| Stage | Baseline | Protected |",
        "|---|---|---|",
    ]
    stage_labels = {
        "normalization_ms": "Normalization", "rules_ms": "Rules", "semantic_ms": "Semantic embeddings", "scoring_ms": "Scoring", "policy_ms": "Policy", "llm_ms": "LLM/provider", "tool_ms": "Tool execution", "tool_output_guard_ms": "Tool output guard", "context_isolation_ms": "Context isolation", "inter_agent_guard_ms": "Inter-agent guard", "database_ms": "Database/persistence", "agent_workflow_ms": "Agent workflow",
    }
    for key, label in stage_labels.items():
        lines.append(f"| {label} | {_stats_line(performance['baseline']['stages'].get(key, {}))} | {_stats_line(performance['protected']['stages'].get(key, {}))} |")
    lines.extend([
        "",
        "## Response Quality",
        "",
        f"- Status: {'COMPLETE' if quality.get('status') == 'COMPLETE' else 'PENDING'}",
        "- Method: human blinded A/B comparison using the checked-in rubric; no LLM judge was used.",
        f"- Dataset size: {quality.get('dataset', {}).get('task_count', 'N/A')} benign tasks; scored records: {quality.get('scored_records', 0)}",
        f"- Provider: {quality.get('provider', {}).get('provider', 'none') if isinstance(quality.get('provider'), dict) else quality.get('provider', 'none')}",
        "- Task Success / Relevance / Completeness / Factuality / Helpfulness: N/A — real provider response and human scores are pending.",
        "",
        "## Phase 15 Security Effectiveness (linked artifact)",
        "",
        f"- FULL_AGENTSHIELD: TP/TN/FP/FN={full_metrics.get('TP')}/{full_metrics.get('TN')}/{full_metrics.get('FP')}/{full_metrics.get('FN')}; recall={_fmt(full_metrics.get('recall'))}; F1={_fmt(full_metrics.get('f1'))}; ASR={_fmt(full_metrics.get('attack_success_rate'))}.",
        f"- BASELINE_NO_AGENTSHIELD: TP/TN/FP/FN={baseline_metrics.get('TP')}/{baseline_metrics.get('TN')}/{baseline_metrics.get('FP')}/{baseline_metrics.get('FN')}; ASR={_fmt(baseline_metrics.get('attack_success_rate'))}.",
        "",
        "## Results Pipeline",
        "",
        "runner → raw JSONL → compute_performance/compute_quality → processed summaries → figures → report",
        f"- Figures: {', '.join(figures.get('generated_figures', [])) or 'none'}",
        "- Every displayed number is derived from a raw/processed artifact and configuration; no manual measurements are embedded.",
        "",
        "## Traceability",
        "",
        f"- Runtime freeze: {SYSTEM_FREEZE.relative_to(REPO)} (SHA-256 {sha256_file(SYSTEM_FREEZE)})",
        f"- Performance summary: {(PROCESSED_DIR / 'performance_summary.json').relative_to(REPO)} (SHA-256 {sha256_file(PROCESSED_DIR / 'performance_summary.json')})",
        f"- Quality summary: {(PROCESSED_DIR / 'quality_summary.json').relative_to(REPO)} (SHA-256 {sha256_file(PROCESSED_DIR / 'quality_summary.json')})",
        f"- Git SHA recorded by freeze: {freeze.get('git_sha')}",
        f"- Seed: {performance.get('seed')}; Python: {freeze.get('python', {}).get('version', '').splitlines()[0]}",
        "",
        "## Limitations",
        "",
        "Semantic embeddings were unavailable in the current runtime, so semantic latency is N/A. Canonical tool-output and inter-agent guard timings are also N/A because those boundaries would re-enter the unavailable semantic runtime; no substitute latency is reported. No real provider was runtime-verified; response-quality scores remain PENDING. Deterministic backend timing uses an inert temporary SQLite sandbox and cannot substitute for provider latency.",
        "",
        "Reproduction commands are documented in `experiments/performance_quality/README.md`.",
    ])
    report = "\n".join(lines) + "\n"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "performance_quality_report.md").write_text(report, encoding="utf-8")
    return report


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    # PowerShell on Windows may expose a legacy code page; the generated
    # report intentionally contains Unicode workflow arrows.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    print(generate())


if __name__ == "__main__":
    main()
