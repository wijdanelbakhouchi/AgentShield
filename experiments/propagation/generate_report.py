"""Generate the thesis-ready markdown report for the propagation study.

The report is written from the persisted processed/raw results only; it never
invents numbers.  Results not yet measured are labelled ``NOT YET MEASURED``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .generate_figures import _CONFIG_LABELS, _available_configs, _load_processed, _load_raw

ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"
REPORT_PATH = REPORTS_DIR / "propagation_report.md"


def _fmt(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def _table_rows(metric: str) -> list[str]:
    rows = []
    for name in _available_configs():
        data = _load_processed(name)
        value = data["metrics"]["overall"].get(metric)
        rows.append(f"| {_CONFIG_LABELS.get(name, name)} | {_fmt(value)} |")
    return rows


def build_report() -> str:
    configs = _available_configs()
    lines: list[str] = []

    lines.append("# AgentShield Propagation Study — Results Report")
    lines.append("")
    lines.append(
        "**Status:** deterministic detector-stack evaluation on the frozen "
        "benchmark v2 corpus. All numbers below are reported from processed "
        "experiment summaries; raw run records are generated artifacts and are "
        "not committed by default."
    )
    lines.append("")

    lines.append("## 1. Research questions")
    lines.append("")
    lines.append(
        "1. How far do prompt-injection payloads propagate through the frozen "
        "multi-agent graph when the system is unprotected?"
    )
    lines.append(
        "2. Which defense layer (gateway, tool security, message-level "
        "inter-agent monitoring, provenance awareness) closes the propagation "
        "gap, and by how much?"
    )
    lines.append(
        "3. What is the false-positive cost of each configuration on benign and "
        "benign-with-adversarial-distractor content?"
    )
    lines.append(
        "4. How much do adaptive (transformed) attacks degrade containment "
        "relative to non-adaptive attacks?"
    )
    lines.append("")

    lines.append("## 2. Methodology")
    lines.append("")
    lines.append(
        "- **Testbed:** frozen graph `user -> researcher -> planner -> writer -> "
        "finalizer` with canonical `InterAgentGuard` boundaries; agent prompts "
        "and topology are frozen in the propagation experiment configuration."
    )
    lines.append(
        "- **Detector stack:** canonical normalize -> rules -> context -> "
        "sentence-embedding similarity -> calibrated risk -> policy. The LLM "
        "classifier is excluded because its calibrated weight is 0.00; scores "
        "are unchanged."
    )
    lines.append(
        "- **Propagation model:** deterministic reachability — an agent that "
        "receives payload-bearing content reproduces it verbatim in its output. "
        "This measures the security envelope, not LLM compliance, and is fully "
        "reproducible without a live provider."
    )
    lines.append(
        "- **Corpus:** benchmark v2 (dev + held-out test template families); "
        "the split methodology is encoded in the benchmark dataset builder and "
        "propagation experiment configuration."
    )
    lines.append(
        "- **Uncertainty:** 95% group bootstrap CIs (template family as the "
        "resampling unit); paired configuration comparisons use McNemar's test "
        "with Yates correction on per-sample attack success."
    )
    lines.append("")

    lines.append("## 3. Security metrics (per configuration)")
    lines.append("")
    lines.append("| Configuration | ASR | Mitigation | Precision | Recall | F1 | FPR |")
    lines.append("|---|---|---|---|---|---|---|")
    for name in configs:
        data = _load_processed(name)
        overall = data["metrics"]["overall"]
        label = _CONFIG_LABELS.get(name, name)
        lines.append(
            f"| {label} | {_fmt(overall.get('attack_success_rate'))} | "
            f"{_fmt(overall.get('mitigation_rate'))} | {_fmt(overall.get('precision'))} | "
            f"{_fmt(overall.get('recall'))} | {_fmt(overall.get('f1'))} | "
            f"{_fmt(overall.get('fpr'))} |"
        )
    lines.append("")
    lines.append(
        "FPR is measured on the benign arm (normal + benign-with-distractor); "
        "a high FPR on distractor content is a measured cost of aggressive "
        "deterministic rules, not a claim of zero false positives."
    )
    lines.append("")

    lines.append("## 4. Propagation metrics")
    lines.append("")
    lines.append("| Configuration | Mean depth | Median depth | Privileged reach | Contained @ gateway | Contained @ tool | Contained @ researcher | Contained @ inter-agent |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for name in configs:
        data = _load_processed(name)
        propagation = data["metrics"]["propagation"]
        label = _CONFIG_LABELS.get(name, name)
        lines.append(
            f"| {label} | {_fmt(propagation.get('mean_depth'))} | "
            f"{_fmt(propagation.get('median_depth'))} | "
            f"{_fmt(propagation.get('privileged_reach_rate'))} | "
            f"{propagation.get('contained_at_gateway', 0)} | "
            f"{propagation.get('contained_at_tool_security', 0)} | "
            f"{propagation.get('contained_at_researcher', 0)} | "
            f"{propagation.get('contained_at_inter_agent', 0)} |"
        )
    lines.append("")
    lines.append(
        "Privileged reach = attacks targeting the writer or finalizer that "
        "reached their target."
    )
    lines.append("")

    lines.append("## 5. Paired comparisons (McNemar)")
    lines.append("")
    pairs_path = ROOT / "processed_results" / "_paired.json"
    if pairs_path.exists():
        pairs = json.loads(pairs_path.read_text(encoding="utf-8"))
        lines.append("| Comparison | p-value | Paired samples |")
        lines.append("|---|---|---|")
        for name, test in pairs.items():
            lines.append(f"| {name} | {_fmt(test.get('p_value'))} | {test.get('paired_samples')} |")
        lines.append("")
        lines.append(
            "p < 0.05 indicates a statistically significant difference in "
            "per-sample attack success on this corpus."
        )
    else:
        lines.append("NOT YET MEASURED — run `run_evaluation.py` to persist paired tests.")
    lines.append("")

    lines.append("## 6. Adaptive vs non-adaptive attacks")
    lines.append("")
    records_by_config = {name: _load_raw(name) for name in configs}

    def arm_asr(records: list[dict], obfuscation: str) -> str:
        arm = [r for r in records if r["label"] == "malicious" and r.get("obfuscation") == obfuscation]
        if not arm:
            return "—"
        return f"{sum(1 for r in arm if r['attack_success']) / len(arm):.4f} (n={len(arm)})"

    lines.append("| Configuration | Non-adaptive ASR | Adaptive ASR |")
    lines.append("|---|---|---|")
    for name in configs:
        records = records_by_config.get(name, [])
        lines.append(
            f"| {_CONFIG_LABELS.get(name, name)} | {arm_asr(records, 'none')} | "
            f"{_adaptive_asr(records)} |"
        )
    lines.append("")

    lines.append("## 7. Detector signal quality (alert-only arm)")
    lines.append("")
    if "ALERT_ONLY_DETECTION" in configs:
        data = _load_processed("ALERT_ONLY_DETECTION")
        detection = data["metrics"]["detection"]
        lines.append(
            f"Precision {_fmt(detection.get('precision'))}, recall "
            f"{_fmt(detection.get('recall'))}, F1 {_fmt(detection.get('f1'))}, "
            f"FPR {_fmt(detection.get('fpr'))}, detection rate "
            f"{_fmt(detection.get('detection_rate'))}."
        )
    else:
        lines.append("NOT YET MEASURED.")
    lines.append("")

    lines.append("## 8. Figures")
    lines.append("")
    manifest_path = ROOT / "figures" / "figures_manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name, path in manifest.get("figures", {}).items():
            lines.append(f"- `{name}` -> `{path}`")
    else:
        lines.append("NOT YET GENERATED — run `generate_figures.py`.")
    lines.append("")

    lines.append("## 9. Honest limitations")
    lines.append("")
    lines.append(
        "- The propagation model measures payload **reachability**, not whether "
        "a particular LLM would comply; real-provider compliance studies remain "
        "future work (see `experiments/e2e_evaluation/`)."
    )
    lines.append(
        "- FPR is estimated on a small benign arm; bootstrap CIs are wide."
    )
    lines.append(
        "- Semantic similarity uses the frozen English-focused MiniLM model; "
        "multilingual coverage is not claimed."
    )
    lines.append(
        "- Provenance bonuses (0.03 / 0.01 / 0.02) are one operating point; "
        "sensitivity to these parameters is future work."
    )
    lines.append(
        "- The LLM classifier (weight 0.00) was excluded; a future calibrated "
        "classifier tier can be added without changing the stack."
    )
    lines.append("")

    lines.append("## 10. How to reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("python -m experiments.propagation.run_evaluation --all")
    lines.append("python -m experiments.propagation.generate_figures")
    lines.append("python -m experiments.propagation.generate_report")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _adaptive_asr(records: list[dict]) -> str:
    arm = [r for r in records if r["label"] == "malicious" and r.get("obfuscation") != "none"]
    if not arm:
        return "—"
    return f"{sum(1 for r in arm if r['attack_success']) / len(arm):.4f} (n={len(arm)})"


def main() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(build_report(), encoding="utf-8")
    print(f"Report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
