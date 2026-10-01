"""Generate the Phase 15 evidence report from frozen artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .config import CONFIG_NAMES, ROOT, load_config
from .validate_dataset import MANIFEST_PATH


PROCESSED_DIR = ROOT / "processed_results"
FREEZE_PATH = ROOT / "datasets" / "system_freeze.json"
REPORT_PATH = ROOT / "reports" / "final_evaluation_report.md"


def _load(name: str) -> dict[str, Any]:
    path = PROCESSED_DIR / f"{load_config(name).name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing processed result: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _pct(value: float) -> str:
    if value is None:
        return "N/A"
    return f"{100.0 * float(value):.1f}%"


def _metric(metrics: dict[str, Any], key: str) -> str:
    return _pct(metrics.get(key, 0.0))


def generate_report(path: Path = REPORT_PATH) -> str:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    freeze = json.loads(FREEZE_PATH.read_text(encoding="utf-8"))
    results = {load_config(name).name: _load(name) for name in CONFIG_NAMES}
    full = results["FULL_AGENTSHIELD"]
    baseline = results["BASELINE_NO_AGENTSHIELD"]
    full_metrics = full["metrics"]["overall"]
    baseline_metrics = baseline["metrics"]["overall"]

    lines = [
        "# Phase 15 Final Research Evaluation Report",
        "",
        "**Status: FRAMEWORK / DETERMINISTIC EVALUATION ONLY**",
        "",
        "This report is generated from frozen dataset, configuration, and raw-result artifacts. It is not a thesis conclusion.",
        "",
        "## Dataset",
        "",
        f"- Version: {manifest['dataset_version']}",
        f"- SHA-256: {manifest['sha256']}",
        f"- Samples: {manifest['total_samples']} (malicious {manifest['labels']['malicious']}, benign {manifest['labels']['benign']})",
        f"- Effective groups: {manifest['effective_groups']}",
        f"- Category counts: {json.dumps(manifest['category_counts'], sort_keys=True)}",
        "- Provenance: manually curated threat-model tasks, with explicitly marked transformed variants; no public dataset or real-world attack claim.",
        "- Development/calibration samples reused as final: NO.",
        "- Duplicate policy: casefolded whitespace-normalized text and unique sample IDs; transformation siblings share group_id.",
        "",
        "## Frozen System",
        "",
        f"- Base commit: {freeze['git_commit']}",
        f"- Security weights: {json.dumps(freeze['security_weights'], sort_keys=True)}",
        f"- Block threshold: {freeze['policy_block_threshold']}",
        f"- Semantic model/revision/threshold: {freeze['semantic_model']['name']} / {freeze['semantic_model']['revision']} / {freeze['semantic_model']['threshold']}",
        f"- Historical semantic attack corpus SHA-256: {freeze['attack_corpus']['sha256']}",
        "- Final-test runner is read-only with respect to thresholds, detectors, rules, semantic corpus, and policies.",
        "",
        "## Method",
        "",
        "The controlled evaluator preserves the researcher -> planner -> writer -> finalizer topology and uses only inert evaluation resources. FULL_AGENTSHIELD reuses the repository normalizer, rule detector, context analyzer, calibrated scorer, and policy mapping. Ablations disable only the named defense flag; business/task stages and sandbox constraints remain. BASELINE_NO_AGENTSHIELD disables all AgentShield interventions while retaining the same four stages and records attack behavior as successful when a malicious row reaches the end.",
        "",
        "Decision mapping: BLOCK, REVIEW, and SANITIZE are mitigation/positive; ALLOW is non-mitigation. TP = malicious mitigated, TN = benign allowed, FP = benign mitigated, FN = malicious allowed. Attack Success Rate (ASR) = successful malicious rows / malicious rows; Mitigation Rate = 1 - ASR.",
        "",
        "The pinned embedding runtime was unavailable in this environment, so semantic findings are recorded as unavailable and no lexical substitute is used. No classifier ablation is claimed because its frozen weight is 0.00 and no runtime provider was verified.",
        "",
        "## Baseline vs Full",
        "",
        "| Configuration | Recall | F1 | FPR | ASR | Mitigation Rate |",
        "|---|---:|---:|---:|---:|---:|",
        f"| BASELINE_NO_AGENTSHIELD | {_metric(baseline_metrics, 'recall')} | {_metric(baseline_metrics, 'f1')} | {_metric(baseline_metrics, 'fpr')} | {_metric(baseline_metrics, 'attack_success_rate')} | {_metric(baseline_metrics, 'mitigation_rate')} |",
        f"| FULL_AGENTSHIELD | {_metric(full_metrics, 'recall')} | {_metric(full_metrics, 'f1')} | {_metric(full_metrics, 'fpr')} | {_metric(full_metrics, 'attack_success_rate')} | {_metric(full_metrics, 'mitigation_rate')} |",
        "",
        "## Ablation",
        "",
        "Delta ASR is ablation ASR minus FULL_AGENTSHIELD ASR; positive values mean more attacks succeeded after removing a layer.",
        "",
        "| Configuration | Recall | F1 | FPR | ASR | Delta ASR |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for config_file in CONFIG_NAMES:
        name = load_config(config_file).name
        if name == "BASELINE_NO_AGENTSHIELD":
            continue
        metrics = results[name]["metrics"]["overall"]
        delta = float(metrics["attack_success_rate"]) - float(full_metrics["attack_success_rate"])
        lines.append(f"| {name} | {_metric(metrics, 'recall')} | {_metric(metrics, 'f1')} | {_metric(metrics, 'fpr')} | {_metric(metrics, 'attack_success_rate')} | {_pct(delta)} |")

    lines += ["", "## Grouped 95% Bootstrap Intervals (FULL)", "", "| Metric | Estimate | 95% CI | Effective groups |", "|---|---:|---:|---:|"]
    for metric, interval in full["grouped_bootstrap_95_ci"].items():
        lines.append(f"| {metric} | {_pct(interval['estimate'])} | {_pct(interval['lower'])} - {_pct(interval['upper'])} | {interval['effective_group_count']} |")

    lines += ["", "## Category Results (FULL)", "", "| Category | Samples | Groups | Recall | FPR | ASR |", "|---|---:|---:|---:|---:|---:|"]
    for category, metrics in full["metrics"]["categories"].items():
        lines.append(f"| {category} | {metrics['sample_count']} | {metrics['effective_group_count']} | {_metric(metrics, 'recall')} | {_metric(metrics, 'fpr')} | {_metric(metrics, 'attack_success_rate')} |")

    lines += [
        "",
        "## Provider and Limitations",
        "",
        "- Real provider available: NO (OpenAI, Gemini, Groq, and Ollama were not runtime verified/configured).",
        "- Demo fallback used as final LLM evidence: NO.",
        "- Real-provider final multi-agent evaluation: PENDING.",
        "- This deterministic matrix is suitable for validating dataset integrity, ablation wiring, and detector-only security behavior; it must not be labeled a real-LLM baseline.",
        "- Raw rows are in raw_results/*.jsonl; processed metrics are in processed_results/*.json; every metric is recomputed from raw rows.",
        "",
        "## Reproduction",
        "",
        "    python -m experiments.final_evaluation.validate_dataset --write-manifest",
        "    python -m experiments.final_evaluation.freeze_system",
        "    python -m experiments.final_evaluation.run_evaluation --all",
        "    python -m experiments.final_evaluation.compute_metrics --all",
        "    python -m experiments.final_evaluation.generate_report",
        "",
    ]
    report = "\n".join(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=REPORT_PATH)
    args = parser.parse_args()
    print(generate_report(args.output))


if __name__ == "__main__":
    main()
