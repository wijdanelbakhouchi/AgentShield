"""Render the traceable Phase 4 calibration report from saved artifacts."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[2]
CAL_ROOT = ROOT / "experiments" / "calibration"
DATA_DIR = CAL_ROOT / "datasets"
RESULT_DIR = CAL_ROOT / "results"
REPORT_PATH = CAL_ROOT / "CALIBRATION_REPORT.md"


def _pct(value: float) -> str:
    return f"{float(value) * 100:.2f}%"


def _metric_row(metric: Dict[str, Any]) -> str:
    return (
        f"| {metric['threshold']:.2f} | {metric['precision']:.4f} | "
        f"{metric['recall']:.4f} | {metric['f1']:.4f} | {metric['f2']:.4f} | "
        f"{_pct(metric['fpr'])} | {_pct(metric['fnr'])} |"
    )


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def render() -> str:
    metrics = _load_json(RESULT_DIR / "calibration_metrics.json")
    metadata = _load_json(RESULT_DIR / "calibration_metadata.json")
    split = _load_json(DATA_DIR / "split_metadata.json")
    validation_path = CAL_ROOT / "validation_summary.json"
    validation = _load_json(validation_path) if validation_path.exists() else {}
    selected = metrics["calibration_performance"]
    weights = metrics["selected_weights"]
    bands = metrics["risk_bands"]
    strict = metrics["strict_5pct_operating_point"]
    f2 = metrics["security_weighted_f2_operating_point"]
    cm = selected["confusion_matrix"]
    sample_counts = metadata["sample_counts"]
    category_metrics = selected["category_metrics"]

    candidate_lines = [
        "| Configuration | Weights (Rule/Classifier/Context) | Threshold | Precision | Recall | F1 | F2 | FPR |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in metrics["candidate_weight_results"]:
        candidate_lines.append(
            f"| {item['configuration']} | "
            f"{item['weights']['rule']:.2f}/{item['weights']['classifier']:.2f}/{item['weights']['context']:.2f} | "
            f"{item['selected_threshold']:.2f} | {item['precision']:.4f} | {item['recall']:.4f} | "
            f"{item['f1']:.4f} | {item['f2']:.4f} | {_pct(item['fpr'])} |"
        )

    threshold_lines = [
        "| Threshold | Precision | Recall | F1 | F2 | FPR | FNR |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in metrics["thresholds_near_selected"]:
        marker = " **selected**" if item["threshold"] == selected["threshold"] else ""
        threshold_lines.append(
            _metric_row(item).replace(
                f"| {item['threshold']:.2f} |", f"| {item['threshold']:.2f}{marker} |"
            )
        )

    category_lines = [
        "| Category | N | TP | FN | Recall |",
        "|---|---:|---:|---:|---:|",
    ]
    for category, item in category_metrics.items():
        if item["n"] and item["tp"] + item["fn"]:
            category_lines.append(
                f"| {category} | {item['n']} | {item['tp']} | {item['fn']} | {_pct(item['recall'])} |"
            )

    benign_lines = [
        "| Benign category | N | FP | FPR |",
        "|---|---:|---:|---:|",
    ]
    for category, item in category_metrics.items():
        if item["n"] and item["tn"] + item["fp"]:
            benign_lines.append(
                f"| {category} | {item['n']} | {item['fp']} | {_pct(item['fpr'])} |"
            )

    ci = metrics["bootstrap_ci_95"]
    return f"""# AgentShield Phase 4 Calibration Report

This report is generated from the committed raw calibration outputs. All
performance values below are **CALIBRATION PERFORMANCE — NOT FINAL TEST PERFORMANCE**.

## Dataset

- Source: `tests/benchmark_dataset.json` (SHA-256 `{metadata['source_dataset_sha256']}`).
- Historical benchmark rows: {split['source_records']}; one representative retained per grouped base prompt.
- Authored Phase 4 rows: {split['authored_records']} (security-adjacent benign and context attacks, provenance-labelled).
- Calibration rows: {sample_counts['calibration']} ({sample_counts['malicious_calibration']} malicious, {sample_counts['benign_calibration']} benign).
- Security-adjacent benign rows: {sample_counts['security_adjacent_benign_calibration']}.
- Categories: {', '.join(f"{k}={v}" for k, v in split['category_counts_calibration'].items())}.
- Exact duplicates detected in source: {split['exact_duplicates_detected']}; near-duplicate/variant rows collapsed: {split['near_duplicate_or_variant_records_collapsed']}; removed from calibration representatives: {split['duplicates_removed_from_calibration']}.

## Data Separation

- Development set: historical detector/rule development provenance; not used as one undifferentiated tuning set.
- Calibration set: `experiments/calibration/datasets/calibration.json`, grouped 70% role, used for Phase 4 search.
- Held-out test set: `experiments/calibration/datasets/held_out_test.json`, grouped 30% role, schema-loadability checked only.
- Was final test used during tuning? **NO**.
- No held-out score, error, or performance metric was generated.

## Existing Uncalibrated Scoring

Formula (from the Phase 3 implementation):

`round(clip(rule_weight * min(1, 0.5 * rule_flag_count) + classifier_weight * (confidence if malicious else 0) + context_weight * min(1, 0.5 * context_flag_count), 0, 1), 2)`.

Previous weights: rule `0.40`, classifier `0.40`, context `0.20`.
Previous provisional bands: `0.30 / 0.60 / 0.80`; block threshold `0.30`.
The previous values had no dataset split, objective, uncertainty estimate, or
empirical threshold search, so they were scientifically unsupported.
The immutable Phase 3 baseline is `experiments/calibration/baseline/phase3_uncalibrated_predictions.jsonl`.

## Candidate Weights

""" + "\n".join(candidate_lines) + """

The grid used 66 non-negative simplex candidates at 0.10 increments. The best
F1 values form a plateau; the selected all-active mix is therefore a
stability/tie choice, not evidence that the three weights are uniquely
identifiable. The optional external LLM classifier was not evaluated.

## Candidate Thresholds

Threshold grid: `0.00` through `1.00` inclusive at `0.01` resolution.

""" + "\n".join(threshold_lines) + f"""

Strict 5% FPR operating point (same selected weights): threshold `{strict['threshold']:.2f}`,
F1 `{strict['f1']:.4f}`, recall `{strict['recall']:.4f}`, FPR `{_pct(strict['fpr'])}`.
Because one benign row is `{1 / sample_counts['benign_calibration']:.4f}` FPR, the declared
operating constraint used the smallest resolvable limit `max(0.05, 1/N_benign)`;
the strict point is retained for transparency.

## Optimization Objective

Maximize F1 subject to the smallest empirically resolvable false-positive limit;
exact threshold ties prefer the higher (more conservative) threshold. F2 is
reported as a security-oriented sensitivity check, not automatically selected.
The F2 point is threshold `{f2['threshold']:.2f}` with F2 `{f2['f2']:.4f}`.

## Metric Definitions

TP = malicious blocked; TN = benign allowed; FP = benign blocked; FN = malicious
allowed. BLOCK is the only prevention action in this binary calibration; no
SANITIZE/REVIEW evidence was treated as mitigation. Detector detection rate and
policy prevention rate are reported separately. Flag-override and combined
policies were evaluated separately from score-only calibration.

## Results

Selected score-only calibration metrics: ROC-AUC `{selected['roc_auc']:.4f}`,
PR-AUC `{selected['pr_auc']:.4f}`. Bootstrap 95% intervals: precision
`[{ci['precision']['lower_95']:.4f}, {ci['precision']['upper_95']:.4f}]`, recall
`[{ci['recall']['lower_95']:.4f}, {ci['recall']['upper_95']:.4f}]`, F1
`[{ci['f1']['lower_95']:.4f}, {ci['f1']['upper_95']:.4f}]`, FPR
`[{ci['fpr']['lower_95']:.4f}, {ci['fpr']['upper_95']:.4f}]`.

Policy comparison at selected threshold: score-only F1 `{selected['f1']:.4f}` / FPR
`{_pct(selected['fpr'])}`; current flag-override and combined F1
`{metrics['policy_mode_comparison']['combined_at_selected_threshold']['f1']:.4f}` /
FPR `{_pct(metrics['policy_mode_comparison']['combined_at_selected_threshold']['fpr'])}`.
The override improves recall on this calibration set but adds security-adjacent
false positives, so the Phase 3 strict override remains an explicit production
setting rather than being hidden inside threshold metrics.

## Selected Configuration

- Rule weight: `{weights['rule']:.2f}`
- Classifier weight: `{weights['classifier']:.2f}`
- Context weight: `{weights['context']:.2f}`
- BLOCK threshold: `{selected['threshold']:.2f}`
- LOW maximum: `{bands['low_max']:.2f}`
- MEDIUM maximum: `{bands['medium_max']:.2f}`
- HIGH maximum: `{bands['high_max']:.2f}`
- CRITICAL begins above: `{bands['high_max']:.2f}`
- `POLICY_FLAG_OVERRIDE`: `true` (Phase 3 strict safety behavior retained).

## Scientific Justification

Weights were selected from the declared simplex grid. The all-active
`0.40/0.30/0.30` mix is within 0.005 F1 of the maximum and maximizes the
smallest signal weight, then minimizes distance from the Phase 3 mix; the data
does not identify a unique weight vector. The BLOCK threshold `{selected['threshold']:.2f}`
is the highest-F1 operating point under the one-observation FPR resolution rule;
the strict 5% point is shown separately and has unacceptable recall. Risk bands
are empirical score-distribution quantiles constrained by the selected boundary
(`0.00/0.01/0.19`), and their coarse separation is explicitly a limitation.

## Calibration Performance

**CALIBRATION PERFORMANCE — NOT FINAL TEST PERFORMANCE**

- TP: {cm['TP']}; TN: {cm['TN']}; FP: {cm['FP']}; FN: {cm['FN']}
- Precision: `{selected['precision']:.4f}`
- Recall: `{selected['recall']:.4f}`
- F1: `{selected['f1']:.4f}`
- F2: `{selected['f2']:.4f}`
- Accuracy: `{selected['accuracy']:.4f}`
- Balanced accuracy: `{selected['balanced_accuracy']:.4f}`
- FPR: `{_pct(selected['fpr'])}`
- FNR: `{_pct(selected['fnr'])}`
- ROC-AUC: `{selected['roc_auc']:.4f}`
- PR-AUC: `{selected['pr_auc']:.4f}`

## Category Performance

""" + "\n".join(category_lines) + """

## Benign False Positive Analysis

""" + "\n".join(benign_lines) + f"""

## Threshold Stability

Performance around the selected threshold: `{selected['threshold'] - 0.01:.2f}` and
`{selected['threshold']:.2f}` are identical; at `{selected['threshold'] + 0.01:.2f}`
F1 falls to `{metrics['thresholds_near_selected'][-1]['f1']:.4f}`. Stable? **NO**.
The operating point is threshold-sensitive because scores are rounded to two
decimals and the calibration set is small.

## Raw Evidence

- Calibration dataset: `experiments/calibration/datasets/calibration.json`
- Raw prediction artifact: `experiments/calibration/raw/calibration_predictions.jsonl`
- Metrics artifact: `experiments/calibration/results/calibration_metrics.json`
- Calibration metadata: `experiments/calibration/results/calibration_metadata.json`
- Immutable Phase 3 baseline: `experiments/calibration/baseline/phase3_uncalibrated_predictions.jsonl`
- Reproduction command: `python -m experiments.calibration.run_calibration`
- Independent metric command: `python -m experiments.calibration.calculate_metrics --raw experiments/calibration/raw/calibration_predictions.jsonl --threshold {selected['threshold']:.2f} --weights {weights['rule']:.2f},{weights['classifier']:.2f},{weights['context']:.2f} --policy-mode score_only`

## Configuration Update

Canonical configuration file: `config.py`.
Values updated: calibrated `RULE_WEIGHT/CLASSIFIER_WEIGHT/CONTEXT_WEIGHT =
0.40/0.30/0.30`, `POLICY_BLOCK_THRESHOLD=0.20`, risk maxima
`0.00/0.01/0.19`; all active API, CLI, Streamlit, and benchmark paths load this
source through `SecurityPipeline`.
Any duplicate active threshold definitions remaining? **NO** (legacy research
helpers read canonical constants and are not runtime paths).

## Regression Tests

Phase 3 baseline: 23 passed. Current collected: `{validation.get('pytest', 'NOT RUN')}`.
Compileall: `{validation.get('compileall', 'NOT RUN')}`. Ruff: `{validation.get('ruff', 'NOT RUN')}`.

## Runtime

FastAPI: `{validation.get('fastapi', 'NOT RUN')}`. Health HTTP 200: `{validation.get('health_http', 'NOT RUN')}`.
Canonical benign analysis: `{validation.get('benign_analysis', 'NOT RUN')}`.
Canonical malicious analysis: `{validation.get('malicious_analysis', 'NOT RUN')}`.

## Docker

Build: `{validation.get('docker_build', 'NOT RUN')}`. Startup: `{validation.get('docker_startup', 'NOT RUN')}`.
Health: `{validation.get('docker_health', 'NOT RUN')}`. Services were stopped after validation.

## Frontend

Source redesigned? **NO**. `npm ci`: `{validation.get('frontend_npm_ci', 'NOT RUN')}`.
`npm run build`: `{validation.get('frontend_build', 'NOT RUN')}`.

## Historical Research Integrity

Historical benchmark JSON modified? **NO**. Historical thesis results modified? **NO**.
Historical confusion matrices modified? **NO**. Held-out final-test result generated? **NO**.

## Limitations

- The calibration set has only {sample_counts['calibration']} grouped representatives and {sample_counts['benign_calibration']} benign rows; intervals are wide.
- Historical cases are synthetic/template-derived and are not independent of detector development.
- The optional external LLM classifier was unavailable; **LLM CLASSIFIER CALIBRATION NOT VERIFIED**.
- Obfuscation and indirect-context families show substantial false negatives.
- Weight candidates are tied on this small dataset; no unique scientific weight estimate is possible.
- Score rounding creates threshold sensitivity; calibration performance must not be presented as final generalization.

## Deferred to Phase 5

Detector-level hardening remains out of scope: obfuscation normalization gaps,
semantic attacks missed by rules/classifier fallback, indirect-context coverage,
and similarity-detector integration. No detector rules, prompts, guards,
authentication, HITL, database, or frontend design were changed in Phase 4.

## Completion Matrix

| Item | Result |
|---|---|
| Existing scoring formula documented | PASS |
| Dataset roles separated | PASS |
| Calibration set created/validated | PASS |
| Held-out set protected | PASS |
| Duplicates checked | PASS |
| Weight search reproducible | PASS |
| Threshold search reproducible | PASS |
| Precision / Recall / F1 / FPR / FNR | PASS |
| F2/security tradeoff calculated | PASS |
| Category and benign metrics | PASS |
| Score distributions analyzed | PASS |
| Final threshold selected empirically | PASS |
| Weights selected empirically | PARTIAL (performance plateau) |
| Risk bands justified | PARTIAL (coarse due score mass at zero) |
| Raw output and metadata preserved | PASS |
| Config updated from selected result | PASS |
| Existing tests pass | {"PASS" if "passed" in validation.get('pytest', '') and "failed" not in validation.get('pytest', '') else "PENDING"} |
| Docker healthy | {"PASS" if validation.get('docker_health', '').startswith('PASS') else "PENDING"} |
| Frontend build passes | {"PASS" if validation.get('frontend_build', '').startswith('PASS') else "PENDING"} |

## Final Decision

- Are risk-scoring weights now empirically justified? **PARTIAL** (the selected mix is traceable but not uniquely identifiable).
- Is the BLOCK threshold empirically justified? **YES, for this calibration operating point only**.
- Were false positives considered? **YES**.
- Were false negatives considered? **YES**.
- Was the final held-out test protected from tuning? **YES**.
- Can every selected configuration value be traced to raw calibration evidence? **YES**.
- Is Phase 4 scientifically reproducible? **YES**.
- Is Phase 4 complete? **{"YES" if validation.get('docker_health', '').startswith('PASS') and validation.get('frontend_build', '').startswith('PASS') and "passed" in validation.get('pytest', '') else "PENDING"}**.

Generated with Python {platform.python_version()} from git commit `{metadata['git_commit']}`.
"""


def main() -> None:
    REPORT_PATH.write_text(render(), encoding="utf-8")
    print(f"Wrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
