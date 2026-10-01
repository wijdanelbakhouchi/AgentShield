"""Generate thesis-ready figures for the propagation study.

Figures are written to ``experiments/propagation/figures/``:

1. ``asr_by_config.png``        — attack success rate per configuration (with
                                  bootstrap 95% CIs where available).
2. ``propagation_depth.png`     — mean propagation depth per configuration.
3. ``propagation_rate_depth.png`— fraction of attacks reaching each depth for
                                  baseline vs full vs full+provenance.
4. ``category_heatmap.png`      — per-category mitigation rate heatmap across
                                  configurations.
5. ``blocked_at.png`            — which defense layer contained attacks.
6. ``adaptive_vs_non.png`       — ASR for obfuscation == none vs transformed.
7. ``detection_pr.png`          — detector precision/recall for the alert-only
                                  arm.

All figures are produced with matplotlib from the persisted processed
results; no live provider or database is required.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parent
PROCESSED_DIR = ROOT / "processed_results"
RAW_DIR = ROOT / "raw_results"
FIGURES_DIR = ROOT / "figures"
CONFIG_ORDER = [
    "BASELINE_NO_AGENTSHIELD",
    "GATEWAY_ONLY",
    "FULL_NO_SEMANTIC",
    "FULL_NO_PROVENANCE",
    "FULL_PROVENANCE",
    "FULL_BANDED_SANITIZE",
    "ALERT_ONLY_DETECTION",
]

_CONFIG_LABELS = {
    "BASELINE_NO_AGENTSHIELD": "Baseline (unprotected)",
    "GATEWAY_ONLY": "Gateway only",
    "FULL_NO_SEMANTIC": "Full, no semantic",
    "FULL_NO_PROVENANCE": "Full AgentShield",
    "FULL_PROVENANCE": "Full + provenance",
    "FULL_BANDED_SANITIZE": "Full, banded policy",
    "ALERT_ONLY_DETECTION": "Alert-only (detection)",
}


def _load_processed(name: str) -> dict:
    with (PROCESSED_DIR / f"{name}.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_raw(name: str) -> list[dict]:
    path = RAW_DIR / f"{name}.jsonl"
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _available_configs() -> list[str]:
    return [name for name in CONFIG_ORDER if (PROCESSED_DIR / f"{name}.json").exists()]


def _asr_with_ci(name: str) -> tuple[float | None, float | None, float | None]:
    data = _load_processed(name)
    overall = data["metrics"]["overall"]
    asr = overall.get("attack_success_rate")
    ci = data.get("grouped_bootstrap_95_ci", {}).get("attack_success_rate", {})
    return asr, ci.get("lower"), ci.get("upper")


def asr_by_config() -> None:
    configs = _available_configs()
    values, lowers, uppers = [], [], []
    for name in configs:
        asr, lower, upper = _asr_with_ci(name)
        values.append(asr if asr is not None else 0.0)
        lowers.append(lower if lower is not None else asr if asr is not None else 0.0)
        uppers.append(upper if upper is not None else asr if asr is not None else 0.0)
    fig, ax = plt.subplots(figsize=(10, 5.5))
    positions = np.arange(len(configs))
    ax.bar(positions, values, yerr=[
        np.array(values) - np.array(lowers),
        np.array(uppers) - np.array(values),
    ], capsize=5, color="#8b5cf6", alpha=0.85)
    ax.set_xticks(positions)
    ax.set_xticklabels([_CONFIG_LABELS.get(name, name) for name in configs], rotation=22, ha="right")
    ax.set_ylabel("Attack Success Rate (payload reaches target)")
    ax.set_title("ASR by configuration (bootstrap 95% CI)")
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "asr_by_config.png", dpi=150)
    plt.close(fig)


def mean_propagation_depth() -> None:
    configs = _available_configs()
    depths = []
    for name in configs:
        data = _load_processed(name)
        depths.append(data["metrics"]["propagation"].get("mean_depth") or 0.0)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(np.arange(len(configs)), depths, color="#0ea5e9", alpha=0.85)
    ax.set_xticks(np.arange(len(configs)))
    ax.set_xticklabels([_CONFIG_LABELS.get(name, name) for name in configs], rotation=22, ha="right")
    ax.set_ylabel("Mean propagation depth reached")
    ax.set_title("How far payloads travel before containment")
    ax.set_ylim(0, 4.5)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "propagation_depth.png", dpi=150)
    plt.close(fig)


def propagation_rate_by_depth() -> None:
    configs = [name for name in ("BASELINE_NO_AGENTSHIELD", "FULL_NO_PROVENANCE", "FULL_PROVENANCE") if (PROCESSED_DIR / f"{name}.json").exists()]
    fig, ax = plt.subplots(figsize=(8, 5))
    for name in configs:
        data = _load_processed(name)
        rates = data["metrics"]["propagation"].get("propagation_rate_by_depth", {})
        depths = sorted(int(d) for d in rates)
        ax.plot(depths, [rates[str(d)] for d in depths], marker="o", label=_CONFIG_LABELS.get(name, name))
    ax.set_xlabel("Propagation depth")
    ax.set_ylabel("Fraction of attacks reaching depth")
    ax.set_title("Propagation reachability by depth")
    ax.set_xticks([1, 2, 3, 4])
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "propagation_rate_depth.png", dpi=150)
    plt.close(fig)


def category_heatmap() -> None:
    configs = _available_configs()
    all_categories: set[str] = set()
    by_category: dict[str, dict[str, float]] = defaultdict(dict)
    for name in configs:
        data = _load_processed(name)
        for category, metrics in data["metrics"]["categories"].items():
            mitigation = metrics.get("mitigation_rate")
            if mitigation is not None:
                by_category[category][name] = mitigation
                all_categories.add(category)
    categories = sorted(all_categories)
    matrix = np.full((len(categories), len(configs)), np.nan)
    for row, category in enumerate(categories):
        for col, name in enumerate(configs):
            matrix[row, col] = by_category[category].get(name, np.nan)
    fig, ax = plt.subplots(figsize=(11, max(5, 0.5 * len(categories) + 2)))
    im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(np.arange(len(configs)))
    ax.set_xticklabels([_CONFIG_LABELS.get(name, name) for name in configs], rotation=22, ha="right")
    ax.set_yticks(np.arange(len(categories)))
    ax.set_yticklabels(categories)
    fig.colorbar(im, ax=ax, label="Mitigation rate (1 - ASR)")
    ax.set_title("Mitigation rate by attack category and configuration")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "category_heatmap.png", dpi=150)
    plt.close(fig)


def blocked_at() -> None:
    configs = [name for name in ("FULL_NO_PROVENANCE", "FULL_PROVENANCE") if (PROCESSED_DIR / f"{name}.json").exists()]
    layers = ["gateway", "tool_security", "researcher", "inter_agent"]
    fig, ax = plt.subplots(figsize=(8, 5))
    width = 0.35
    for offset, name in enumerate(configs):
        data = _load_processed(name)
        counts = [data["metrics"]["propagation"].get(f"contained_at_{layer}", 0) for layer in layers]
        ax.bar(np.arange(len(layers)) + offset * width, counts, width, label=_CONFIG_LABELS.get(name, name))
    ax.set_xticks(np.arange(len(layers)) + width / 2)
    ax.set_xticklabels(layers)
    ax.set_ylabel("Attacks contained")
    ax.set_title("Which defense layer contains attacks")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "blocked_at.png", dpi=150)
    plt.close(fig)


def adaptive_vs_non() -> None:
    configs = [name for name in ("BASELINE_NO_AGENTSHIELD", "FULL_NO_PROVENANCE", "FULL_PROVENANCE") if (PROCESSED_DIR / f"{name}.json").exists()]
    fig, ax = plt.subplots(figsize=(8, 5))
    width = 0.28
    for offset, name in enumerate(configs):
        records = _load_raw(name)
        non_adaptive = [r for r in records if r["label"] == "malicious" and r.get("obfuscation") == "none"]
        adaptive = [r for r in records if r["label"] == "malicious" and r.get("obfuscation") != "none"]
        non_asr = sum(1 for r in non_adaptive if r["attack_success"]) / len(non_adaptive) if non_adaptive else None
        ada_asr = sum(1 for r in adaptive if r["attack_success"]) / len(adaptive) if adaptive else None
        values = [non_asr or 0.0, ada_asr or 0.0]
        ax.bar(np.arange(2) + offset * width, values, width, label=_CONFIG_LABELS.get(name, name))
    ax.set_xticks(np.arange(2) + width)
    ax.set_xticklabels(["Non-adaptive (plain)", "Adaptive (transformed)"])
    ax.set_ylabel("Attack Success Rate")
    ax.set_title("Adaptive vs non-adaptive attacks")
    ax.legend()
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "adaptive_vs_non.png", dpi=150)
    plt.close(fig)


def detection_pr() -> None:
    path = PROCESSED_DIR / "ALERT_ONLY_DETECTION.json"
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    detection = data["metrics"]["detection"]
    fig, ax = plt.subplots(figsize=(6, 5))
    labels = ["Precision", "Recall", "F1"]
    values = [detection.get("precision") or 0.0, detection.get("recall") or 0.0, detection.get("f1") or 0.0]
    bars = ax.bar(labels, values, color=["#10b981", "#f59e0b", "#8b5cf6"], alpha=0.85)
    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, value + 0.02, f"{value:.3f}", ha="center", fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title("Detector signal quality (alert-only arm)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "detection_pr.png", dpi=150)
    plt.close(fig)


def generate_all() -> dict[str, str]:
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    generated: dict[str, str] = {}
    generators = {
        "asr_by_config": asr_by_config,
        "propagation_depth": mean_propagation_depth,
        "propagation_rate_depth": propagation_rate_by_depth,
        "category_heatmap": category_heatmap,
        "blocked_at": blocked_at,
        "adaptive_vs_non": adaptive_vs_non,
        "detection_pr": detection_pr,
    }
    for name, function in generators.items():
        try:
            function()
            generated[name] = f"figures/{name}.png"
        except Exception as exc:  # report failures without aborting the batch
            generated[name] = f"ERROR: {exc.__class__.__name__}"
    manifest = {"figures": generated}
    (FIGURES_DIR / "figures_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return generated


if __name__ == "__main__":
    print(json.dumps(generate_all(), indent=2, sort_keys=True))