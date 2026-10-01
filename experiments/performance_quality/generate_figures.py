"""Generate non-empty figures from processed Phase 16 summaries only."""

from __future__ import annotations

import argparse
import json

from .config import FIGURES_DIR, PROCESSED_DIR
from .runtime import sha256_file


def _mpl():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def generate() -> dict:
    performance_path = PROCESSED_DIR / "performance_summary.json"
    quality_path = PROCESSED_DIR / "quality_summary.json"
    if not performance_path.exists():
        raise RuntimeError("Compute performance summary before generating figures")
    performance = json.loads(performance_path.read_text(encoding="utf-8"))
    quality = json.loads(quality_path.read_text(encoding="utf-8")) if quality_path.exists() else None
    plt = _mpl()
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []

    labels = ["Baseline", "Protected"]
    total = [performance["baseline"]["total"], performance["protected"]["total"]]
    fig, axis = plt.subplots(figsize=(7, 4))
    for index, stats in enumerate(total):
        values = [stats.get("p50"), stats.get("p95"), stats.get("p99")]
        axis.plot(["P50", "P95", "P99"], values, marker="o", label=labels[index])
    axis.set_ylabel("Latency (ms)")
    axis.set_title("Baseline vs protected total latency")
    axis.legend()
    fig.tight_layout()
    path = FIGURES_DIR / "latency_comparison.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    generated.append(str(path))

    stage_names = [name for name, stats in performance["protected"]["stages"].items() if stats.get("count", 0) > 0]
    if stage_names:
        fig, axis = plt.subplots(figsize=(9, 4.5))
        axis.bar([name.removesuffix("_ms") for name in stage_names], [performance["protected"]["stages"][name]["p50"] for name in stage_names])
        axis.set_ylabel("P50 latency (ms)")
        axis.set_title("Measured protected-stage latency")
        axis.tick_params(axis="x", rotation=35)
        fig.tight_layout()
        path = FIGURES_DIR / "stage_latency_distribution.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        generated.append(str(path))

    overhead = performance["overhead"]
    if overhead.get("count", 0) > 0:
        fig, axis = plt.subplots(figsize=(6, 4))
        axis.bar(["Absolute overhead"], [overhead.get("absolute_overhead_ms")])
        axis.set_ylabel("Milliseconds")
        axis.set_title("Protected minus baseline overhead")
        fig.tight_layout()
        path = FIGURES_DIR / "security_overhead.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        generated.append(str(path))

    if quality and quality.get("status") == "COMPLETE" and quality.get("scored_records", 0) > 0:
        configs = sorted(quality.get("configurations", {}))
        dimensions = list(next(iter(quality["configurations"].values()))["dimensions"])
        fig, axis = plt.subplots(figsize=(9, 4.5))
        for config in configs:
            axis.plot(dimensions, [quality["configurations"][config]["dimensions"][d]["mean"] for d in dimensions], marker="o", label=config)
        axis.set_ylim(1, 5)
        axis.set_ylabel("Mean rubric score (1–5)")
        axis.set_title("Blinded benign-response quality")
        axis.legend()
        axis.tick_params(axis="x", rotation=35)
        fig.tight_layout()
        path = FIGURES_DIR / "quality_comparison.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        generated.append(str(path))

    manifest = {
        "schema_version": "phase16-figures-v1",
        "source_processed": {
            "performance": {"path": str(performance_path), "sha256": sha256_file(performance_path)},
            "quality": {"path": str(quality_path), "sha256": sha256_file(quality_path)} if quality_path.exists() else None,
        },
        "generated_figures": generated,
        "quality_figure_omitted": not (quality and quality.get("status") == "COMPLETE" and quality.get("scored_records", 0) > 0),
    }
    (FIGURES_DIR / "figures_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(json.dumps(generate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
