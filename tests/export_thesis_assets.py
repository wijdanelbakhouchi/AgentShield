"""
tests/export_thesis_assets.py
==============================
AgentShield Phase 5 — Automated Thesis Asset Exporter

Generates thesis-ready figures and LaTeX summary table (.tex) from benchmark evaluation results.
Provides robust SVG vector graphic fallback if matplotlib/seaborn are not installed.
"""

import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def export_svg_confusion_matrix(cm: dict, out_path: str):
    """Generates clean SVG confusion matrix graphic."""
    tp, fp, tn, fn = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" width="500" height="400" viewBox="0 0 500 400">
  <rect width="100%" height="100%" fill="#0F172A" />
  <text x="250" y="40" font-family="sans-serif" font-size="18" font-weight="bold" fill="#F8FAFC" text-anchor="middle">AgentShield Confusion Matrix (N=300)</text>
  
  <!-- Axis Labels -->
  <text x="250" y="380" font-family="sans-serif" font-size="14" font-weight="bold" fill="#94A3B8" text-anchor="middle">Predicted Action</text>
  <text x="20" y="200" font-family="sans-serif" font-size="14" font-weight="bold" fill="#94A3B8" text-anchor="middle" transform="rotate(-90 20 200)">Ground Truth Class</text>

  <!-- Headers -->
  <text x="200" y="80" font-family="sans-serif" font-size="13" fill="#CBD5E1" text-anchor="middle">Allowed (Safe)</text>
  <text x="350" y="80" font-family="sans-serif" font-size="13" fill="#CBD5E1" text-anchor="middle">Blocked (Attack)</text>
  
  <text x="110" y="150" font-family="sans-serif" font-size="13" fill="#CBD5E1" text-anchor="end">Actual Benign</text>
  <text x="110" y="270" font-family="sans-serif" font-size="13" fill="#CBD5E1" text-anchor="end">Actual Attack</text>

  <!-- Cell TN -->
  <rect x="130" y="100" width="140" height="100" fill="#1E293B" rx="8" stroke="#334155"/>
  <text x="200" y="150" font-family="sans-serif" font-size="22" font-weight="bold" fill="#10B981" text-anchor="middle">TN: {tn}</text>

  <!-- Cell FP -->
  <rect x="280" y="100" width="140" height="100" fill="#1E293B" rx="8" stroke="#334155"/>
  <text x="350" y="150" font-family="sans-serif" font-size="22" font-weight="bold" fill="#EF4444" text-anchor="middle">FP: {fp}</text>

  <!-- Cell FN -->
  <rect x="130" y="210" width="140" height="100" fill="#1E293B" rx="8" stroke="#334155"/>
  <text x="200" y="260" font-family="sans-serif" font-size="22" font-weight="bold" fill="#F59E0B" text-anchor="middle">FN: {fn}</text>

  <!-- Cell TP -->
  <rect x="280" y="210" width="140" height="100" fill="#1E293B" rx="8" stroke="#334155"/>
  <text x="350" y="260" font-family="sans-serif" font-size="22" font-weight="bold" fill="#3B82F6" text-anchor="middle">TP: {tp}</text>
</svg>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(svg_content)


def export_assets(results_path: str = None):
    if not results_path:
        results_path = os.path.join(ROOT_DIR, "tests", "thesis_benchmark_results.json")

    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    summary = data["summary"]
    _records = data.get("evaluation_records", [])
    out_dir = os.path.join(ROOT_DIR, "tests")

    # 1. LaTeX Summary Table (thesis_summary_table.tex)
    tex_path = os.path.join(out_dir, "thesis_summary_table.tex")
    tex_content = f"""\\begin{{table}}[htbp]
\\centering
\\caption{{\\textbf{{AgentShield Thesis Empirical Evaluation Summary (N=300)}}}}
\\label{{tab:agentshield_metrics}}
\\begin{{tabular}}{{llcc}}
\\hline
\\textbf{{Metric Category}} & \\textbf{{Evaluation Metric}} & \\textbf{{Target}} & \\textbf{{AgentShield Result}} \\\\ \\hline
\\multirow{{4}}{{*}}{{Classification Performance}} 
 & Precision & $>$ 95.0\\% & \\textbf{{{summary['precision']*100:.2f}\\%}} \\\\
 & Recall & $>$ 90.0\\% & \\textbf{{{summary['recall']*100:.2f}\\%}} \\\\
 & F1-Score & $>$ 90.0\\% & \\textbf{{{summary['f1_score']*100:.2f}\\%}} \\\\
 & False Positive Rate (FPR) & $<$ 2.0\\% & \\textbf{{{summary['false_positive_rate']*100:.2f}\\%}} \\\\ \\hline
\\multirow{{3}}{{*}}{{Latency Overhead (ms)}} 
 & P50 Latency Overhead & $<$ 50.0 ms & \\textbf{{{summary['latency_stats_ms']['p50']} ms}} \\\\
 & P95 Latency Overhead & $<$ 100.0 ms & \\textbf{{{summary['latency_stats_ms']['p95']} ms}} \\\\
 & P99 Latency Overhead & $<$ 200.0 ms & \\textbf{{{summary['latency_stats_ms']['p99']} ms}} \\\\ \\hline
\\multirow{{3}}{{*}}{{A/B Efficacy Mitigation}} 
 & Baseline Vulnerability Execution & -- & {summary['ab_efficacy']['baseline_vulnerability_rate_pct']:.2f}\\% \\\\
 & Protected Vulnerability Execution & $<$ 10.0\\% & \\textbf{{{summary['ab_efficacy']['protected_vulnerability_rate_pct']:.2f}\\%}} \\\\
 & Attack Mitigation Efficacy & $>$ 90.0\\% & \\textbf{{{summary['ab_efficacy']['attack_mitigation_rate_pct']:.2f}\\%}} \\\\ \\hline
\\end{{tabular}}
\\end{{table}}
"""
    with open(tex_path, "w", encoding="utf-8") as f:
        f.write(tex_content)
    print(f"  • LaTeX Summary Table exported to: {tex_path}")

    # 2. Confusion Matrix Graphic (confusion_matrix.svg)
    cm_svg_path = os.path.join(out_dir, "confusion_matrix.svg")
    export_svg_confusion_matrix(summary["confusion_matrix"], cm_svg_path)
    print(f"  • Confusion Matrix SVG exported to: {cm_svg_path}")

    # 3. Matplotlib PNG export fallback
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # Confusion matrix PNG
        cm = summary["confusion_matrix"]
        fig, ax = plt.subplots(figsize=(6, 5))
        ax.imshow([[cm["TN"], cm["FP"]], [cm["FN"], cm["TP"]]], cmap="Blues")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Allowed", "Blocked"])
        ax.set_yticklabels(["Actual Benign", "Actual Attack"])
        plt.title("AgentShield Confusion Matrix (N=300)")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "confusion_matrix.png"), dpi=300)
        plt.close()
        print("  • PNG charts generated successfully via matplotlib.")
    except ImportError:
        print("  • Matplotlib not installed; SVG vector graphics exported as fallback.")

    print("\nAll thesis benchmark assets successfully generated and exported!")


if __name__ == "__main__":
    export_assets()
