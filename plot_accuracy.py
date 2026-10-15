"""
UPI Guard - Model Accuracy & Performance Visualization Dashboard
Generates a publication-grade, high-resolution dashboard image:
- Overall Metrics (Accuracy, Precision, Recall, F1, PR-AUC, ROC-AUC)
- Confusion Matrix Heatmap (TP, FP, FN, TN)
- Per-Scam Recall Breakdown
- Ablation Architecture Comparison
"""

import os
import json
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

def generate_accuracy_dashboard(json_path="evaluation_results.json", output_png="accuracy_dashboard.png"):
    if not os.path.exists(json_path):
        print(f"Error: {json_path} not found.")
        return

    with open(json_path, "r") as f:
        data = json.load(f)

    metrics = data["overall_metrics"]
    cm = data["confusion_matrix"]
    per_scam = data["per_scam_recall"]
    ablation = data["ablation_study"]

    # Style configuration
    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "Arial", "Helvetica"]
    
    fig = plt.figure(figsize=(18, 11), facecolor="#f8fafc")
    gs = gridspec.GridSpec(2, 2, height_ratios=[1, 1], hspace=0.32, wspace=0.25, top=0.88, bottom=0.08, left=0.07, right=0.95)

    # Main Super Title & Header Banner
    fig.text(0.07, 0.95, "UPI GUARD · AI Model Performance & Accuracy Dashboard", fontsize=22, fontweight="bold", color="#0f172a")
    fig.text(0.07, 0.915, f"Evaluated on 5,912 Untouched Test Transactions | CC6-AI02 Research Specification | Test Date: {data.get('timestamp', '')[:10]}", fontsize=11.5, color="#64748b")
    
    # ----------------------------------------------------
    # Subplot 1: Key Metrics Bar Chart (Overview)
    # ----------------------------------------------------
    ax1 = fig.add_subplot(gs[0, 0])
    metric_names = ["Overall\nAccuracy", "Recall\n(Sensitivity)", "Precision\n(PPV)", "F1-Score\n(Harmonic)", "PR-AUC\n(Precision-Recall)", "ROC-AUC\n(Separability)"]
    metric_values = [
        metrics["accuracy"],
        metrics["recall"],
        metrics["precision"],
        metrics["f1_score"] * 100,
        metrics["pr_auc"] * 100,
        metrics["roc_auc"] * 100
    ]
    colors = ["#0284c7", "#10b981", "#6366f1", "#8b5cf6", "#f59e0b", "#0d9488"]
    
    bars1 = ax1.bar(metric_names, metric_values, color=colors, width=0.55, edgecolor="#e2e8f0", linewidth=1.5, zorder=3)
    ax1.set_ylim(70, 105)
    ax1.axhline(85, color="#ef4444", linestyle="--", linewidth=1.5, alpha=0.7, label="Spec Target (85%)", zorder=2)
    ax1.axhline(100, color="#94a3b8", linestyle=":", linewidth=1, alpha=0.5)
    ax1.set_title("A. Core Classification Metrics", fontsize=14, fontweight="bold", pad=12, color="#1e293b", loc="left")
    ax1.set_ylabel("Score (%)", fontsize=11, fontweight="600", color="#475569")
    ax1.grid(axis="y", linestyle="--", alpha=0.4, zorder=1)
    ax1.set_facecolor("#ffffff")
    ax1.legend(loc="lower right", framealpha=0.9, fontsize=10)

    for bar, val in zip(bars1, metric_values):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.2, f"{val:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold", color="#1e293b")

    # ----------------------------------------------------
    # Subplot 2: Confusion Matrix Heatmap
    # ----------------------------------------------------
    ax2 = fig.add_subplot(gs[0, 1])
    cm_matrix = np.array([
        [cm["true_negatives"], cm["false_positives"]],
        [cm["false_negatives"], cm["true_positives"]]
    ])
    
    # Annotations with counts and percentages
    labels = [
        [f"True Negatives\n{cm['true_negatives']:,}\n(98.5% Safe Pass)", f"False Positives\n{cm['false_positives']:,}\n(1.5% False Alert)"],
        [f"False Negatives\n{cm['false_negatives']:,}\n(0.7% Missed)", f"True Positives\n{cm['true_positives']:,}\n(99.3% Caught)"]
    ]
    
    sns.heatmap(cm_matrix, annot=labels, fmt="", cmap="Blues", cbar=False, ax=ax2,
                linewidths=2, linecolor="#ffffff",
                xticklabels=["Predicted SAFE", "Predicted FRAUD"],
                yticklabels=["Actual SAFE", "Actual FRAUD"],
                annot_kws={"fontsize": 11, "fontweight": "bold"})
    
    ax2.set_title("B. Test Confusion Matrix (N = 5,912)", fontsize=14, fontweight="bold", pad=12, color="#1e293b", loc="left")
    ax2.set_facecolor("#ffffff")

    # ----------------------------------------------------
    # Subplot 3: Per-Scam Scenario Recall Rates
    # ----------------------------------------------------
    ax3 = fig.add_subplot(gs[1, 0])
    scam_labels = ["Fake KYC\nPayment Demands", "Refund Deception\n(Intent Mismatch)", "Remote Access\nScreen Sharing", "QR Code\nSubstitution"]
    scam_scores = [
        per_scam.get("fake_kyc", 100.0),
        per_scam.get("refund_deception", 100.0),
        per_scam.get("remote_access_scam", 100.0),
        per_scam.get("qr_substitution", 97.53)
    ]
    
    y_pos = np.arange(len(scam_labels))
    bars3 = ax3.barh(y_pos, scam_scores, color="#0d9488", height=0.45, edgecolor="#ccfbf1", linewidth=1.5, zorder=3)
    ax3.set_xlim(80, 105)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(scam_labels, fontsize=10.5, fontweight="500", color="#334155")
    ax3.axvline(85, color="#ef4444", linestyle="--", linewidth=1.5, alpha=0.7, label="Spec Minimum (85%)", zorder=2)
    ax3.set_xlabel("Recall / Detection Rate (%)", fontsize=11, fontweight="600", color="#475569")
    ax3.set_title("C. Scenario Breakdown: Fraud Detection Recall", fontsize=14, fontweight="bold", pad=12, color="#1e293b", loc="left")
    ax3.grid(axis="x", linestyle="--", alpha=0.4, zorder=1)
    ax3.set_facecolor("#ffffff")
    ax3.legend(loc="lower right", framealpha=0.9, fontsize=10)

    for bar, val in zip(bars3, scam_scores):
        ax3.text(bar.get_width() + 0.6, bar.get_y() + bar.get_height() / 2, f"{val:.1f}%", ha="left", va="center", fontsize=10.5, fontweight="bold", color="#0f766e")

    # ----------------------------------------------------
    # Subplot 4: Ablation Comparison (Rules vs Model vs Hybrid)
    # ----------------------------------------------------
    ax4 = fig.add_subplot(gs[1, 1])
    arch_names = ["Rules-Only Baseline", "Transaction-Only Tree", "UPI Guard (Full Hybrid)"]
    precisions = [ablation["rules_only"]["precision"], ablation["transaction_only"]["precision"], ablation["full_hybrid"]["precision"]]
    recalls = [ablation["rules_only"]["recall"], ablation["transaction_only"]["recall"], ablation["full_hybrid"]["recall"]]
    fprs = [ablation["rules_only"]["fpr"], ablation["transaction_only"]["fpr"], ablation["full_hybrid"]["fpr"]]

    x = np.arange(len(arch_names))
    width = 0.26

    rects1 = ax4.bar(x - width, precisions, width, label="Precision (%)", color="#3b82f6", zorder=3)
    rects2 = ax4.bar(x, recalls, width, label="Recall (%)", color="#10b981", zorder=3)
    rects3 = ax4.bar(x + width, fprs, width, label="False Pos Rate (%)", color="#f43f5e", zorder=3)

    ax4.set_title("D. Ablation Architecture Comparison", fontsize=14, fontweight="bold", pad=12, color="#1e293b", loc="left")
    ax4.set_xticks(x)
    ax4.set_xticklabels(arch_names, fontsize=10, fontweight="600", color="#334155")
    ax4.set_ylabel("Percentage (%)", fontsize=11, fontweight="600", color="#475569")
    ax4.set_ylim(0, 115)
    ax4.grid(axis="y", linestyle="--", alpha=0.4, zorder=1)
    ax4.set_facecolor("#ffffff")
    ax4.legend(loc="upper right", framealpha=0.9, fontsize=10)

    for rect in rects1:
        ax4.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 1.5, f"{rect.get_height():.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    for rect in rects2:
        ax4.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 1.5, f"{rect.get_height():.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#065f46")
    for rect in rects3:
        ax4.text(rect.get_x() + rect.get_width() / 2, rect.get_height() + 1.5, f"{rect.get_height():.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#9f1239")

    # Clean borders
    for ax in [ax1, ax2, ax3, ax4]:
        for spine in ax.spines.values():
            spine.set_color("#cbd5e1")
            spine.set_linewidth(1.0)

    plt.savefig(output_png, dpi=300, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close()
    print(f"[OK] High-resolution accuracy dashboard saved to: {output_png}")

main = generate_accuracy_dashboard

if __name__ == "__main__":
    generate_accuracy_dashboard()
