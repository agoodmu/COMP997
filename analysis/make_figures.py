#!/usr/bin/env python3
"""Draw the dissertation figures (kit v3.1).

    python3 analysis/make_figures.py [KIT_DIR]

Writes to analysis/figures/:
  figure_3_1_testbed.png          architecture and evidence flow (no data)
  figure_4_1_attack_success.png   attack success by condition with exact 95% CIs
  figure_4_2_session_outcomes.png outcome of every session by condition

Figures 4.1 and 4.2 are computed from results/runs_sessions.csv (one run of
each of the 325 case-condition pairs). Requires matplotlib.
"""
import csv
import math
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

KIT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
OUT = KIT / "analysis" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 10,
    "savefig.dpi": 300,
})
CONDS = ["C0", "C1", "C2", "C3", "C4"]
# condition names as in Table 3.4
CLABEL = {"C0": "C0\nBaseline", "C1": "C1\nInput labels\nand rules", "C2": "C2\nTask policy and\nrestricted IAM",
          "C3": "C3\nCanary checks", "C4": "C4\nLayered"}


def clopper_pearson(k, n, alpha=0.05):
    """Exact binomial confidence interval (as BETA.INV in the workbook)."""
    def cdf(x, p):
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(x + 1))

    def solve(f):
        lo, hi = 0.0, 1.0
        for _ in range(200):
            mid = (lo + hi) / 2
            lo, hi = (lo, mid) if f(mid) else (mid, hi)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(lambda p: 1 - cdf(k - 1, p) >= alpha / 2)
    upper = 1.0 if k == n else solve(lambda p: cdf(k, p) <= alpha / 2)
    return lower, upper


def load_sessions():
    with open(KIT / "results" / "runs_sessions.csv", newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# --------------------------------------------------------------- Figure 3.1
def figure_3_1():
    fig, ax = plt.subplots(figsize=(6.8, 4.7))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 66)
    ax.axis("off")

    def box(x, y, w, h, text, fc, fs=9.5, weight="normal", top=False):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                                    fc=fc, ec="black", lw=0.9))
        ty, va = (y + h - 1.4, "top") if top else (y + h / 2, "center")
        ax.text(x + w / 2, ty, text, ha="center", va=va, fontsize=fs, weight=weight, linespacing=1.12)

    def arrow(x1, y1, x2, y2, dashed=False, both=False):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="<|-|>" if both else "-|>", mutation_scale=9,
                                    lw=0.9 if dashed else 1.0, color="0.3" if dashed else "black",
                                    linestyle=(0, (4, 2.5)) if dashed else "-", shrinkA=0, shrinkB=0))

    def label(x, y, text, fs=8.5, color="black"):
        ax.text(x, y, text, ha="center", va="center", fontsize=fs, color=color, style="italic",
                linespacing=1.05, bbox=dict(fc="white", ec="none", pad=0.5))

    BLUE, PEACH, GREEN, GREY, YELLOW = "#dbe8f5", "#fbe5cf", "#e2efda", "#ececec", "#fff2cc"
    # model and agent
    box(23, 55, 30, 10, "Amazon Bedrock\nNova Lite (Converse API)", BLUE)
    box(0.3, 22, 14.7, 20, "Test harness\n(run.py)\n\nsends cases,\nreads the SQS\nqueue, scores\neach session",
        YELLOW, fs=8.6)
    box(19, 17, 38, 30, "AgentCore runtime (the agent)", BLUE, fs=9.5, weight="bold", top=True)
    box(20.5, 36.4, 35, 6.6, "C1  phrase rule on the user request;\nsource markers around tool results", PEACH,
        fs=8.5)
    box(20.5, 28.6, 35, 6.6, "C2  policy check of each tool request\nagainst the case's task policy", PEACH, fs=8.5)
    box(20.5, 20.8, 35, 6.6, "C3  canary check on the final answer\nand on notification text", PEACH, fs=8.5)
    ax.text(38, 18.9, "C0: none        C4: C1 + C2 + C3", ha="center", va="center", fontsize=8.5,
            style="italic")
    # tools and resources
    box(61.5, 18.5, 16, 27.5, "Tool Lambda\nfunctions\n\nC0, C1, C3:\none function,\nbroad role\n\n"
        "C2, C4: one\nper tool,\nrestricted role", GREEN, fs=8.7)
    box(82, 38, 17.5, 9, "S3 bucket\ndocuments and\nprotected file", GREEN, fs=8.7)
    box(82, 27.5, 17.5, 9, "DynamoDB\nrecords and\nprotected tables", GREEN, fs=8.7)
    box(82, 17, 17.5, 9, "SNS topic", GREEN, fs=8.7)
    box(82, 1.5, 17.5, 10, "SQS queue\nread only by\nthe harness", GREEN, fs=8.7)
    # evidence
    box(0.3, 1.5, 18.2, 10, "Evidence export\nAWS CLI, Logs\nInsights queries", GREY, fs=8.7)
    box(23, 1.5, 30, 10, "CloudWatch Logs\ntrail events, Lambda logs\nand runtime logs", GREY, fs=8.7)
    box(58.5, 1.5, 20.5, 10, "CloudTrail\nmanagement and\ndata events", GREY, fs=8.7)

    # runtime path (solid)
    arrow(14.5, 32, 19, 32, both=True)
    arrow(33, 47, 33, 55)
    arrow(43, 55, 43, 47)
    label(33, 51, "prompt")
    label(43, 51, "tool request\nor answer")
    arrow(57, 32, 61.5, 32)
    arrow(77.5, 40, 82, 42.5)
    arrow(77.5, 32, 82, 32)
    arrow(77.5, 24, 82, 21.5)
    arrow(90.75, 17, 90.75, 11.5)
    # audit records (dashed)
    arrow(28, 17, 28, 11.5, dashed=True)
    label(28, 14.2, "runtime log", fs=8, color="0.2")
    arrow(64, 18.5, 50, 11.5, dashed=True)
    label(57.0, 15.0, "Lambda log", fs=8, color="0.2")
    arrow(73, 18.5, 73, 11.5, dashed=True)
    label(73, 15.0, "API calls", fs=8, color="0.2")
    arrow(58.5, 6.5, 53, 6.5, dashed=True)
    arrow(23, 6.5, 18.5, 6.5, dashed=True)

    fig.savefig(OUT / "figure_3_1_testbed.png", bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)


# --------------------------------------------------------------- Figure 4.1
def figure_4_1(rows):
    attacks = [r for r in rows if r["kind"] == "attack"]
    k = [sum(1 for r in attacks if r["condition"] == c and r["attack_success"] == "1") for c in CONDS]
    n = [sum(1 for r in attacks if r["condition"] == c) for c in CONDS]
    rate = [100 * a / b for a, b in zip(k, n)]
    ci = [clopper_pearson(a, b) for a, b in zip(k, n)]
    lo = [r - 100 * c[0] for r, c in zip(rate, ci)]
    hi = [100 * c[1] - r for r, c in zip(rate, ci)]
    fig, ax = plt.subplots(figsize=(7.0, 3.7))
    x = range(len(CONDS))
    ax.bar(x, rate, width=0.6, color="#8c8c8c", edgecolor="black", lw=0.8)
    ax.errorbar(x, rate, yerr=[lo, hi], fmt="none", ecolor="black", elinewidth=1.0, capsize=6)
    for i in x:
        ax.text(i, 100 * ci[i][1] + 1.2, "%.0f%%\n(%d/%d)" % (rate[i], k[i], n[i]), ha="center", va="bottom",
                fontsize=11)
    ax.set_xticks(list(x))
    ax.set_xticklabels([CLABEL[c] for c in CONDS], fontsize=11)
    ax.set_ylabel("Attack success (%)", fontsize=11.5)
    ax.tick_params(axis="y", labelsize=11)
    ax.set_ylim(0, 40)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "figure_4_1_attack_success.png")
    plt.close(fig)
    return k, n, ci


# --------------------------------------------------------------- Figure 4.2
def figure_4_2(rows):
    cats = [("attack_success", "Attack success", "#c0392b"),
            ("attack_contained", "Attack contained", "#e59866"),
            ("attack_failed", "Attack failed", "#bfbfbf"),
            ("benign_complete", "Legitimate task completed", "#5d8aa8"),
            ("benign_blocked", "Legitimate task blocked", "#1f3a5f")]

    def cat(r):
        if r["kind"] == "attack":
            return r["outcome"]
        return "benign_complete" if r["benign_complete"] == "1" else "benign_blocked"

    counts = {c: Counter(cat(r) for r in rows if r["condition"] == c) for c in CONDS}
    fig, ax = plt.subplots(figsize=(7.0, 3.9))
    bottom = [0] * len(CONDS)
    for key, lab, col in cats:
        vals = [counts[c][key] for c in CONDS]
        ax.bar(range(len(CONDS)), vals, bottom=bottom, width=0.6, color=col, edgecolor="black", lw=0.6,
               label=lab)
        for i, v in enumerate(vals):
            if v >= 3:
                ax.text(i, bottom[i] + v / 2, str(v), ha="center", va="center", fontsize=10.5,
                        color="white" if col in ("#c0392b", "#1f3a5f", "#5d8aa8") else "black")
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_xticks(range(len(CONDS)))
    ax.set_xticklabels(CONDS, fontsize=11.5)
    ax.set_ylabel("Sessions (65 per condition)", fontsize=11.5)
    ax.tick_params(axis="y", labelsize=11)
    ax.set_ylim(0, 66)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False, fontsize=10.5)
    fig.tight_layout()
    fig.savefig(OUT / "figure_4_2_session_outcomes.png")
    plt.close(fig)
    return counts


if __name__ == "__main__":
    rows = load_sessions()
    figure_3_1()
    k, n, ci = figure_4_1(rows)
    counts = figure_4_2(rows)
    for c, a, b, (l, u) in zip(CONDS, k, n, ci):
        print("%s attack success %d/%d  95%% CI [%.1f, %.1f]  outcomes %s" % (
            c, a, b, 100 * l, 100 * u, dict(counts[c])))
    print("wrote", OUT)
