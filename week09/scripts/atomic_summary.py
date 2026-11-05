"""
Week 9 - Atomic Red Team: the test plan and the EXPECTED detection coverage.

One list (TESTS) is the single source of truth for which atomic tests we run
(they come from the Week 8 emulation plan, phases A-E) and which log + ELK query
should catch each one. This script writes:

  ../results/atomic_plan.csv       the plan table (one row per atomic test)
  ../images/atomic_coverage.png    expected detection coverage (a bar per test)
  ../images/atomic_logsource.png   how many tests each Windows log source catches

IMPORTANT: this file is the PLAN and the EXPECTED result. The REAL result
(detected yes/no, event counts) is produced by `atomic_analytic.py`, which reads
the logs you export from the lab VM after you run the tests. See lab-tutorial.md.

Run:  python3 atomic_summary.py     (on Windows: python atomic_summary.py)
Needs: matplotlib
"""

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

BASE = Path(__file__).resolve().parent.parent

GREEN, AMBER, GREY = "#5a9367", "#d9a441", "#c9ced6"
EXP_COLOR = {"detect": GREEN, "partial": AMBER, "doc_only": GREY}

# Log-source vocabulary (Windows event that carries the signal)
#   S1   = Sysmon 1  (process create)          S10 = Sysmon 10 (process access -> lsass)
#   S11  = Sysmon 11 (file create)             S3  = Sysmon 3  (network connect)
#   S13  = Sysmon 13 (registry value set)      PS  = PowerShell 4104 (script block)
#   7045 = Security 7045 / 4697 (new service)  4657 = Security 4657 (registry)
#   4688 = Security 4688 (process create)

# step, phase, ATT&CK id, technique, atomic test (number + name),
# log families (list), which ELK query, must-detect?(Week8), expected
TESTS = [
    ("T9-1", "B Execution", "T1059.003", "Windows Command Shell",
     "ART T1059.003 #1 - Create and Execute Batch Script",
     ["S1", "4688"], "Week 5 H1 (process-tree pivot)", "no", "detect"),
    ("T9-2", "B Execution", "T1059.001", "PowerShell",
     "ART T1059.001 #15 (-EncodedCommand) + #17 (obfuscated IEX)",
     ["S1", "PS", "4688"], "Week 5 H1", "yes", "detect"),
    ("T9-3", "C Persistence", "T1547.001", "Registry Run Keys",
     "ART T1547.001 #1 - Reg Key Run (has cleanup)",
     ["S13", "4657"], "Week 9 Q1 (new)", "no", "detect"),
    ("T9-4", "C Persistence", "T1543.003", "Windows Service",
     "ART T1543.003 #1 - Service Installation (has cleanup)",
     ["7045", "S1"], "Week 5 H1 (pivot 2)", "yes", "detect"),
    ("T9-5", "D Credential Access", "T1003.001", "LSASS Memory",
     "ART T1003.001 #2 - comsvcs.dll MiniDump (also #1 ProcDump)",
     ["S10", "S1", "S11"], "Week 5 H3 + Week 7 CAR-2020-05-001", "yes", "detect"),
    ("T9-6", "E Exfiltration", "T1074.001", "Local Data Staging",
     "ART T1074.001 #1 - Stage data from Discovery.bat",
     ["S11", "S1"], "Week 9 Q2 (new)", "no", "partial"),
    ("T9-7", "E Exfiltration", "T1560.001", "Archive via Utility",
     "ART T1560.001 #1 - Compress Data for Exfiltration (PowerShell/7-Zip)",
     ["S1", "S11"], "Week 9 Q3 (new)", "no", "detect"),
    ("T9-8", "E Exfiltration", "T1567.002", "Exfil to Cloud Storage (Rclone)",
     "ART T1567.002 - Rclone to a lab endpoint we control",
     ["S1", "S3"], "Week 9 Q4 (new)", "yes", "detect"),
    ("T9-9", "Impact (opt.)", "T1490", "Inhibit System Recovery",
     "ART T1490 #1 - Delete Volume Shadow Copies (VM snapshot first!)",
     ["S1", "4688"], "Week 9 Q5 = CAR-2021-01-009 (new)", "no", "detect"),
    ("--", "Impact", "T1486", "Data Encrypted for Impact",
     "NOT RUN - destructive (Week 8 rule). Marker file EMULATION_WAS_HERE.txt only.",
     [], "n/a", "no", "doc_only"),
]

COLS = ["step", "phase", "attack_id", "technique", "atomic_test",
        "log_families", "elk_query", "must_detect", "expected"]

LOG_LABEL = {
    "S1": "Sysmon 1\n(process)", "S10": "Sysmon 10\n(LSASS access)",
    "S11": "Sysmon 11\n(file create)", "S3": "Sysmon 3\n(network)",
    "S13": "Sysmon 13\n(registry)", "PS": "PowerShell 4104\n(script block)",
    "7045": "Security 7045/4697\n(service)", "4657": "Security 4657\n(registry)",
    "4688": "Security 4688\n(process)",
}
LOG_ORDER = ["S1", "PS", "S10", "S11", "S13", "S3", "7045", "4657", "4688"]


def write_csv():
    (BASE / "results").mkdir(exist_ok=True)
    with open(BASE / "results" / "atomic_plan.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        for t in TESTS:
            row = list(t)
            row[5] = " ".join(t[5])
            w.writerow(row)


def chart_coverage():
    run = [t for t in TESTS if t[8] != "doc_only"][::-1]  # T9-1 on top
    labels = [f"{t[0]}  {t[2]}\n{t[3]}" for t in run]
    colors = [EXP_COLOR[t[8]] for t in run]
    edge = ["#2d2d2d" if t[7] == "yes" else "white" for t in run]
    lw = [2.4 if t[7] == "yes" else 0.6 for t in run]

    fig, ax = plt.subplots(figsize=(10.5, 5.4))
    ax.barh(range(len(run)), [1] * len(run), color=colors, edgecolor=edge, linewidth=lw)
    ax.set_yticks(range(len(run)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xticks([])
    ax.set_xlim(0, 1)
    for i, t in enumerate(run):
        ax.text(0.5, i, {"detect": "EXPECT DETECT", "partial": "EXPECT PARTIAL"}[t[8]],
                ha="center", va="center", fontsize=8, color="white", fontweight="bold")
    ax.set_title("Week 9 - Atomic Red Team: EXPECTED detection coverage\n"
                 "(thick border = must-detect step from the Week 8 plan; "
                 "fill the real result with atomic_analytic.py)", fontsize=10.5)
    legend = [
        Patch(facecolor=GREEN, label="Expect detect"),
        Patch(facecolor=AMBER, label="Expect partial (noisy, needs tuning)"),
        Patch(facecolor="white", edgecolor="#2d2d2d", linewidth=2.4, label="Must-detect (Week 8)"),
    ]
    ax.legend(handles=legend, loc="lower center", bbox_to_anchor=(0.5, -0.2),
              ncol=3, fontsize=8, frameon=False)
    for s in ("top", "right", "bottom"):
        ax.spines[s].set_visible(False)
    plt.tight_layout()
    (BASE / "images").mkdir(exist_ok=True)
    fig.savefig(BASE / "images" / "atomic_coverage.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def chart_logsource():
    counts = {k: 0 for k in LOG_ORDER}
    for t in TESTS:
        for fam in t[5]:
            counts[fam] += 1
    fams = [k for k in LOG_ORDER if counts[k]]
    vals = [counts[k] for k in fams]
    fig, ax = plt.subplots(figsize=(9.5, 4.3))
    ax.bar(range(len(fams)), vals, color="#6b8fc7")
    ax.set_xticks(range(len(fams)))
    ax.set_xticklabels([LOG_LABEL[k] for k in fams], fontsize=8)
    ax.set_ylabel("Atomic tests using this log", fontsize=9)
    ax.set_title("Week 9 - which Windows log source carries each test's signal\n"
                 "(a test can need more than one log)", fontsize=10.5)
    for i, v in enumerate(vals):
        ax.text(i, v + 0.04, str(v), ha="center", fontsize=9)
    ax.set_ylim(0, max(vals) + 1)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    plt.tight_layout()
    fig.savefig(BASE / "images" / "atomic_logsource.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def main():
    write_csv()
    chart_coverage()
    chart_logsource()
    run = [t for t in TESTS if t[8] != "doc_only"]
    must = [t for t in run if t[7] == "yes"]
    print(f"Atomic tests planned: {len(run)}  (must-detect: {len(must)} -> {', '.join(t[0] for t in must)})")
    print("Wrote results/atomic_plan.csv, images/atomic_coverage.png, images/atomic_logsource.png")


if __name__ == "__main__":
    main()
