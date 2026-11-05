"""
Week 10 - APT41 TTPs, mapped to MITRE ATT&CK (v20), compared with our Black Basta chain.

One list (ROWS) is the single source of truth. The script writes:
  ../results/ttp_comparison.csv       APT41 techniques, tactic, and overlap with our chain
  ../attack_navigator_layer.json      a layer for the ATT&CK Navigator
  ../images/apt41_overlap.png         APT41 vs Black Basta: techniques per tactic + overlap

APT41 techniques are taken from the MITRE ATT&CK group page G0096 (and its campaigns
C0017 and C0040 "APT41 DUST"). The "in our Black Basta chain" flag compares each one to
the techniques our own project used in Weeks 4-9 (see CHAIN below), so the overlap is
measured against the chain WE built, not just the bare ATT&CK software entry.

Run:  python3 make_apt41_layer.py     (on Windows: python make_apt41_layer.py)
Needs: matplotlib
"""

import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent.parent

BLUE, RED, GOLD = "#6b8fc7", "#d1495b", "#e6b422"

# Techniques our own Black Basta chain used across Weeks 4-9 (parent or sub id).
# From week06/results/ttp_mapping.csv + the Week 8 plan + the Week 9 atomic tests.
CHAIN = {
    "T1566.004", "T1219.002", "T1204.002", "T1059.003", "T1059.001", "T1027.010",
    "T1564.003", "T1569.002", "T1543.003", "T1021.002", "T1685", "T1105", "T1071.001",
    "T1197", "T1547.001", "T1003.001", "T1218.011", "T1003.003", "T1074.001",
    "T1560.001", "T1567.002", "T1486", "T1490", "T1485", "T1036.005",
}

# (ATT&CK id, name, tactic, tactic id, APT41 note, signature?)  signature = APT41 hallmark
ROWS = [
    # Resource Development
    ("T1588.002", "Tool", "Resource Development", "TA0042",
     "Uses public tools: Mimikatz, Cobalt Strike, China Chopper, for mission objectives", False),
    ("T1588.003", "Code Signing Certificates", "Resource Development", "TA0042",
     "Steals code-signing certificates to sign its malware", True),
    # Initial Access
    ("T1566.001", "Spearphishing Attachment", "Initial Access", "TA0001",
     "Spear-phishing with .chm / LNK attachments (e.g. the 2025 TOUGHPROGRESS campaign)", False),
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001",
     "Fast exploitation of public web/app vulnerabilities (Citrix, Cisco, Zoho in 2019-2020)", True),
    ("T1195.002", "Compromise Software Supply Chain", "Initial Access", "TA0001",
     "Signature move: poisoned legitimate software (game updates, utilities) to reach victims", True),
    ("T1133", "External Remote Services", "Initial Access", "TA0001",
     "Uses stolen VPN / remote-service access to get in", False),
    # Execution
    ("T1059.001", "PowerShell", "Execution", "TA0002",
     "Runs PowerShell payloads  (SAME as our chain, Week 9 T9-2)", False),
    ("T1059.003", "Windows Command Shell", "Execution", "TA0002",
     "Batch / cmd.exe  (SAME as our chain, Week 9 T9-1)", False),
    ("T1047", "Windows Management Instrumentation", "Execution", "TA0002",
     "WMI for execution and recon", False),
    ("T1053.005", "Scheduled Task", "Execution", "TA0002",
     "Scheduled tasks for execution and persistence", False),
    # Persistence
    ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence", "TA0003",
     "Run keys for persistence  (SAME as our chain, Week 9 T9-3)", False),
    ("T1543.003", "Windows Service", "Persistence", "TA0003",
     "Creates services for persistence  (SAME as our chain, Week 9 T9-4)", False),
    ("T1505.003", "Web Shell", "Persistence", "TA0003",
     "China Chopper and other web shells on compromised servers", False),
    ("T1542.003", "Bootkit", "Persistence", "TA0003",
     "Rare MBR bootkit (ROCKBOOT) for stealthy persistence on high-value hosts", True),
    # Privilege Escalation / Stealth
    ("T1055", "Process Injection", "Privilege Escalation", "TA0004",
     "Process hollowing (PLUSINJECT into svchost.exe, 2025)", False),
    ("T1574.001", "DLL Search Order / Side-Loading", "Stealth", "TA0005",
     "DLL side-loading to run payloads under trusted binaries  (overlaps our T1036 idea)", True),
    ("T1553.002", "Code Signing", "Defense Impairment", "TA0112",
     "Signs malware with stolen certificates to look trusted", True),
    ("T1036.005", "Match Legitimate Name or Location", "Stealth", "TA0005",
     "Names tools like Windows files  (SAME idea as our chain, Week 8 B3)", False),
    ("T1140", "Deobfuscate/Decode Files or Information", "Stealth", "TA0005",
     "Decrypts/decodes its payloads in memory", False),
    ("T1070.004", "File Deletion", "Stealth", "TA0005",
     "Deletes its files to clean up", False),
    ("T1014", "Rootkit", "Stealth", "TA0005",
     "Rootkits to hide on select systems", False),
    ("T1112", "Modify Registry", "Defense Impairment", "TA0112",
     "Edits the registry to hide or configure malware", False),
    # Credential Access
    ("T1003.001", "LSASS Memory", "Credential Access", "TA0006",
     "Mimikatz LSASS dump  (SAME as our chain + our Week 7 CAR + Week 9 T9-5)", False),
    ("T1003.003", "NTDS", "Credential Access", "TA0006",
     "Dumps the AD database on domain controllers  (SAME as our chain)", False),
    ("T1555", "Credentials from Password Stores", "Credential Access", "TA0006",
     "Steals stored credentials, including from browsers", False),
    # Discovery
    ("T1018", "Remote System Discovery", "Discovery", "TA0007",
     "Maps other hosts before moving  (shared with our chain intel)", False),
    ("T1082", "System Information Discovery", "Discovery", "TA0007",
     "Collects host info", False),
    ("T1087.002", "Domain Account Discovery", "Discovery", "TA0007",
     "Enumerates AD accounts", False),
    # Lateral Movement
    ("T1021.002", "SMB / Windows Admin Shares", "Lateral Movement", "TA0008",
     "Spreads over SMB / admin shares  (SAME as our chain, Week 4/9)", False),
    ("T1550.002", "Pass the Hash", "Lateral Movement", "TA0008",
     "Reuses stolen hashes to move laterally", False),
    ("T1570", "Lateral Tool Transfer", "Lateral Movement", "TA0008",
     "Copies tools host to host  (shared with our chain idea)", False),
    # Collection
    ("T1074.001", "Local Data Staging", "Collection", "TA0009",
     "Stages files before theft  (SAME as our chain, Week 9 T9-6)", False),
    ("T1560.001", "Archive via Utility", "Collection", "TA0009",
     "Archives data before exfil  (SAME as our chain, Week 9 T9-7)", False),
    ("T1056.001", "Keylogging", "Collection", "TA0009",
     "Keyloggers for espionage", False),
    # Command and Control
    ("T1071.001", "Web Protocols", "Command and Control", "TA0011",
     "HTTP/HTTPS C2  (SAME as our chain, Week 6)", False),
    ("T1105", "Ingress Tool Transfer", "Command and Control", "TA0011",
     "Downloads more tools  (SAME as our chain, Week 6)", False),
    ("T1102", "Web Service", "Command and Control", "TA0011",
     "Signature move: uses Google Calendar / cloud services as C2 (TOUGHPROGRESS, 2025)", True),
    ("T1090", "Proxy", "Command and Control", "TA0011",
     "Proxies C2 to hide the real server", False),
    # Exfiltration
    ("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration", "TA0010",
     "Exfil to cloud storage  (SAME as our chain, Week 9 T9-8)", False),
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "TA0010",
     "Steals data over the C2 channel", False),
    # Impact
    ("T1486", "Data Encrypted for Impact", "Impact", "TA0040",
     "Deployed ransomware (Encryptor/ransomware in game studios)  (SAME as Black Basta's goal)", False),
    ("T1496.001", "Compute Hijacking", "Impact", "TA0040",
     "Crypto-mining on victim machines for profit", False),
]


def main():
    (BASE / "results").mkdir(exist_ok=True)
    rows_out = []
    for tid, name, tactic, tac_id, note, sig in ROWS:
        parent = tid.split(".")[0]
        overlap = tid in CHAIN or parent in CHAIN
        rows_out.append([tid, name, tactic, tac_id, "yes" if overlap else "no",
                         "yes" if sig else "no", note])
    with open(BASE / "results" / "ttp_comparison.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "technique", "tactic", "tactic_id",
                    "in_black_basta_chain", "apt41_signature", "note"])
        w.writerows(rows_out)

    # ---- ATT&CK Navigator layer -------------------------------------------------
    def color(r):
        tid = r[0]
        if tid in CHAIN or tid.split(".")[0] in CHAIN:
            return RED      # APT41 technique that is also in our Black Basta chain
        if r[5]:
            return GOLD     # APT41 signature technique (not in our chain)
        return BLUE         # other APT41 technique

    layer = {
        "name": "APT41 (G0096) vs our Black Basta chain (Week 10)",
        "versions": {"attack": "20", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "APT41 techniques (MITRE ATT&CK G0016... G0096 and campaigns C0017, C0040). "
                       "Red = APT41 technique also used in the Black Basta chain we studied in Weeks 4-9 "
                       "(our detections already cover these). Gold = APT41 signature technique not in our "
                       "chain. Blue = other APT41 technique.",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True,
                   "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": r[0], "color": color(r), "comment": r[4] + " — " + ("in our chain" if (r[0] in CHAIN or r[0].split('.')[0] in CHAIN) else ("APT41 signature" if r[5] else "APT41")),
             "enabled": True, "showSubtechniques": False}
            for r in ROWS
        ],
        "legendItems": [
            {"label": "Also in our Black Basta chain (we already detect it)", "color": RED},
            {"label": "APT41 signature technique", "color": GOLD},
            {"label": "Other APT41 technique", "color": BLUE},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#2a2a2a",
        "selectTechniquesAcrossTactics": True,
    }
    with open(BASE / "attack_navigator_layer.json", "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    # ---- chart: techniques per tactic, with overlap -----------------------------
    order = ["Resource Development", "Initial Access", "Execution", "Persistence",
             "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access",
             "Discovery", "Lateral Movement", "Collection", "Command and Control",
             "Exfiltration", "Impact"]
    per = {t: [0, 0] for t in order}  # [apt41 count, overlap count]
    for r in rows_out:
        tac = r[2]
        per.setdefault(tac, [0, 0])
        per[tac][0] += 1
        if r[4] == "yes":
            per[tac][1] += 1
    tacs = [t for t in order if per[t][0]]
    a41 = [per[t][0] for t in tacs]
    ov = [per[t][1] for t in tacs]
    y = range(len(tacs))[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(list(y), a41, color=BLUE, label="APT41 techniques")
    ax.barh(list(y), ov, color=RED, label="Also in our Black Basta chain")
    ax.set_yticks(list(y))
    ax.set_yticklabels(tacs, fontsize=9)
    ax.set_xlabel("Number of techniques", fontsize=9)
    total = len(ROWS)
    total_ov = sum(1 for r in rows_out if r[4] == "yes")
    ax.set_title(f"Week 10 - APT41 TTPs by ATT&CK tactic ({total} techniques), "
                 f"and overlap with our Black Basta chain ({total_ov} shared)", fontsize=10.5)
    for i, t in zip(list(y), tacs):
        ax.text(per[t][0] + 0.1, i, str(per[t][0]), va="center", fontsize=8, color="#333")
    ax.legend(loc="lower right", fontsize=9, frameon=False)
    ax.set_xticks(range(0, max(a41) + 2))
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    plt.tight_layout()
    (BASE / "images").mkdir(exist_ok=True)
    fig.savefig(BASE / "images" / "apt41_overlap.png", dpi=150, bbox_inches="tight")
    plt.close(fig)

    print(f"APT41 techniques listed: {len(ROWS)}")
    print(f"Also in our Black Basta chain: {total_ov}")
    print(f"APT41 signature techniques: {sum(1 for r in ROWS if r[5])}")
    print("Wrote results/ttp_comparison.csv, attack_navigator_layer.json, images/apt41_overlap.png")


if __name__ == "__main__":
    main()
