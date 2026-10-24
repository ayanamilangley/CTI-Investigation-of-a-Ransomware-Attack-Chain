"""
Week 6 - map what we saw in the Week 5 datasets to MITRE ATT&CK (v20).

One list (ROWS) is the single source of truth. The script writes:
  ../results/ttp_mapping.csv          the mapping table
  ../attack_navigator_layer.json      a layer for the ATT&CK Navigator
                                      (https://mitre-attack.github.io/attack-navigator/)

Run:  python3 make_navigator_layer.py     (on Windows: python make_navigator_layer.py)
"""

import csv
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

BLUE, RED, GREY = "#6b8fc7", "#d1495b", "#c9ced6"


ROWS = [
    ("T1059.001", "PowerShell", "Execution", "TA0002",
     "WORKSTATION6, 2020-09-20 16:16:56 (empire_psexec_dcerpc_tcp_svcctl)",
     "powershell -noP -sta -w 1 -enc ..., run as SYSTEM, parent cmd.exe", "observed"),
    ("T1027.010", "Command Obfuscation", "Stealth", "TA0005",
     "WORKSTATION6, same event",
     "the command is hidden in Base64 (-enc)", "observed"),
    ("T1564.003", "Hidden Window", "Stealth", "TA0005",
     "WORKSTATION6, same event",
     "-w 1 means the PowerShell window is hidden", "observed"),
    ("T1569.002", "Service Execution", "Execution", "TA0002",
     "WORKSTATION6, same time (EventID 7045 and 4697)",
     "new service 'Updater' installed, PsExec style", "observed"),
    ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "TA0008",
     "WORKSTATION6, same time",
     "remote service creation (the dataset name says DCE/RPC svcctl); best-fit mapping", "observed"),
    ("T1685", "Disable or Modify Tools", "Defense Impairment", "TA0112",
     "WORKSTATION6, decoded payload",
     "AMSI bypass and PowerShell Script Block Logging turned off", "observed"),
    ("T1105", "Ingress Tool Transfer", "Command and Control", "TA0011",
     "WORKSTATION6 (decoded payload) and WORKSTATION5, 2020-10-23 06:36:43",
     "Net.WebClient download from http://10.10.10.5/news.php; bitsadmin /transfer from GitHub", "observed"),
    ("T1071.001", "Web Protocols", "Command and Control", "TA0011",
     "WORKSTATION6, Sysmon EventID 3",
     "powershell.exe connects to 10.10.10.5:80", "observed"),
    ("T1197", "BITS Jobs", "Stealth", "TA0005",
     "WORKSTATION5, 2020-10-23 06:36:43 (cmd_bitsadmin_download_psh_script)",
     "bitsadmin.exe /transfer downloads a file (v20 lists BITS Jobs under Execution, Persistence and Stealth)", "observed"),
    ("T1003.001", "LSASS Memory", "Credential Access", "TA0006",
     "WORKSTATION5, 2020-10-18 23:50:05 (psh_lsass_memory_dump_comsvcs)",
     "comsvcs.dll MiniDump of lsass.exe; Sysmon 10 with access 0x1fffff and 0x1410", "observed_car"),
    ("T1218.011", "Rundll32", "Stealth", "TA0005",
     "WORKSTATION5, same event",
     "rundll32.exe starts the LSASS dump", "observed"),
    ("T1003.003", "NTDS", "Credential Access", "TA0006",
     "DC01, 2023-07-19 19:20:48 (cmd_dumping_ntds_dit_file_volume_shadow_copy)",
     "vssadmin create shadow /for=C: on a domain controller", "observed"),
    ("T1490", "Inhibit System Recovery", "Impact", "TA0040",
     "not in our logs (CISA advisory, Week 1)",
     "Black Basta deletes shadow copies before encryption; our datasets only contain 'create shadow'", "related"),
]

COLOR = {"observed": BLUE, "observed_car": RED, "related": GREY}


def main():
    (BASE / "results").mkdir(exist_ok=True)
    with open(BASE / "results" / "ttp_mapping.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "technique", "tactic", "tactic_id", "where_seen", "evidence", "status"])
        w.writerows(ROWS)

    layer = {
        "name": "Black Basta hunt - techniques seen in our datasets (Assignment 4)",
        "versions": {"attack": "20", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques we observed in the 5 Windows datasets from Week 5 (blue), the one also "
                       "detected by the CAR analytic CAR-2020-05-001 from Week 7 (red), and one technique "
                       "known from intel but not seen in our logs (grey).",
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True,
                   "showName": True, "showAggregateScores": False, "countUnscored": False,
                   "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": [
            {"techniqueID": r[0], "color": COLOR[r[6]], "comment": f"{r[4]}: {r[5]}",
             "enabled": True, "metadata": [], "links": [], "showSubtechniques": False}
            for r in ROWS
        ],
        "gradient": {"colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Seen in our Week 5 datasets", "color": BLUE},
            {"label": "Seen and detected by CAR-2020-05-001 (Week 7)", "color": RED},
            {"label": "Known from intel, not in our logs", "color": GREY},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
    with open(BASE / "attack_navigator_layer.json", "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    seen = [r for r in ROWS if r[6] != "related"]
    tactics = sorted({r[2] for r in seen})
    print(f"Techniques seen in our logs: {len(seen)}")
    print(f"Detected by the CAR analytic: {sum(1 for r in ROWS if r[6] == 'observed_car')}")
    print(f"Tactics covered ({len(tactics)}): {', '.join(tactics)}")
    print("Wrote results/ttp_mapping.csv and attack_navigator_layer.json")


if __name__ == "__main__":
    main()
