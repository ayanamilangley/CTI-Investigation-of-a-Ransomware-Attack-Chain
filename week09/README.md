# Week 9 — Atomic Red Team (Assignment 6, part 1 of 2)

**Project:** CTI Investigation of the Black Basta Ransomware Attack Chain
**Team:** Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev

Assignment 6 = weeks 9 and 10. Part 2 (Learning APT Techniques) is in [`../week10/`](../week10/README.md).

## Task (from the syllabus, week 9)

1. Run selected atomic tests (e.g., **T1059, T1003**).
2. Record and analyze the test results in a **SIEM**.

Recommended reading: Atomic Red Team Wiki and GitHub Repository.

## What we did

We ran **9 Atomic Red Team tests** on an isolated Windows VM — the real version of our Week 8
emulation plan — shipped the logs to our Week 5 ELK stack, and detected each one with our own
hunt queries (4 reused from Weeks 5/7, 5 new). The four must-detect steps from Week 8 are
**B2, C2, D1, E3** (encoded PowerShell, new service, LSASS dump, exfiltration).

| Item | Result |
|---|---|
| Atomic tests run | 9 (T1059.001/.003, T1547.001, T1543.003, T1003.001, T1074.001, T1560.001, T1567.002, T1490) |
| Not run (destructive) | T1486 encryption — marker file only |
| SIEM | Elasticsearch + Kibana 8.15.3 (same as Week 5), index `blackbasta-atomic` |
| Queries | 4 reused (Week 5 H1/H3, Week 7 CAR-2020-05-001) + 5 new |
| Result | **Must-detect 4/4**, 7/9 detected overall (1,766 events analysed) |
| Key finding | LSA Protection blocked the LSASS handle → no Sysmon 10, so the Week 7 CAR analytic did not fire; the command-line hunt (Week 5 H3) still caught it |
| Found | SwiftOnSecurity Sysmon config does **not** log Event 10 (LSASS); fixed with our config |

The numbers per test are produced from the lab logs by `scripts/atomic_analytic.py` and live in
`results/atomic_results.md`.

## Files

| Path | What it is |
|---|---|
| [`report.md`](report.md) | The report |
| [`lab-tutorial.md`](lab-tutorial.md) | **Step-by-step tutorial** to run the whole lab on a Windows VM |
| [`config/sysmon-week9.xml`](config/sysmon-week9.xml) | Sysmon config that logs what the queries need (incl. LSASS Event 10) |
| [`queries/atomic_detection_kql.md`](queries/atomic_detection_kql.md) | The Kibana KQL detection, one per test |
| [`scripts/atomic_summary.py`](scripts/atomic_summary.py) | The plan + expected-coverage charts (single source of truth) |
| [`scripts/atomic_analytic.py`](scripts/atomic_analytic.py) | Reads the exported logs → writes the real results table |
| [`scripts/export_logs.ps1`](scripts/export_logs.ps1) | Run on the VM to export the logs as `atomic_logs.zip` |
| [`elk/load_to_elk.py`](elk/load_to_elk.py) | Loads `atomic_logs.zip` into Kibana (index `blackbasta-atomic`) |
| [`results/`](results/) | `atomic_plan.csv`, `atomic_results.md` (filled from the run) |
| `images/` | Coverage charts + your Kibana screenshots |

## How to repeat

Full instructions are in [`lab-tutorial.md`](lab-tutorial.md). Short version (on an isolated Windows VM, snapshot first):

```
# 1. logging on
Sysmon64.exe -accepteula -i config\sysmon-week9.xml
# 2. Atomic Red Team
Install-AtomicRedTeam -getAtomics -Force
# 3. run the tests (example: the two syllabus techniques)
Invoke-AtomicTest T1059.001 -TestNumbers 15,17 -GetPrereqs ; Invoke-AtomicTest T1059.001 -TestNumbers 15,17
Invoke-AtomicTest T1003.001 -TestNumbers 1,2 -GetPrereqs ; Invoke-AtomicTest T1003.001 -TestNumbers 1,2
# 4. export + analyze
.\scripts\export_logs.ps1
python scripts\atomic_analytic.py scripts\atomic_logs.zip
```

To redraw the plan charts: `cd scripts && python3 atomic_summary.py` (needs `matplotlib`).

![Expected detection coverage](images/atomic_coverage.png)
