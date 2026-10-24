# Adversary Emulation Plan: Black Basta / Storm-1811 (simple)

**Project:** CTI Investigation of the Black Basta Ransomware Attack Chain
**Authors:** Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev
**Week 8 — Creating a Plan to Emulate an Attacker's Action (Assignment 5)**

---

## 1. What this is

An **adversary emulation plan** is a plan to *act like a real attacker in our own lab*, using the
attacker's known behaviour (TTPs), so we can **test if our detections work**. We do not attack anyone.
We copy only the *behaviour* of Black Basta / Storm-1811 that we studied in Weeks 1–5, on machines we own.

Note on names: we use ATT&CK v20, as in Weeks 6 and 7. There the old tactic *Defense Evasion* (TA0005) is called **Stealth**.

The syllabus asks for a **simple** plan with three phases: **initial access → persistence → data exfiltration**.
We keep to these three phases and add a short execution and credential step between them, because the
real chain needs them. The last real step of Black Basta — **encryption (T1486) and deleting backups
(T1490) — is OUT of scope**. We replace it with a harmless marker file. See the safety rules (section 2).

This plan follows the MITRE Engenuity adversary-emulation method (intelligence → plan → emulate → detect)
and is written so it can be run with **MITRE CALDERA** or **Atomic Red Team** in a lab.

## 2. Scope and safety rules (Rules of Engagement)

| Rule | Detail |
|---|---|
| Where | An **isolated lab only**: one Windows VM + one Windows Server (DC) VM, on a host-only network. No internet to the victim VMs except a fake "C2" we control. |
| Who | Our team, on our own VMs. No real company, no real user, no production system. |
| Data | We use a **canary file** `C:\decoy\patient_records.txt` (fake data we made). No real personal data. |
| Destruction | **No encryption, no deleting shadow copies, no stopping AV.** Where the real group would encrypt, we only write `EMULATION_WAS_HERE.txt`. |
| Credentials | We dump LSASS on a **test account only** (a local user we created `labadmin`). The point is to trigger the detection, not to collect real passwords. |
| Exfiltration | "Exfil" goes to **our own** lab web server / MinIO bucket, not to a real cloud. |
| Stop | If a VM is unstable or a step touches anything outside the lab, we stop and snapshot. We take a VM snapshot before every run so we can roll back. |
| Logging | Sysmon (SwiftOnSecurity config) + Windows Security auditing + PowerShell ScriptBlock logging ON, shipped to our Week 5 ELK stack. |

## 3. The attacker we emulate (from our own intel)

From Weeks 1–5: Storm-1811 is an affiliate that deploys **Black Basta** ransomware. Their 2024 chain was:
email bombing → fake IT help-desk call (vishing) → victim opens **Quick Assist** → attacker runs batch /
PowerShell → persistence → credential theft → lateral movement → data theft with **Rclone** → encryption.
Sources: CISA AA24-131A, Microsoft and Rapid7 (May 2024), MITRE ATT&CK G1046 / S1070.

We emulate a **trimmed, safe** version of this chain.

## 4. The plan, phase by phase

Each step has: ATT&CK ID, what the real group does, what **we** do in the lab (safe), the **data source**
to watch, and the **Week 5 hunt** that should catch it. "Evidence" = how well the real behaviour is documented.

### Phase A — Initial access

| # | ATT&CK | Real Black Basta / Storm-1811 behaviour | Safe lab emulation | Detect (data source → signal) | Evidence |
|---|---|---|---|---|---|
| A1 | **T1566.004** Phishing: Spearphishing Voice | Call the user, pretend to be IT help desk | *Skipped in tooling* — we start at the remote-tool step. Documented only. | N/A (human step) | reported |
| A2 | **T1219.002** Remote Access Tools: Remote Desktop Software | Victim opens **Quick Assist**; attacker gets control | Launch `quickassist.exe` (or a stand-in remote tool) on the victim VM | Sysmon 1: process `QuickAssist.exe` with no matching help-desk ticket | reported |
| A3 | **T1204.002** User Execution: Malicious File | User runs a `.bat` "spam-filter update" | Run a **benign** `update.bat` we wrote that only echoes markers | Sysmon 1: `cmd.exe` child of a remote-access process | reported |

### Phase B — Execution and stealth

| # | ATT&CK | Real behaviour | Safe lab emulation | Detect | Evidence |
|---|---|---|---|---|---|
| B1 | **T1059.003** Windows Command Shell | Batch scripts run in `cmd.exe` | `update.bat` runs real but harmless commands | Sysmon 1: `cmd.exe /c` command lines | reported |
| B2 | **T1059.001** PowerShell | Encoded / hidden-window PowerShell | Run PowerShell with `-EncodedCommand` that only prints text (Atomic T1059.001) | Sysmon 1 + PowerShell 4104: `-enc`, `-w hidden`; **decode the Base64** (our Week 5 H1) | confirmed (Week 5) |
| B3 | **T1036.005** Masquerading: Match Legitimate Name | OpenSSH renamed `RuntimeBroker.exe` | Copy a signed test binary to a Windows-like name and run it | Sysmon 1: image name vs real path / hash mismatch | reported |

### Phase C — Persistence

| # | ATT&CK | Real behaviour | Safe lab emulation | Detect | Evidence |
|---|---|---|---|---|---|
| C1 | **T1547.001** Registry Run Keys / Startup Folder | Run key starts the script at logon | Add a Run key pointing to our benign marker script (Atomic T1547.001); remove it after | Sysmon 13 / Security 4657: write to `...\CurrentVersion\Run` | reported |
| C2 | **T1543.003** Create or Modify System Process: Windows Service | PsExec-style **remote service** starts the payload | Create a test service that runs our benign binary, then delete it (Atomic T1543.003) | Security 7045 / 4697 + Sysmon 1: new service → unusual child | confirmed (Week 5 H1 pivot) |

### Phase D — Credential access (needed before exfil)

| # | ATT&CK | Real behaviour | Safe lab emulation | Detect | Evidence |
|---|---|---|---|---|---|
| D1 | **T1003.001** OS Credential Dumping: LSASS Memory | Mimikatz / `comsvcs.dll` MiniDump of LSASS | Dump LSASS on the lab VM, where only our test account `labadmin` logs on (Atomic T1003.001 — dump to a lab path, then delete). **No real creds used.** | Sysmon 10 to `lsass.exe` with `GrantedAccess 0x1fffff` / `0x1410` (Week 5 H3); **CAR-2020-05-001**: `dbgcore.dll` or `dbghelp.dll` in `CallTrace` (Week 7); Sysmon 1 `rundll32` + `comsvcs` + `MiniDump` | confirmed (Weeks 5 and 7) |

### Phase E — Data exfiltration

| # | ATT&CK | Real behaviour | Safe lab emulation | Detect | Evidence |
|---|---|---|---|---|---|
| E1 | **T1074.001** Data Staged: Local Data Staging | Collect files into one folder | Copy our **canary** `patient_records.txt` into `C:\temp\stage\` | Sysmon 11: many file-create events into one staging folder | reported |
| E2 | **T1560.001** Archive Collected Data: via Utility | Archive before sending | Zip the staging folder with `tar`/7-Zip (Atomic T1560.001) | Sysmon 1: `tar.exe` / archiver on a staging path | reported |
| E3 | **T1567.002** Exfiltration Over Web Service: Exfiltration to Cloud Storage (Rclone) | Rclone the data to attacker cloud | Upload the zip to **our own** lab MinIO/web server (Rclone to a lab endpoint we control) | Sysmon 1 + Sysmon 3: `rclone.exe` + outbound to the lab C2 IP only | reported |

### Out of scope (documented, not run)

| ATT&CK | Why excluded |
|---|---|
| **T1486** Data Encrypted for Impact | Destructive. We write `EMULATION_WAS_HERE.txt` instead. |
| **T1490** Inhibit System Recovery (`vssadmin delete shadows`) | Destructive. Not run. A safe test (on a VM snapshot) can be planned later for CAR-2021-01-009 (Week 7). |
| **T1485** Data Destruction | Destructive. Not run. |

## 5. Flow

```
A2/A3 Initial access      B1/B2/B3 Execution      C1/C2 Persistence      D1 Cred access      E1/E2/E3 Exfiltration
(Quick Assist, bat)  -->  (cmd, enc PowerShell) -->  (Run key, service) --> (LSASS test)  -->  (stage, zip, upload)
                                                                                                      |
                                                                                   [ encryption OUT of scope ]
```

![Emulation flow](images/emulation_flow.png)

## 6. Mapping to our other weeks

- Every technique here comes from our **Week 4** Kill Chain mapping (we use a subset).
- Every detection column reuses our **Week 5** hunts (H1 encoded PowerShell + service, H3 LSASS + vssadmin).
- **Week 6:** the techniques use the same ATT&CK v20 names as our Navigator layer. Step D1 is the technique we studied there (T1003.001).
- **Week 7:** step D1 is also checked with the CAR analytic **CAR-2020-05-001** in ELK.
- **Week 9:** we will run the Atomic Red Team tests listed here and record the results in ELK.
- So this week closes the loop: Week 4 *described* the attack, Week 5 *hunted* for it on borrowed data,
  Weeks 8–9 **recreate the behaviour ourselves** to prove the hunts fire on data we generate.

## 7. Success criteria (how we grade our own run)

A step "passes" if, after we run it, the matching Week 5 hunt or ELK query shows the event. Target: at
least **B2, C2, D1, E3** detected. These four are the highest-value, hardest-to-hide steps (top of the
Pyramid of Pain).

## 8. How to run (lab)

1. Snapshot both VMs.
2. Confirm Sysmon + PowerShell logging ship to ELK (Week 5 stack).
3. Build the abilities in CALDERA, **or** run the listed Atomic Red Team tests by ID, in order A→E.
4. After each phase, check ELK: the Week 5 queries (`week05/queries/kibana_kql.md`) and the Week 7 CAR query (`week07/queries/car_2020_05_001.md`).
5. Record "detected? y/n" per step.
6. Revert VMs from snapshot.

## 9. Sources

1. CISA, *#StopRansomware: Black Basta*, AA24-131A.
2. MITRE ATT&CK — Black Basta (S1070), Storm-1811 / groups G1046; technique pages.
3. MITRE Engenuity Center for Threat-Informed Defense — Adversary Emulation Library and method.
4. MITRE CALDERA documentation (adversary profiles, abilities).
5. Red Canary — Atomic Red Team (test IDs referenced per step).
6. Microsoft Threat Intelligence and Rapid7 — Storm-1811 / Black Basta, May 2024.
7. MITRE CAR, CAR-2020-05-001 and CAR-2021-01-009.
8. Our Weeks 1, 4, 5, 6 and 7 materials.
