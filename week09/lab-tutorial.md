# Week 9 — step-by-step lab tutorial (Atomic Red Team)

**Read this top to bottom. Do every step on a throwaway Windows VM only.**
Time: about 2 hours. When you finish you will have one file (`atomic_logs.zip`) and a few
screenshots to send back, and the report gets filled with your real numbers.

> **Safety (from our Week 8 Rules of Engagement).** Do this on an **isolated VM you own**.
> No real company, no real passwords, no internet target. Take a **VM snapshot before you start**
> and **revert it at the end**. We never run encryption. We dump LSASS on a **test account only**.

---

## 0. What you need

- A **Windows 10 or 11 virtual machine** (VirtualBox or VMware). Free Microsoft dev VMs:
  https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/
- The VM set to **Host-only / internal network** (no bridge to your real network).
- **4 GB RAM** free for the VM, plus space for Docker.
- Admin rights inside the VM.

If you already have a Windows VM with Sysmon, skip to step 3 — but check step 2 (the LSASS logging fix), because that is the one most people get wrong.

Everything runs **inside the VM**: Sysmon, Atomic Red Team, and the ELK stack (Docker Desktop).
You do not need a second machine.

---

## 1. Prepare the VM

1. Start the VM. **Take a snapshot now** and name it `clean`.
   - VirtualBox: *Machine → Take Snapshot*. VMware: *VM → Snapshot → Take Snapshot*.
2. Open **PowerShell as Administrator** (right-click → Run as administrator). Keep this window for the whole lab.
3. Allow scripts for this session:
   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass -Force
   ```
4. Copy the `week09` folder from our repo into the VM, for example to `C:\week09`.
   (Download the repo as a ZIP from GitHub, or `git clone` it inside the VM.)

---

## 2. Turn on the logs (the important step)

Our detections read five Windows logs: Sysmon **1, 3, 10, 11, 13**, PowerShell **4104**, and Security **4688 / 7045 / 4697 / 4657**. Turn them all on:

**a) Install Sysmon with our config** (this one logs LSASS access — Event 10 — which the normal SwiftOnSecurity config does **not**):
```powershell
# download Sysmon
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon -Force
# install with OUR config (ships in week09/config/)
C:\Sysmon\Sysmon64.exe -accepteula -i C:\week09\config\sysmon-week9.xml
```

**b) Turn on PowerShell Script Block Logging (Event 4104):**
```powershell
$p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $p -Force | Out-Null
Set-ItemProperty $p EnableScriptBlockLogging 1
```

**c) Turn on process-creation auditing with command line (Event 4688), service and registry auditing (7045 / 4697 / 4657):**
```powershell
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
auditpol /set /subcategory:"Security System Extension" /success:enable | Out-Null
auditpol /set /subcategory:"Registry" /success:enable | Out-Null
# include the command line in 4688
$k = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item $k -Force | Out-Null
Set-ItemProperty $k ProcessCreationIncludeCmdLine_Enabled 1
```

**Check Sysmon is running and logging Event 10:**
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
```

---

## 3. Install Atomic Red Team

In the same admin PowerShell (from the official Red Canary instructions):
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomics"}
```

> Windows Defender may delete the atomics folder (it looks like hacker tools). For the lab only,
> add an exclusion: *Windows Security → Virus & threat protection → Manage settings → Exclusions →
> Add folder → `C:\AtomicRedTeam`*. This is fine on a throwaway VM. Do **not** disable Defender
> fully — "detection is a must", and we want to see what fires.

Check it works:
```powershell
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
```

---

## 4. Set up the Week 8 lab props

```powershell
# a test account we dump LSASS on (NOT a real user)
net user labadmin P@ssw0rd-Lab-123 /add
# a fake "canary" file to stage and exfil (no real data)
New-Item -ItemType Directory -Force C:\decoy | Out-Null
"FAKE PATIENT RECORDS - EMULATION ONLY - not real data" | Out-File C:\decoy\patient_records.txt
New-Item -ItemType Directory -Force C:\temp\stage | Out-Null
```

---

## 5. Run the atomic tests (in order A → E)

Run each block, wait for it to finish, then run its `-Cleanup`. The pattern for every test is:
**GetPrereqs → run → Cleanup.** The `-GetPrereqs` step downloads any tool the test needs (e.g. ProcDump).

```powershell
# T9-2  PowerShell: encoded command (#15) + obfuscated IEX (#17)   [must-detect B2]
Invoke-AtomicTest T1059.001 -TestNumbers 15,17 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 15,17
Invoke-AtomicTest T1059.001 -TestNumbers 15,17 -Cleanup

# T9-1  Windows Command Shell: batch script (#1)
Invoke-AtomicTest T1059.003 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.003 -TestNumbers 1
Invoke-AtomicTest T1059.003 -TestNumbers 1 -Cleanup

# T9-3  Persistence: Run key (#1)  -- adds then removes a Run value
Invoke-AtomicTest T1547.001 -TestNumbers 1
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup

# T9-4  Persistence: Windows service (#1)   [must-detect C2]
Invoke-AtomicTest T1543.003 -TestNumbers 1
Invoke-AtomicTest T1543.003 -TestNumbers 1 -Cleanup

# T9-5  Credential access: LSASS via comsvcs.dll (#2) + ProcDump (#1)   [must-detect D1]
Invoke-AtomicTest T1003.001 -TestNumbers 1,2 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1,2
Invoke-AtomicTest T1003.001 -TestNumbers 1,2 -Cleanup

# T9-6  Exfil: stage data (#1)
Invoke-AtomicTest T1074.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1074.001 -TestNumbers 1
Invoke-AtomicTest T1074.001 -TestNumbers 1 -Cleanup

# T9-7  Exfil: archive the data (#1)
Invoke-AtomicTest T1560.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1560.001 -TestNumbers 1
Invoke-AtomicTest T1560.001 -TestNumbers 1 -Cleanup
```

**T9-8 (Rclone exfil, must-detect E3).** The real atomic uploads to a cloud account. For safety we do **not** use a real cloud. Instead, prove the same behaviour locally:
```powershell
# download rclone (lab tool), then copy the staged file to a LOCAL folder that stands in for "cloud"
Invoke-WebRequest https://downloads.rclone.org/rclone-current-windows-amd64.zip -OutFile C:\rclone.zip
Expand-Archive C:\rclone.zip C:\rclone -Force
$rc = (Get-ChildItem C:\rclone -Recurse -Filter rclone.exe)[0].FullName
New-Item -ItemType Directory -Force C:\lab_cloud | Out-Null
& $rc copy C:\temp\stage C:\lab_cloud -v
```
This makes the same `rclone.exe` process and file activity our query looks for, with no data leaving the VM. (If your teacher wants the cloud version, set up a local MinIO bucket and point an rclone remote at `http://127.0.0.1:9000` — still inside the lab.)

**T9-9 (optional, shadow copy deletion — closes the Week 7 gap).** This **deletes shadow copies**, so only do it if your snapshot is fresh:
```powershell
Invoke-AtomicTest T1490 -TestNumbers 1 -GetPrereqs   # creates a shadow copy to delete
Invoke-AtomicTest T1490 -TestNumbers 1               # deletes it (CAR-2021-01-009 detects this)
```

**We do NOT run T1486 (encryption).** Instead:
```powershell
"EMULATION_WAS_HERE" | Out-File C:\decoy\EMULATION_WAS_HERE.txt
```

---

## 6. Export the logs

Still in the admin PowerShell:
```powershell
cd C:\week09\scripts
.\export_logs.ps1
```
This writes `C:\week09\scripts\atomic_logs.zip`. **This is the main file to send back.**

---

## 7. See your detections in Kibana (for screenshots)

1. Install **Docker Desktop** in the VM (or use your Week 5 host if it is easier).
2. Start the Week 5 ELK stack and load your new logs. Use the repo folders (clone the whole repo in the VM so `week05` and `week09` sit side by side):
   ```powershell
   cd <repo>\week05\elk
   docker compose up -d           # wait ~2 minutes
   cd <repo>\week09\elk
   python load_to_elk.py ..\scripts\atomic_logs.zip
   ```
3. Open Kibana: http://localhost:5601 → *Stack Management → Data Views → Create data view*.
   Name/pattern `blackbasta-atomic`, timestamp field `@timestamp`.
4. Open **Discover**, set the time range to **Last 1 year**, pick the `blackbasta-atomic` data view.
5. Paste each query from [`queries/atomic_detection_kql.md`](queries/atomic_detection_kql.md) and **take a screenshot** showing the hit count. Add columns `Image`, `CommandLine`, `TargetImage`, `GrantedAccess`, `CallTrace`.

**Screenshots to take (6 is enough):**
- T9-2 encoded PowerShell (Sysmon 1) — must-detect
- T9-4 new service (Security 7045) — must-detect
- T9-5 LSASS: the CAR query, with `CallTrace` showing `dbgcore.dll` — must-detect
- T9-8 rclone (Sysmon 1 + 3) — must-detect
- T9-3 Run key (Sysmon 13)
- T9-9 shadow copy delete (optional)

---

## 8. Build the results table (the numbers for the report)

```powershell
cd C:\week09\scripts
python atomic_analytic.py atomic_logs.zip
```
This writes `week09/results/atomic_results.csv` and `atomic_results.md` — the real "detected yes/no"
per test. (I can also run this for you if you just send me `atomic_logs.zip`.)

---

## 9. Finish

1. **Revert the VM** to the `clean` snapshot. (All the mess is gone.)
2. Send me:
   - `atomic_logs.zip`
   - your 6 screenshots
3. I will: put the numbers in `report.md`, drop the screenshots into `week09/images/`,
   and give you the final files to commit.

---

## If something goes wrong

| Problem | Fix |
|---|---|
| `Invoke-AtomicTest` not found | Re-run the `Import-Module ...` line from step 3. |
| LSASS test gives 0 hits in Kibana | Sysmon Event 10 is off. Re-run step 2a (our config), then re-run the LSASS test. |
| Defender deletes the atomics | Add the `C:\AtomicRedTeam` exclusion (step 3). |
| ProcDump "not recognized" | Run the test with `-GetPrereqs` first. |
| `docker compose` fails | Give the VM ~4 GB RAM; wait 2 min after `up -d`. |
| Nervous about a destructive step | Skip T9-9 (and never run T1486). The other 7 tests are safe and cover the four must-detect steps. |
