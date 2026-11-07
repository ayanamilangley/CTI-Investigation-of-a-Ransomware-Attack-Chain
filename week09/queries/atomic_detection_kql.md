# Week 9 — detection queries for the atomic tests (Kibana KQL)

Index / data view: `blackbasta-atomic` (load your exported logs into Elasticsearch, index `blackbasta-atomic`).
Time range in Discover: **Last 1 year**. All text fields are lowercase-normalized, so write values in lowercase.

Each query below is the detection for one atomic test (T9-x). Four of them are our own
Week 5 / Week 7 queries, re-used unchanged — that is the point of Week 9: the hunts we
wrote on *borrowed* data (OTRF) must also fire on data **we generate ourselves**. Five
are new for Week 9.

Useful columns in Discover: `Hostname`, `EventID`, `Image`, `ParentImage`, `CommandLine`, `User`, `TargetImage`, `GrantedAccess`, `CallTrace`, `TargetObject`, `TargetFilename`.

---

## T9-1 — T1059.003 Windows Command Shell (reuse Week 5 H1 idea)

```
EventID:1 and Channel:"microsoft-windows-sysmon/operational"
  and Image:*cmd.exe and (CommandLine:*.bat* or CommandLine:*.cmd* or CommandLine:*/c*)
```

Expect: the `cmd.exe` that runs the batch script, child of `powershell.exe` (Invoke-AtomicTest) or of the batch file.

## T9-2 — T1059.001 PowerShell, encoded / hidden (**reuse Week 5 H1, must-detect B2**)

```
EventID:1 and Channel:"microsoft-windows-sysmon/operational" and Image:*powershell.exe
  and (CommandLine:*-enc* or CommandLine:*-encodedcommand* or (CommandLine:*-w*hidden* and CommandLine:*-nop*))
```

PowerShell Script Block (decode the Base64, like Week 5):

```
EventID:4104 and (ScriptBlockText:*frombase64* or ScriptBlockText:*iex* or ScriptBlockText:*invoke-expression*)
```

Expect: `-EncodedCommand` test (#15) shows in Sysmon 1; the obfuscated `IEX` test (#17) shows in 4104.

## T9-3 — T1547.001 Registry Run Key (new Q1)

```
(EventID:13 and Channel:"microsoft-windows-sysmon/operational" and TargetObject:*currentversion\\run*)
  or (EventID:4657 and ObjectName:*currentversion\\run*)
```

Expect: a value written to `...\Windows\CurrentVersion\Run` (Sysmon 13, or Security 4657 if registry auditing is on). The test's cleanup removes it afterwards.

## T9-4 — T1543.003 Windows Service (**reuse Week 5 H1 pivot 2, must-detect C2**)

```
EventID:7045 or EventID:4697
```

Then pivot to the child process it starts (Week 5 pattern):

```
Channel:"microsoft-windows-sysmon/operational" and EventID:1 and ParentImage:*services.exe*
```

Expect: Security 7045 "a service was installed" (and 4697 if enabled), then an unusual child of `services.exe`.

## T9-5 — T1003.001 LSASS Memory (**reuse Week 7 CAR + Week 5 H3, must-detect D1**)

Week 7 CAR-2020-05-001 (MiniDump CallTrace):

```
EventID:10 and Channel:"microsoft-windows-sysmon/operational"
  and TargetImage:*lsass.exe and (CallTrace:*dbghelp.dll* or CallTrace:*dbgcore.dll*)
```

Week 5 H3 (access mask + command line), same index:

```
(EventID:10 and TargetImage:*lsass.exe
   and GrantedAccess:(0x1fffff or 0x1010 or 0x1410 or 0x143a or 0x1438)
   and not SourceImage:(*msmpeng.exe or *svchost.exe or *wmiprvse.exe or *csrss.exe or *wininit.exe or *services.exe or *vboxservice.exe))
or (EventID:1 and Image:*rundll32.exe and CommandLine:*comsvcs* and CommandLine:*minidump*)
```

Expect: the comsvcs test (#2) gives a Sysmon 10 to `lsass.exe` with `dbgcore.dll` in the CallTrace **and** a Sysmon 1 `rundll32 ... comsvcs.dll MiniDump` line — the same procedure we detected in Weeks 5 and 7. **This needs Sysmon Event 10 to be logged — see lab-tutorial.md, the SwiftOnSecurity warning.**

## T9-6 — T1074.001 Local Data Staging (new Q2, expect noisy)

```
EventID:11 and Channel:"microsoft-windows-sysmon/operational"
  and (TargetFilename:*\\temp\\* or TargetFilename:*\\stage* or TargetFilename:*patient_records*)
```

Expect: several Sysmon 11 file-create events into the staging folder. This is **noisy** (Windows writes to `\temp\` all the time), so in a real detection you would group by folder and count, not alert on one event.

## T9-7 — T1560.001 Archive via Utility (new Q3)

```
EventID:1 and Channel:"microsoft-windows-sysmon/operational"
  and (Image:(*tar.exe or *7z.exe or *7za.exe or *rar.exe or *winrar.exe) or CommandLine:*compress-archive*)
```

Expect: the archiver process on a staging path, just before exfil.

## T9-8 — T1567.002 Exfiltration to Cloud / Rclone (new Q4, **must-detect E3**)

```
(EventID:1 and Image:*rclone.exe)
  or (EventID:1 and CommandLine:*rclone*)
  or (EventID:3 and Channel:"microsoft-windows-sysmon/operational" and Image:*rclone.exe)
```

Expect: `rclone.exe` starting (Sysmon 1) and its outbound connection (Sysmon 3) to **the lab endpoint only**. In the lab we point rclone at our own MinIO / web server, never a real cloud.

## T9-9 — T1490 Inhibit System Recovery (new Q5 = CAR-2021-01-009)

This is the analytic we named as future work in Week 7. Take a **VM snapshot first** (the test deletes shadow copies).

```
(EventID:1 or EventID:4688)
  and (
    (CommandLine:*vssadmin* and CommandLine:*delete* and CommandLine:*shadow*)
    or (CommandLine:*wmic* and CommandLine:*shadowcopy* and CommandLine:*delete*)
    or (CommandLine:*vssadmin* and CommandLine:*resize* and CommandLine:*shadowstorage*)
  )
```

Source: MITRE CAR **CAR-2021-01-009** "Detecting Shadow Copy Deletion or Resize" (process-create command line). Expect: `vssadmin.exe delete shadows /all /quiet` in Sysmon 1 / Security 4688. This closes the Week 7 gap: in Week 5 our data only had `vssadmin create shadow`, never a delete; now we generate the delete ourselves and prove the analytic fires.

---

## Not run (Week 8 rule)

- **T1486 Data Encrypted for Impact** — destructive. We write a marker file `EMULATION_WAS_HERE.txt` instead and do not run any encryption atomic.
