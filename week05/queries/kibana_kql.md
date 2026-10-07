# Hunt queries for Kibana (KQL)

Index / data view: `blackbasta-hunt` (load it with [`../elk/load_to_elk.py`](../elk/load_to_elk.py)).
Time range in Discover: **Last 10 years** (the datasets were recorded in 2020 and 2023).
All fields are lowercase-normalized, so write values in lowercase.

Useful columns to add in Discover: `Hostname`, `EventID`, `Image`, `ParentImage`, `CommandLine`, `User`, `dataset`.

## H1 — Suspicious PowerShell (encoded command or hidden window)

```
EventID:1 and Channel:"microsoft-windows-sysmon/operational" and Image:*powershell.exe
  and (CommandLine:*-enc* or CommandLine:*-encodedcommand* or (CommandLine:*-w*hidden* and CommandLine:*-nop*))
```

Expected: 1 hit, `WORKSTATION6`, `powershell -noP -sta -w 1 -enc …`, user `NT AUTHORITY\SYSTEM`, parent `cmd.exe`.

**Pivot 1 — what started it?** (process tree, same host)

```
Hostname:workstation6* and EventID:1
```

**Pivot 2 — new service and network around the same time** (PsExec-style remote service, C2)

```
Hostname:workstation6* and (EventID:7045 or EventID:4697 or (EventID:3 and Image:*powershell.exe))
```

Expected: service `Updater` (7045 / 4697) and `powershell.exe` → `10.10.10.5:80`.

## H2 — Built-in tools downloading files

```
EventID:1 and Channel:"microsoft-windows-sysmon/operational"
  and ((Image:(*curl.exe or *bitsadmin.exe or *certutil.exe) and CommandLine:*http*)
    or (Image:*powershell.exe and CommandLine:(*downloadstring* or *downloadfile* or *webclient* or *invoke-webrequest* or *start-bitstransfer*)))
```

Expected: 1 hit (`bitsadmin.exe /transfer … https://raw.githubusercontent.com/…`).
The Empire download is **not** found by KQL, because it is hidden inside the base64 `-enc` text. Our Python script decodes it and finds it (see the report, section 6).

**Storm-1811 version (Quick Assist first, then a download tool):**

```
EventID:1 and Image:(*quickassist.exe or *curl.exe or *bitsadmin.exe or *certutil.exe)
```

Then sort by `Hostname` and `@timestamp`: a `quickassist.exe` start followed by `curl.exe` on the same host within ~10 minutes is the pattern from Week 4. In our datasets Quick Assist never appears (0 results).

## H3 — Credential theft and backup tampering

```
EventID:1 and Channel:"microsoft-windows-sysmon/operational"
  and ((Image:*vssadmin.exe and CommandLine:*shadow*)
    or (Image:*wmic.exe and CommandLine:*shadowcopy*delete*)
    or (Image:*rundll32.exe and CommandLine:*comsvcs* and CommandLine:*minidump*))
```

Expected: 2 hits — `vssadmin.exe create shadow /for=C:` on `DC01` and `rundll32 comsvcs.dll MiniDump` on `WORKSTATION5`.

**LSASS memory access (Sysmon 10):**

```
EventID:10 and TargetImage:*lsass.exe
  and GrantedAccess:(0x1fffff or 0x1010 or 0x1410 or 0x143a or 0x1438)
  and not SourceImage:(*msmpeng.exe or *svchost.exe or *wmiprvse.exe or *csrss.exe or *wininit.exe or *services.exe)
```

Expected: 2 hits, `rundll32.exe` with `0x1fffff` and `0x1410`.
Without the `GrantedAccess` filter you get 184 events (150 are `vboxservice.exe`, a normal VirtualBox tool).
