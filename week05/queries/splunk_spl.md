# Hunt queries for Splunk (SPL)

The same hunts as in [kibana_kql.md](kibana_kql.md), for teams that use Splunk.
Upload the JSON files from `../data/*.zip` (unzip first) with **Settings → Add Data → Upload**,
source type `_json`, index `blackbasta`. Time range: **All time**.

## H1 — Suspicious PowerShell

```spl
index=blackbasta EventID=1 Channel="Microsoft-Windows-Sysmon/Operational" Image="*\\powershell.exe"
| where match(CommandLine, "(?i)\s-e(nc|ncodedcommand)?\s") OR (match(CommandLine, "(?i)-w(indowstyle)?\s+(hidden|1)") AND match(CommandLine, "(?i)-nop"))
| table _time Hostname User ParentImage CommandLine
```

Pivot (same host, service install and network):

```spl
index=blackbasta Hostname="WORKSTATION6*" (EventID=7045 OR EventID=4697 OR (EventID=3 Image="*\\powershell.exe"))
| table _time Hostname EventID ServiceName ImagePath ServiceFileName Image DestinationIp DestinationPort
```

## H2 — Built-in tools downloading files

```spl
index=blackbasta EventID=1 Channel="Microsoft-Windows-Sysmon/Operational"
| eval exe=lower(mvindex(split(Image,"\\"),-1))
| where (in(exe,"curl.exe","bitsadmin.exe","certutil.exe") AND match(CommandLine,"(?i)https?://"))
     OR (exe="powershell.exe" AND match(CommandLine,"(?i)downloadstring|downloadfile|net\.webclient|invoke-webrequest|start-bitstransfer"))
| table _time Hostname exe ParentImage CommandLine
```

Storm-1811 version — Quick Assist, then a download tool on the same host within 10 minutes:

```spl
index=blackbasta EventID=1
| eval exe=lower(mvindex(split(Image,"\\"),-1))
| where in(exe,"quickassist.exe","curl.exe","bitsadmin.exe","certutil.exe")
| eval qa_time=if(exe="quickassist.exe",_time,null())
| sort 0 Hostname _time
| streamstats last(qa_time) as last_qa by Hostname
| where exe!="quickassist.exe" AND _time-last_qa<=600
| table _time Hostname exe CommandLine last_qa
```

## H3 — Credential theft and backup tampering

```spl
index=blackbasta EventID=1 Channel="Microsoft-Windows-Sysmon/Operational"
| eval exe=lower(mvindex(split(Image,"\\"),-1)), cl=lower(CommandLine)
| where (exe="vssadmin.exe" AND like(cl,"%shadow%"))
     OR (exe="wmic.exe" AND like(cl,"%shadowcopy%delete%"))
     OR (exe="rundll32.exe" AND like(cl,"%comsvcs%") AND like(cl,"%minidump%"))
| eval verdict=case(like(cl,"%delete%"),"T1490 backups destroyed", like(cl,"%create%"),"T1003.003 NTDS theft", true(),"T1003.001 LSASS dump")
| table _time Hostname exe ParentImage CommandLine verdict
```

LSASS access:

```spl
index=blackbasta EventID=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1fffff","0x1010","0x1410","0x143a","0x1438")
  NOT SourceImage IN ("*\\MsMpEng.exe","*\\svchost.exe","*\\wmiprvse.exe","*\\csrss.exe","*\\wininit.exe","*\\services.exe")
| stats count by Hostname SourceImage GrantedAccess
```

Note: we tested the hunt logic with our Python script. We did not run these SPL queries in a real Splunk instance; they are given for comparison.
