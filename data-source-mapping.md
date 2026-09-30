# Data Source Mapping — Black Basta

If Black Basta attacked our organization, this table shows which logs would reveal each step of the attack.

| Attack step | What the attacker does | Where you would see it (log / data source) | Example event |
|---|---|---|---|
| Initial access | Phishing email with a link or attachment | Email gateway logs, proxy logs | Suspicious sender, risky attachment type |
| Execution | Runs PowerShell / scripts | Sysmon, PowerShell logs | Sysmon ID 1; PowerShell 4104 |
| Credential access | Dumps passwords (Mimikatz) | Sysmon | Sysmon ID 10 (access to lsass.exe) |
| Lateral movement | RDP, PsExec | Windows Security, System logs | 4624 logon type 10; 7045 new service |
| Exfiltration | Uploads data with Rclone | Firewall / proxy logs, Sysmon | Sysmon ID 3; large outbound traffic |
| Inhibit recovery | Deletes shadow copies | Sysmon / process creation logs | Sysmon ID 1 or 4688: `vssadmin delete shadows` |
| Impact | Encrypts files | Sysmon, EDR | Sysmon ID 11: many new files with the same extension |

## Conclusion

Process creation logs (Sysmon event ID 1 or Windows event 4688) are the most valuable single data source. With command lines they show execution through PowerShell, tools such as PsExec and Rclone, and the deletion of shadow copies with vssadmin, so one source covers several steps of the attack.

Network data (firewall, proxy and DNS logs) is needed for phishing links, Cobalt Strike beaconing and data exfiltration. The IP addresses and domains collected in week 2 can be matched against these logs directly, although they become outdated quickly.

Windows Security and System logs (4624 logon type 10, 7045) reveal RDP and PsExec lateral movement, and Sysmon event 10 reveals attempts to read lsass.exe. File encryption (Sysmon 11) is visible only at the very end of the chain, so effective threat hunting has to detect the earlier steps.

## Sources

1. CISA AA24-131A — #StopRansomware: Black Basta
2. Lecture 2 slides
