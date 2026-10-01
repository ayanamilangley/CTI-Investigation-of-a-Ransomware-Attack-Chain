# Data Source Mapping — Black Basta

A log is a record of what happens on a computer or in a network. This table shows where we would see each step of a Black Basta attack if it happened in our organization.

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

The most useful log is the one that records which programs start and with which commands (Sysmon event 1 or Windows event 4688). It shows PowerShell scripts, tools like PsExec and Rclone, and the deletion of shadow copies, so one log covers several steps of the attack.

Network logs (firewall, proxy, DNS) are needed to see phishing links, Cobalt Strike connections and data being sent out. The IPs and domains I collected this week can be searched in these logs, but they get old quickly.

Windows Security and System logs show RDP and PsExec logins to other computers (4624 with logon type 10, 7045), and Sysmon event 10 shows when something tries to read lsass.exe to steal passwords. Encrypting the files (Sysmon 11) is the last step, so by then it is already late. That is why it is better to catch the earlier steps.

## Sources

1. CISA AA24-131A — #StopRansomware: Black Basta
2. Lecture 2 slides
