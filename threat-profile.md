# Threat Profile: Black Basta

Project: CTI Investigation of the Black Basta Ransomware Attack Chain

Author: Botakoz Berikkyzy, Timur Aktayev, Alina Ashirova

## ID card

- Type: criminal group, ransomware-as-a-service
- First seen: April 2022
- Goal: money (double extortion)
- Victims: more than 500 organizations
- Sectors: 12 of 16 US critical infrastructure sectors, including healthcare
- Regions: North America, Europe, Australia
- How they get in: phishing emails, ScreenConnect bug (CVE-2024-1709), stolen passwords, fake IT support on Teams
- Main tools: Mimikatz, Cobalt Strike, PsExec, RDP, Backstab, Rclone, vssadmin
- Encryption: ChaCha20 + RSA-4096; files get ".basta" ending; note "readme.txt"
- Contact: .onion link; 10–12 days to pay
- Status now: their private chats leaked in February 2025. Since then they are mostly inactive.

## Attack chain

1. Get in: phishing email, software bug, stolen password, or fake IT support call.
2. Look around: scan the network with SoftPerfect Network Scanner. Tools are renamed to look like "Intel" or "Dell" files.
3. Become admin: steal passwords with Mimikatz. Use old Windows bugs (ZeroLogon, NoPac, PrintNightmare).
4. Turn off security: turn off antivirus with PowerShell and the Backstab tool.
5. Spread: move to other computers with Cobalt Strike, PsExec and RDP.
6. Steal data: copy data to the attacker's cloud storage with Rclone.
7. Lock everything: delete backups with vssadmin, encrypt files, leave "readme.txt".

## ATT&CK techniques

|    ID     |             Technique                 |      How Black Basta used it     |
|-----------|---------------------------------------|----------------------------------|
| T1566     |             Phishing                  |         Phishing emails          |
| T1190     | Exploit Public-Facing Application     |         ScreenConnect bug        |
| T1059.001 |              PowerShell               |        Turns off antivirus       |
| T1068     | Exploitation for Privilege Escalation |    ZeroLogon, PrintNightmare     |
| T1003     |         OS Credential Dumping         |               Mimikatz           |
| T1036cc   |          Masquerading                 |    Tools named "Intel", "Dell"   |
| T1562.001 |        Disable or Modify Tools        |              Backstab            |
| T1537     |    Transfer Data to Cloud Account     |               Rclone             |
| T1490     |          Inhibit System Recovery      |      vssadmin deletes backups    |
| T1486c    |     Data Encrypted for Impact         |            Encrypts files        |

## Hunting idea (Lecture 1, slide 19)

- Intelligence: Black Basta deletes backups before locking files.
- ATT&CK: T1490 Inhibit System Recovery.
- Hypothesis: "If Black Basta is in our network, we may find vssadmin deleting backups."
- Where to look: computer process logs (EDR / Sysmon).

## Sources

1. CISA AA24-131A #StopRansomware: Black Basta — https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
2. Picus Security — Black Basta analysis — https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a
3. BleepingComputer — Black Basta chats leak (Feb 2025) — https://www.bleepingcomputer.com/news/security/black-basta-ransomware-gang-s-internal-chat-logs-leak-online/
4. MITRE ATT&CK — Black Basta (S1070) — https://attack.mitre.org/software/S1070/
5. Lecture 1 "Cyber Threat Intelligence Fundamentals", slide 19
