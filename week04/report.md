# Week 4 — The Cyber Kill Chain (Assignment 2)

Project: CTI Investigation of the Black Basta Ransomware Attack Chain

Authors: Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev

## 1. Goal

The syllabus task for week 4 is: *"Analyze a real-world cyberattack using the stages of the Kill Chain. Map each stage to corresponding ATT&CK TTPs."*

We analyzed one real Black Basta attack campaign from 2024. We split it into the 7 stages of the Lockheed Martin Cyber Kill Chain and mapped every step to a MITRE ATT&CK technique. Then we used the Kill Chain to find where defenders can break the attack, and we compared the Kill Chain with ATT&CK.

**Result in one sentence:** we mapped 35 attacker steps to 34 ATT&CK techniques. The earliest and cheapest place to stop this attack is stage 3–4, the fake "IT help desk" call and Quick Assist. Our Week 1 hunting idea (vssadmin, T1490) only catches the attack in stage 7, minutes before encryption.

## 2. The Cyber Kill Chain in short

The Cyber Kill Chain was published by Lockheed Martin (Hutchins, Cloppert and Amin, *"Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains"*). It says an intrusion goes through 7 stages, and the attacker must finish all of them. So **the defender only needs to break one link to stop the attack**.

| # | Stage | Meaning (simple words) |
|---|---|---|
| 1 | Reconnaissance | The attacker researches and chooses targets |
| 2 | Weaponization | The attacker prepares the "weapon": payload, tools, infrastructure |
| 3 | Delivery | The weapon is sent to the victim (email, website, USB…) |
| 4 | Exploitation | The attacker's code runs on the victim computer |
| 5 | Installation | A backdoor is installed to stay in the system (persistence) |
| 6 | Command and Control (C2) | The infected computer connects to the attacker's server, and the attacker gets "hands on keyboard" |
| 7 | Actions on Objectives | The attacker does what he came for: steal data, encrypt files |

The paper also gives a **courses of action matrix**: for every stage, the defender can **Detect, Deny, Disrupt, Degrade, Deceive** or **Destroy**. We use this in section 6.

## 3. The real attack we analyzed

**Case:** the Storm-1811 social engineering campaign that deployed Black Basta ransomware (April–June 2024).

Microsoft calls the group behind these attacks **Storm-1811**. It is a financially motivated group, and MITRE ATT&CK lists it as group **G1046**. MITRE says it is "linked to Black Basta ransomware deployment". We chose this case for three reasons:

- It is a **real attack**, described by two companies that responded to real victims: Microsoft (15 May 2024) and Rapid7 (10 May 2024).
- The two reports were written **independently** and describe the same chain. This gives us corroboration (Lecture 2, slide 17).
- It starts with **phishing and fake IT support**. This is the same initial access we described in Week 1, from the CISA advisory.

**What happened, in short.** The attackers sign the victim's email address up to many newsletters, so the inbox fills with spam (email bombing). Then they call the victim, or write in Microsoft Teams, and pretend to be the company IT help desk who will "fix the spam". The victim opens Quick Assist, a remote help tool that is built into Windows, and gives the attacker control. The attacker downloads batch scripts with curl and steals the password. Then he installs Qakbot, Cobalt Strike, ScreenConnect, NetSupport and an SSH backdoor. After that he explores the domain, moves to other computers, and in several cases uses PsExec to run Black Basta ransomware on the whole network.

**Important note.** Rapid7 stopped its cases before ransomware: *"ransomware deployment was not observed in any of the cases Rapid7 responded to"*. Microsoft did see Black Basta deployed with PsExec. The details of stage 7 (Mimikatz, Rclone, vssadmin) come from the CISA advisory. That advisory describes Black Basta attacks in general, not this exact campaign. We mark this in the table.

### Source evaluation (criteria from Lecture 2)

| Source | Relevance | Reliability | Timeliness | Notes |
|---|---|---|---|---|
| Microsoft Threat Intelligence, 15 May 2024 (updated June 2024) | High | High: own incident response | Medium (2024) | Full chain up to Black Basta deployment |
| Rapid7, 10 May 2024 (updated Jan 2025) | High | High: own incident response | Medium | Most technical details; no ransomware observed |
| CISA AA24-131A | High | High: government | Medium | Black Basta in general, used for stage 7 |
| MITRE ATT&CK G1046 / S1070 | High | High, but secondary (summary of the reports above) | High (updated 2026) | Used for the technique IDs |

## 4. Kill Chain analysis

We put every step of the attack into a CSV file, [`data/killchain_mapping.csv`](data/killchain_mapping.csv), with its Kill Chain stage, ATT&CK ID, evidence and source. Our script [`scripts/build_killchain.py`](scripts/build_killchain.py) does the rest:

1. It downloads the official MITRE ATT&CK data (STIX) from GitHub.
2. It checks every ID. All 34 IDs exist in ATT&CK v19 and none is revoked.
3. It adds the official technique name and tactic.
4. It builds the table below, the diagram, and an ATT&CK Navigator layer.

"Reported" means a source describes this step. "Inferred" means we think it happened, but no report says it directly.

![Kill Chain diagram](images/killchain_diagram.png)

| Kill Chain stage | What the attacker did | ATT&CK ID | Technique | ATT&CK tactic | Evidence |
|---|---|---|---|---|---|
| **1. Reconnaissance** | Find employee email addresses (and phone numbers) of the target company | T1589.002 | Gather Victim Identity Information: Email Addresses | Reconnaissance | inferred |
| **2. Weaponization** | Register domains to host payloads (upd7[.]com, upd7a[.]com) | T1583.001 | Acquire Infrastructure: Domains | Resource Development | reported |
|  | Create Microsoft Teams accounts named "Help Desk" / "IT Support" | T1585.003 | Establish Accounts: Cloud Accounts | Resource Development | reported |
|  | Get tools: Qakbot, Cobalt Strike, ScreenConnect, NetSupport, OpenSSH | T1588.002 | Obtain Capabilities: Tool | Resource Development | reported |
|  | Prepare batch scripts that look like a "spam filter update" | T1036 | Masquerading | Stealth | reported |
| **3. Delivery** | Email bombing: sign the victim up to many newsletters | T1667 | Email Bombing | Impact | reported |
|  | Phone call pretending to be the company IT help desk | T1566.004 | Phishing: Spearphishing Voice | Initial Access | reported |
|  | Teams messages and calls from fake help desk accounts | T1566.003 | Phishing: Spearphishing via Service | Initial Access | reported |
|  | Pretend to be IT support so the user trusts them | T1684.001 | Social Engineering: Impersonation | Stealth | reported |
|  | Send links to an EvilProxy phishing page to steal passwords | T1566.002 | Phishing: Spearphishing Link | Initial Access | reported |
| **4. Exploitation** | User opens Quick Assist or AnyDesk and gives full control | T1219.002 | Remote Access Tools: Remote Desktop Software | Command and Control | reported |
|  | User runs the downloaded batch scripts | T1204.002 | User Execution: Malicious File | Execution | reported |
|  | Batch scripts run in cmd.exe | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | reported |
|  | PowerShell window asks for the password and saves it | T1056 | Input Capture | Collection; Credential Access | reported |
|  | Other Black Basta cases: exploit ScreenConnect bug CVE-2024-1709 | T1190 | Exploit Public-Facing Application | Initial Access | reported |
| **5. Installation** | Download more scripts and tools with curl and BITSAdmin | T1105 | Ingress Tool Transfer | Command and Control | reported |
|  | Registry Run keys start the scripts at every logon | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persistence; Privilege Escalation | reported |
|  | OpenSSH renamed to RuntimeBroker.exe to look like Windows | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | Stealth | reported |
|  | Cobalt Strike hidden as 7z.DLL and loaded by real 7zG.exe | T1574.001 | Hijack Execution Flow: DLL | Stealth; Execution | reported |
|  | Cobalt Strike payload is XOR-encoded inside the DLL | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | Stealth | reported |
| **6. Command and Control** | SSH tunnel in an endless loop back to the attacker server | T1572 | Protocol Tunneling | Command and Control | reported |
|  | ScreenConnect and NetSupport keep remote control | T1219.002 | Remote Access Tools: Remote Desktop Software | Command and Control | reported |
|  | Cobalt Strike beacon talks to C2 domains over the web | T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | inferred |
|  | SystemBC proxy hides the C2 traffic | T1090 | Proxy | Command and Control | reported |
|  | Stolen passwords sent out with SCP | T1048.002 | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | Exfiltration | reported |
| **7. Actions on Objectives** | Find domain accounts (domain enumeration) | T1087.002 | Account Discovery: Domain Account | Discovery | reported |
|  | Find domain trusts | T1482 | Domain Trust Discovery | Discovery | reported |
|  | Check if the user is admin with whoami | T1033 | System Owner/User Discovery | Discovery | reported |
|  | Move to other computers with Impacket over SMB | T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | reported |
|  | Copy tools to other computers | T1570 | Lateral Tool Transfer | Lateral Movement | reported |
|  | Dump passwords with Mimikatz | T1003 | OS Credential Dumping | Credential Access | reported |
|  | Steal data with Rclone to cloud storage | T1537 | Transfer Data to Cloud Account | Exfiltration | reported |
|  | Delete shadow copies with vssadmin | T1490 | Inhibit System Recovery | Impact | reported |
|  | Run Black Basta on many computers with PsExec | T1569.002 | System Services: Service Execution | Execution | reported |
|  | Encrypt files and add the .basta extension | T1486 | Data Encrypted for Impact | Impact | reported |

### Notes for each stage

1. **Reconnaissance.** The reports do not describe it. But the attackers needed the victims' email addresses, and for the calls also their phone numbers or Teams accounts. So we mark T1589.002 as *inferred*.
2. **Weaponization.** In this attack there is no classic "weapon", meaning no exploit inside a document. Instead the attackers prepare infrastructure and tools: payload domains (upd7[.]com, upd7a[.]com), Teams accounts with names like "Help Desk", ready-made tools, and batch scripts that look like a "spam filter update". In ATT&CK these belong to the **Resource Development** tactic.
3. **Delivery.** The "weapon" is delivered by a **person**: email bombing, then a phone call or a Teams call from a fake help desk.
4. **Exploitation.** No software bug is exploited. The attacker exploits **trust**: the user opens Quick Assist (Ctrl + Windows + Q), types the code, and gives full control. In other Black Basta cases, CISA reports exploitation of a real bug (ScreenConnect CVE-2024-1709, T1190).
5. **Installation.** The attacker hides OpenSSH as `RuntimeBroker.exe`. He also hides Cobalt Strike as `7z.DLL`, which is loaded by the real `7zG.exe` (DLL side-loading). He adds Registry Run keys for persistence.
6. **Command and Control.** He keeps several channels open at the same time: an SSH tunnel in an endless loop, ScreenConnect and NetSupport, a Cobalt Strike beacon, and the SystemBC proxy. If we block one channel, the attacker still has the others.
7. **Actions on Objectives.** Discovery of the domain, lateral movement with Impacket and PsExec, password dumping, data theft, deleting backups, and encryption.

## 5. ATT&CK Navigator layer

The file [`navigator/blackbasta_storm1811_layer.json`](navigator/blackbasta_storm1811_layer.json) shows all 34 techniques on the ATT&CK matrix, coloured by Kill Chain stage. Every technique has a comment with the step and the source. To view it, open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose **Open Existing Layer → Upload from local**, and select the file.

## 6. How to break the chain: courses of action

The Kill Chain is useful for defenders because it shows where an attack can be stopped. We filled the courses of action matrix from the paper for this attack. Event IDs are the same as in our Week 2 data source mapping (Sysmon 1 = process creation, 3 = network connection, 7 = image loaded, 10 = process access, 13 = registry value set; Windows 7045 = new service).

| Stage | Detect | Deny | Disrupt / Degrade | Deceive |
|---|---|---|---|---|
| 1. Reconnaissance | Hard: it happens outside our network | Do not publish staff emails and phone numbers | — | A fake (canary) email address on the website |
| 2. Weaponization | CTI: put new domains (upd7[.]com…) and fake "Help Desk" tenants into MISP | Block newly registered domains on the proxy | — | — |
| 3. Delivery | Alert when one mailbox receives a flood of sign-up emails | Allow Teams external chat only with trusted organizations | Training: "real IT never calls you first about spam"; call back to verify | — |
| 4. Exploitation | Sysmon 1: `QuickAssist.exe` started, then `curl.exe` / `cmd.exe` | Remove or block Quick Assist and unapproved remote tools (Microsoft's advice) | Phishing-resistant MFA against EvilProxy | — |
| 5. Installation | Sysmon 13: new Run key; Sysmon 1: `RuntimeBroker.exe` outside `C:\Windows\System32`; Sysmon 7: `7z.DLL` loaded from a user folder | Application control: no programs from user folders | EDR tamper protection | — |
| 6. Command and Control | Sysmon 3 / firewall: outbound SSH (port 22) from workstations; ScreenConnect to unknown relays | Block outbound port 22 from workstations | All traffic only through the proxy | — |
| 7. Actions on Objectives | Sysmon 1 / 4688: `vssadmin delete shadows` (our Week 1 hypothesis); 7045: PsExec service; Sysmon 10: access to lsass | Offline or immutable backups | Block process creation from PsExec (Microsoft ASR rule); limit big uploads (Rclone) | Canary files and honeypot shares |

**The main idea:** the attacker needs all 7 stages, and we need only one good control. In this attack, the cheapest controls are in stages 3–4: block Quick Assist, restrict Teams external access, and train users. These controls break the chain before any malware runs.

## 7. Kill Chain vs MITRE ATT&CK

| | Cyber Kill Chain | MITRE ATT&CK |
|---|---|---|
| Made by / year | Lockheed Martin, 2011 | MITRE, public since 2015, updated twice a year (v19 in 2026) |
| Structure | 7 stages in a fixed order | 15 tactics, 222 techniques and 475 sub-techniques (v19, counted by us) |
| Level of detail | High level: *where* we are in the attack | Detailed: *how* exactly the attacker does each step |
| Inside the network | Everything after C2 is one stage ("Actions on Objectives") | Separate tactics: Discovery, Lateral Movement, Credential Access, Exfiltration, Impact… |
| Good for | Explaining an attack, choosing where to defend | Detection rules, threat hunting, comparing groups |

What we learned from mapping a real attack:

1. **The Kill Chain is linear, but this attack is not "classic".** The model expects malware and an exploit. Here the "weapon" is a phone call and the attacker uses normal tools (Quick Assist, AnyDesk, ScreenConnect, OpenSSH, PsExec). Stages 2–4 had to be interpreted: "exploitation" means exploiting the user's trust, not a bug.
2. **Stage 7 is overloaded.** 10 of our 35 steps (29 %) are in "Actions on Objectives". For ransomware, the most dangerous part happens inside the network. The Kill Chain has only one box for it, while ATT&CK splits it into 6 different tactics.
3. **ATT&CK tactics do not match Kill Chain stages one-to-one.** Email bombing (T1667) is under the *Impact* tactic in ATT&CK, but in this attack it was a delivery trick. Remote Desktop Software (T1219.002) appears in two stages: Exploitation (Quick Assist) and C2 (ScreenConnect).
4. **ATT&CK changes over time.** In v19, the tactic *Defense Evasion* was split into *Stealth* and *Defense Impairment*. Some techniques got new IDs. For example, T1562.001 "Disable or Modify Tools", which we used in Week 1, is now revoked and replaced by **T1685**. This is why our script checks every ID against the current data.
5. **Both models are best together.** We use the Kill Chain to see the order of the attack and the best place to stop it, and ATT&CK to write exact detections.

## 8. Connection to previous weeks

- **Week 1:** our hypothesis (vssadmin deleting shadow copies, T1490) is in stage 7, the last step before encryption. The Kill Chain shows it is **too late** to be our only hunt. For the next weeks we propose an earlier hypothesis: *"If Storm-1811/Black Basta is in our network, we may find `QuickAssist.exe` followed by `curl.exe` downloading .bat or .zip files on the same host within a few minutes"* (Sysmon 1, stages 4–5).
- **Week 2:** almost every tool in this attack is legitimate software. Hash IOCs do not help here, like the WinSCP hash in Week 2 that had 0 detections. This is the Pyramid of Pain again: we must detect behavior (TTPs).
- **Week 3:** the domains from the Microsoft and Rapid7 reports (upd7[.]com, upd7a[.]com, greekpool[.]com…) can be added to MISP as a second event, tagged with galaxy G1046 / Storm-1811. Then MISP can correlate them with our first event.

## 9. Limitations

- The chain is built from **several real incidents** described by two companies, not from one victim. We do not have an exact timeline with dates and hours.
- Stage 1 and the Cobalt Strike protocol (T1071.001) are **inferred**. No report describes them directly.
- Part of stage 7 (Mimikatz, Rclone, vssadmin) comes from the CISA advisory about Black Basta **in general**.
- Mapping a step to a stage is partly subjective. For example, sending stolen passwords with SCP could be stage 6 or stage 7.

## 10. How to reproduce

```bash
cd week04/scripts
pip install matplotlib requests
python3 build_killchain.py
# downloads ATT&CK data to week04/data/enterprise-attack.json (~50 MB, not committed)
# writes: data/killchain_mapping_resolved.csv, data/killchain_table.md,
#         images/killchain_diagram.png, navigator/blackbasta_storm1811_layer.json
```

Output of our run (1 October 2026):

```
Mapped 35 steps to 34 unique ATT&CK techniques (33 reported, 2 inferred). Problems: 0
```

## 11. Sources

1. Lockheed Martin — E. Hutchins, M. Cloppert, R. Amin, *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains*: https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf
2. Lockheed Martin — Cyber Kill Chain: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
3. Microsoft Threat Intelligence — *Threat actors misusing Quick Assist in social engineering attacks leading to ransomware* (15 May 2024): https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
4. Rapid7 — *Ongoing Social Engineering Campaign Linked to Black Basta Ransomware Operators* (10 May 2024): https://www.rapid7.com/blog/post/2024/05/10/ongoing-social-engineering-campaign-linked-to-black-basta-ransomware-operators/
5. MITRE ATT&CK — Storm-1811 (G1046): https://attack.mitre.org/groups/G1046/
6. MITRE ATT&CK — Black Basta (S1070): https://attack.mitre.org/software/S1070/
7. MITRE ATT&CK data (STIX), mitre/cti repository: https://github.com/mitre/cti
8. CISA AA24-131A — #StopRansomware: Black Basta: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
9. Lecture 1 (CTI fundamentals, ATT&CK) and Lecture 2 (source evaluation, slide 17)

## AI use

This week we used AI (Claude) more than before: it helped us find the Microsoft and Rapid7 reports, draft the Kill Chain mapping and the text, and write the Python script. We read the original reports ourselves, reviewed and changed the mapping, and checked every technique ID against the official MITRE data with the script.
