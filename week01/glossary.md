# Week 1 — Glossary

Project: CTI Investigation of the Black Basta Ransomware Attack Chain

Author: Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev 

## 1. Basics

### Threat
**Definition:** Anything that can cause harm to computers or data. It can be a person, a group, or malware.

**Black Basta example:** Black Basta is a threat to hospitals and companies. It can stop their work by locking their computers.

**Source:** NIST glossary

### Vulnerability
**Definition:** A weakness in software or settings. Attackers use it to get in or to get more access to data.

**Black Basta example:** Black Basta used a bug in ConnectWise ScreenConnect (CVE-2024-1709) to get in.

**Source:** NIST glossary; CISA advisory

### Risk
**Definition:** How likely an attack is, and how bad the damage would be.

**Black Basta example:** A hospital with an old, unpatched ScreenConnect and no backups has high risk.

**Source:** NIST glossary

### Threat actor
**Definition:** The person or group who attacked. We describe them by their goals, skills and targets.

**Black Basta example:** Black Basta is a criminal group. It wants money. It has been active since April 2022.

**Source:** Lecture 1, slide 8; CISA advisory

### Attack vector
**Definition:** The way an attacker gets in. For example: an email, a software bug, or a stolen password.

**Black Basta example:** Black Basta used phishing emails, the ScreenConnect bug, stolen passwords, and fake IT support calls on Microsoft Teams.

**Source:** CISA advisory

### Attack surface
**Definition:** All the places where an attacker could try to get in.

**Black Basta example:** For Black Basta, this included remote access tools (ScreenConnect, RDP) and workers' email and Teams accounts.

**Source:** NIST glossary

## 2. CTI itself

### Cyber Threat Intelligence (CTI)
**Definition:** Data that is collected, processed and analyzed to help us understand attackers: who they are, what they want, and how they attack. It helps us to solve the problem with the best solution and decision. A simple list of bad IP addresses is not intelligence by itself. It needs context and analysis.

**Black Basta example:** The CISA advisory is CTI. It explains who Black Basta is, how they attack, and what we should fix.

**Source:** Lecture 1, slides 7–8

### Data, information, intelligence
**Definition:**
- Data = a raw fact with no context.
- Information = data with context.
- Intelligence = Analyzed information that tells us what to do.

**Black Basta example:** An IP address is data. "This IP is a Black Basta server" is information. "Block this IP and check our logs" is intelligence.

**Source:** Lecture 1, slide 9

### Intelligence lifecycle
**Definition:** The steps to make intelligence. They repeat in a circle:
1. Direction — decide what we want to know
2. Collection — gather data
3. Processing — clean and organize the data
4. Analysis — understand what it means
5. Dissemination — give the results to the people who need them
6. Feedback — check if it helped, then start again

**Black Basta example:** In our project, Week 1 is direction, Week 2 is collection, and Week 3 is processing.

**Source:** Lecture 1, slide 21

## 3. Levels of CTI

### Strategic intelligence
**Definition:** Big-picture intelligence for managers. It has no technical details.

**Black Basta example:** "Groups like Black Basta attacked 12 of 16 critical infrastructure sectors. We need money for backups."

**Source:** Lecture 1, slide 6

### Operational intelligence
**Definition:** Intelligence about a specific attack campaign: who, when and how.

**Black Basta example:** From May to October 2024, Black Basta sent a lot of spam to people, then called them on Teams pretending to be IT support.

**Source:** Lecture 1, slide 6; CISA advisory

### Tactical intelligence
**Definition:** Intelligence about how attackers behave (TTPs). Security teams use it to build detections.

**Black Basta example:** Black Basta uses Rclone to steal data. We can make an alert for Rclone.

**Source:** Lecture 1, slide 6

### Technical intelligence
**Definition:** Exact technical clues, like IP addresses, domains and file hashes. They are useful, but they get old quickly.

**Black Basta example:** The IP addresses and domains in the CISA advisory. We can block them in the firewall.

**Source:** Lecture 1, slide 6

## 4. Evidence

### IOC (Indicator of Compromise)
**Definition:** A clue that shows a computer or network may be hacked. Examples: malicious IP addresses, domains, malware file hashes.

**Black Basta example:** The advisory lists Black Basta server IPs. If we find them in our logs, we may be hacked.

**Source:** Lecture 1, slide 11

### IOA (Indicator of Attack)
**Definition:** A sign that an attack is happening now. It looks at what the attacker does, not at a specific file or IP.

**Black Basta example:** If a program deletes backups and then many files get new names, ransomware may be running.

**Source:** CrowdStrike, "IOA vs IOC"

### TTP (Tactics, Techniques, Procedures)
**Definition:** How an attacker behaves.
- Tactic = WHY (the goal)
- Technique = HOW (the method)
- Procedure = the exact details

**Black Basta example:** Goal: steal passwords. Method: take them from memory. Details: use the Mimikatz tool.

**Source:** Lecture 1, slide 12

### Pyramid of Pain
**Definition:** A pyramid showing which clues are easy or difficult for attackers to change. From easy to hard: file hashes, IP addresses, domains, network/host artifacts, tools, TTPs. TTPs are the hardest to change, so detecting them is the most useful.

**Black Basta example:** If we block one Black Basta file hash, they just make a new one. If we detect their behavior (turning off antivirus, stealing data with Rclone, deleting backups), they must change how they work. That is hard for them.

**Source:** Lecture 1, slide 20

## 5. Ransomware world

### Ransomware
**Definition:** Malware that locks files and asks for money to unlock them.

**Black Basta example:** Black Basta locks files, adds ".basta" to the file names, and leaves a note called "readme.txt".

**Source:** CISA advisory

### RaaS (Ransomware-as-a-Service)
**Definition:** Criminals make ransomware and rent it to other criminals ("affiliates"). They share the money.

**Black Basta example:** CISA says Black Basta is RaaS. Its affiliates attacked over 500 organizations.

**Source:** CISA advisory

### Initial Access Broker
**Definition:** A criminal who breaks into companies or steals passwords, then sells that access to other criminals.

**Black Basta example:** Black Basta used stolen or bought passwords to get in.

**Source:** Picus Security article

### Double extortion
**Definition:** Attackers steal the data and also lock it. Then they say: "Pay, or we will publish your data."

**Black Basta example:** Black Basta copied data with Rclone, then locked the files. Victims had 10–12 days to pay.

**Source:** CISA advisory

### Leak site
**Definition:** A website on the dark web where criminals publish stolen data to pressure victims.

**Black Basta example:** Black Basta's leak site was called "Basta News".

**Source:** CISA advisory

## 6. Frameworks

### MITRE ATT&CK
**Definition:** A free online list of real attacker methods. Each method has an ID, like T1566. It gives everyone the same language to describe attacks.

**Black Basta example:** Black Basta used T1566 Phishing and T1486 Data Encrypted for Impact.

**Source:** Lecture 1, slides 13–17

### OSINT (Open Source Intelligence)
**Definition:** Intelligence made from public information, like reports, news and websites. Public does not mean always true, have to check that.

**Black Basta example:** This whole project uses OSINT: the CISA advisory, security blogs and news.

**Source:** Lecture 2, slides 7 and 9

## Sources

- CISA AA24-131A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
- NIST glossary: https://csrc.nist.gov/glossary
- CrowdStrike, IOA vs IOC: https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/ioa-vs-ioc/
- Picus Security: https://www.picussecurity.com/resource/blog/black-basta-ransomware-analysis-cisa-alert-aa24-131a
- MITRE ATT&CK: https://attack.mitre.org
- Lecture 1 and Lecture 2
