# Week 1 — Cyber Threat Intelligence Fundamentals

**Syllabus task:** Create a glossary of key CTI terms. Classify different types of threats and their sources.

**CTI lifecycle stage:** Direction (we decide what we want to know).

| File | What is inside |
|---|---|
| [glossary.md](glossary.md) | About 25 CTI terms, each with a definition, a Black Basta example and a source |
| [threat-classification.md](threat-classification.md) | 5 types of threat actors, 6 types of attacks, open and closed sources of CTI |
| [threat-profile.md](threat-profile.md) | Black Basta "ID card", 7-step attack chain, 10 ATT&CK techniques, hunting hypothesis |

**Main result:** Black Basta is a financially motivated ransomware-as-a-service group (active since April 2022). Our hunting hypothesis: *if Black Basta is in our network, we may find vssadmin deleting shadow copies (T1490) in process logs.*

**Note (added in week 4):** in ATT&CK v19, T1562.001 "Disable or Modify Tools" was revoked and replaced by T1685. See [week04/report.md](../week04/report.md), section 7.
