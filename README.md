# CTI Investigation of the Black Basta Ransomware Attack Chain

Course: Introduction to Threat Hunting, Astana IT University, 2026–2027

Team: Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev

## Goal

Study how Black Basta attacks work, from phishing to encryption, using threat intelligence, and make materials to detect them.

## Structure

| Folder | Week | Topic |
|---|---|---|
| [week01](week01/) | 1 | CTI fundamentals: glossary, threat classification, threat profile |
| [week02](week02/) | 2 | Data collection: OSINT with VirusTotal, Shodan, Maltego; data source mapping |
| [week03](week03/) | 3 | Data processing: normalization script, MISP (Assignment 1) |
| [week04](week04/) | 4 | The Cyber Kill Chain mapped to ATT&CK (Assignment 2) |
| [week05](week05/) | 5 | Threat hunting: hypotheses and hunt queries in ELK (Assignment 3) |
| [week06](week06/) | 6 | ATT&CK framework: T1003.001, mapping, Navigator layer (Assignment 4, part 1) |
| [week07](week07/) | 7 | MITRE CAR: CAR-2020-05-001 in ELK (Assignment 4, part 2) |
| [week08](week08/) | 8 | Adversary emulation plan (Assignment 5) |

Each week folder has its own README with the syllabus task and a list of files.

## Weekly log

- Week 1 - Glossary of CTI terms, threat classification, Black Basta threat profile
- Week 2 - OSINT collection: 21 IOCs from CISA AA24-131A, checks in VirusTotal, Shodan and Maltego, data source mapping
- Week 3 - Normalization with Python (normalize.py), MISP deployment in Docker, MISP event with 21 attributes, galaxy and TLP tags, export to CSV/JSON
- Week 4 - Cyber Kill Chain analysis of a real Black Basta attack (Storm-1811, 2024): 35 steps mapped to 34 ATT&CK techniques, Python script, diagram, ATT&CK Navigator layer, courses of action
- Week 5 - Hypothesis-driven hunt: 3 hypotheses (encoded PowerShell, download tools, LSASS/vssadmin), queries in Kibana (ELK), run on 24,194 events from OTRF Security-Datasets: 7 hits, one confirmed lateral movement with C2
- Week 6 - Studied T1003.001 LSASS Memory; mapped the Week 5 findings to 12 ATT&CK v20 techniques in 6 tactics; ATT&CK Navigator layer
- Week 7 - CAR-2020-05-001 (MiniDump of LSASS) in Kibana and Python: 1 hit, 0 false positives; compared with the Week 5 filter (2 hits); mapped to ATT&CK
- Week 8 - Safe, lab-only emulation plan of the Black Basta / Storm-1811 chain: 5 phases, 12 techniques, each with a detection from Weeks 5 and 7

## Sources

- CISA AA24-131A #StopRansomware: Black Basta
- MITRE ATT&CK
- VirusTotal, Shodan, Maltego (VirusTotal Public API transforms)
- MISP and the CIRCL OSINT feed
- Lockheed Martin Cyber Kill Chain (Hutchins, Cloppert, Amin)
- Microsoft Threat Intelligence and Rapid7 reports on Storm-1811 / Black Basta (May 2024)
- OTRF Security-Datasets (Windows attack logs)
- MITRE CAR, MITRE CALDERA, Atomic Red Team
- Lectures 1, 2, 3 and 4

## AI use

We used AI (Claude). We wrote the text in our own words; Claude checked grammar and clarity and helped us analyze the data. We checked all facts against the CISA advisory and the lectures. In week 4, Claude also helped find the reports, draft the mapping and the report text, and write the script (see the AI use section in week04/report.md). In week 5, Claude helped find the datasets and write the scripts, queries and report draft (see week05/report.md).
