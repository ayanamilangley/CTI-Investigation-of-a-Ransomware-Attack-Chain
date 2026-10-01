# Week 4 — The Cyber Kill Chain (Assignment 2)

**Syllabus task:** Analyze a real-world cyberattack using the stages of the Kill Chain. Map each stage to corresponding ATT&CK TTPs.

**CTI lifecycle stage:** Analysis.

**Case:** the 2024 Storm-1811 campaign that deployed Black Basta ransomware (email bombing → fake IT help desk call → Quick Assist → Cobalt Strike / SSH backdoor → PsExec → Black Basta). Sources: Microsoft and Rapid7 (May 2024), CISA AA24-131A, MITRE ATT&CK G1046.

| File | What is inside |
|---|---|
| [report.md](report.md) | The assignment report: Kill Chain analysis, ATT&CK mapping, courses of action, Kill Chain vs ATT&CK |
| [data/killchain_mapping.csv](data/killchain_mapping.csv) | Our mapping: 35 attacker steps → Kill Chain stage → ATT&CK ID, evidence, source |
| [scripts/build_killchain.py](scripts/build_killchain.py) | Checks every ID against official ATT&CK data and builds the table, diagram and Navigator layer |
| [data/killchain_mapping_resolved.csv](data/killchain_mapping_resolved.csv) | Script output: mapping with official technique names and tactics |
| [images/killchain_diagram.png](images/killchain_diagram.png) | Diagram: 7 stages with their ATT&CK techniques |
| [navigator/blackbasta_storm1811_layer.json](navigator/blackbasta_storm1811_layer.json) | Layer for the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (Open Existing Layer → Upload from local) |

**Main result:** 35 steps → 34 ATT&CK techniques. The cheapest place to break the chain is stages 3–4 (fake help desk call, Quick Assist). Our Week 1 hypothesis (T1490) only catches the attack in stage 7.

![Kill Chain diagram](images/killchain_diagram.png)
