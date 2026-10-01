# Week 3 — Data Processing and Exploitation (Assignment 1)

**Syllabus task:** Deploy MISP and import IOCs. Apply filtering and normalization techniques to collected data.

**CTI lifecycle stage:** Processing.

| File | What is inside |
|---|---|
| [report.md](report.md) | The assignment report |
| [scripts/normalize.py](scripts/normalize.py) | Refangs, classifies, lowercases and filters the raw IOCs |
| [data/iocs_clean.csv](data/iocs_clean.csv) | 21 clean indicators (output of the script) |
| [exports/](exports/) | MISP event export (CSV and JSON) |
| [screenshots/](screenshots/) | MISP dashboard, event, attributes, galaxy, correlation graph |

**Main result:** MISP 2.5 in Docker with one event "Black Basta Ransomware IOCs – CISA AA24-131A": 21 attributes, TLP:CLEAR, BlackBasta galaxy, exported as CSV and JSON.
