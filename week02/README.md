# Week 2 — Data Collection Process

**Syllabus task:** Perform OSINT data collection using Shodan, VirusTotal and Maltego. Develop a data source mapping for analysis.

**CTI lifecycle stage:** Collection.

| File | What is inside |
|---|---|
| [iocs_raw.txt](iocs_raw.txt) | 21 IOCs from CISA AA24-131A (15 hashes, 4 IPs, 2 domains), with source and date |
| [osint-findings.md](osint-findings.md) | Results from VirusTotal, Shodan and Maltego, key observations, source evaluation |
| [data-source-mapping.md](data-source-mapping.md) | Which logs show each step of a Black Basta attack (Sysmon / Windows event IDs) |
| [../images/](../images/) | Screenshots used in the findings |


**Main result:** most 2024 IPs are no longer linked to Black Basta, while hashes and one domain are still flagged. This shows the Pyramid of Pain in real data: detect behavior (TTPs), not only IOCs.
