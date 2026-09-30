# Week 1 — Threat Classification

Project: CTI Investigation of the Black Basta Ransomware Attack Chain

Author: Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev

## Part A — Who attacks and why

### Cybercriminals
- Goal: money
- Attacks: ransomware, fraud
- Example: Black Basta

### Nation-state (APT)
- Goal: spying, damage
- Attacks: long, hidden attacks
- Example: APT29 — SolarWinds attack, 2020

### Hacktivists
- Goal: political message
- Attacks: DDoS, website defacement, leaks
- Example: Anonymous — attacks on Russian government websites, 2022

### Insiders
- Goal: revenge, money, or mistakes
- Attacks: stealing data
- Example: Tesla, 2023 — two ex-workers leaked data about 75,000 employees

### Script kiddies
- Goal: fun, fame
- Attacks: ready-made tools
- Example: Mirai botnet, 2016 — made by students

Note: The goal changes the attack. Criminals want fast money, so they lock files. Nation-states want to stay hidden. Hacktivists want attention.

## Part B — Types of attacks

- Malware — harmful software (ransomware, trojans, worms, spyware). Black Basta: ransomware, Qakbot, Cobalt Strike.
- Phishing / social engineering — tricking people with emails, calls or messages. Black Basta: emails and fake IT support calls.
- Exploiting vulnerabilities — using software bugs to get in. Black Basta: ScreenConnect bug, ZeroLogon, PrintNightmare.
- Credential theft — stealing passwords. Black Basta: Mimikatz, stolen passwords.
- DDoS — sending too much traffic so a website stops working. Black Basta: no.
- Supply chain attack — hacking a supplier to reach its customers. Black Basta: no.

## Part C — Where information comes from

Lecture 1 (slide 21) names 3 types of sources:
- Internal — our own logs and network traffic
- Technical — threat feeds, vulnerability databases
- Human — dark web, forums, social media

Open sources (free, public):
- CISA, ENISA — official reports about threats
- Security company blogs — detailed analysis
- VirusTotal — checks if a file, IP or domain is bad
- Shodan — shows devices connected to the internet
- abuse.ch — free lists of malware and bad URLs
- MITRE ATT&CK — list of attacker techniques

Closed sources (paid or private):
- Paid threat feeds — fresh, checked threat data
- ISACs (sharing groups) — information shared between companies in one sector
- Our own logs — show if WE were really attacked

Why both matter: Open sources are free, but they can be old or wrong. Closed sources are better quality, but cost money. Only our own logs show if we were attacked. (Lecture 2, slides 9–10, 16)

How to check a source (Lecture 2, slide 17): Is it relevant? Reliable? Recent? Confirmed by another source? Specific? Biased? Can we trace where it came from?

Example: The CISA advisory is reliable, but it is from 2024, so it is not very recent.

## Where Black Basta fits

Black Basta is a cybercriminal group. It only wants money. It has worked as ransomware-as-a-service since April 2022. It uses double extortion: it steals data, locks it, and threatens to publish it on "Basta News". It uses phishing, software bugs, stolen passwords and ransomware. It does not use DDoS or supply chain attacks. The best source about it is the CISA advisory.

## Sources

- CISA AA24-131A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
- Lecture 1, slide 21; Lecture 2, slides 9–10, 16–17
