# OSINT Findings — Black Basta

## 1. Goal of the collection

Question: what infrastructure did Black Basta use, and is it still active?

## 2. Results

Data sources: CISA AA24-131A. Hashes come from the initial version (May 2024, Table 7); IPs and domains come from the current version (Nov 2024, Tables 7-8).

### Network indicators (from the advisory)

| IOC | Type | First seen (CISA) | Description (CISA) |
|---|---|---|---|
| 170.130.165[.]73 | ip | Oct 14, 2024 | Likely Cobalt Strike infrastructure |
| 45.11.181[.]44 | ip | Oct 24, 2024 | Likely Cobalt Strike infrastructure |
| 66.42.118[.]54 | ip | Oct 15, 2024 | Exfiltration server |
| 79.132.130[.]211 | ip | Oct 24, 2024 | Likely Cobalt Strike infrastructure |
| Moereng[.]com | domain | Oct 9, 2024 | Suspected Cobalt Strike domain |
| Exckicks[.]com | domain | Oct 2, 2024 | Suspected Cobalt Strike domain |

### Results of my checks

| IOC | Type | Tool | Result | Date checked |
|---|---|---|---|---|
| 0554eb2ffa3582b000d558b6950ec60e876f1259c41acff2eac47ab78a53e94a | sha256 | VirusTotal | 53/70 malicious; label trojan.agentb/blackbasta; EXE, 168.36 KB; tags: spreader, invalid-signature; first submission: 2024-05-09 (screenshots: vt_hash1_exe.png, vt_details_history.png) | 2026-09-29 |
| 90ba27750a04d1308115fa6a90f36503398a8f528c974c5adc07ae8a6cd630e7 | sha256 | VirusTotal | 48/70 malicious; label trojan.pemalform/baster; EXE 64-bit, 2.00 MB; tags: spreader, exploit, cve-2018-8440 (screenshot: vt_hash2_exe.png) | 2026-09-29 |
| 58ddbea084ce18cfb3439219ebcf2fc5c1605d2f6271610b1c7af77b8d0484bd | sha256 | VirusTotal | 57/70 malicious; label ransomware.blackbasta/imps; DLL, 448 KB (screenshot: vt_hash3_dll.png) | 2026-09-29 |
| 96339a7e87ffce6ced247feb9b4cb7c05b83ca315976a9522155bad726b8e5be | sha256 | VirusTotal | 40/64 malicious; label ransomware.blackbasta; ELF 64-bit (Linux), 204.27 KB (screenshot: vt_hash_elf.png) | 2026-09-29 |
| d3683beca3a40574e5fd68d30451137e4a8bbaca8c428ebb781d565d6a70385e | sha256 | VirusTotal | 0 detections; winscp.exe, signed, tagged legit, 25.80 MB (screenshot: vt_hash_winscp.png) | 2026-09-29 |
| 170.130.165[.]73 | ip | VirusTotal | 2/91 malicious (alphaMountain.ai, Sophos), 1 suspicious (Gridinsoft); US; AS 62904 (Eonix Corporation); network 170.130.160.0/21 (screenshot: vt_ip1.png) | 2026-09-29 |
| 45.11.181[.]44 | ip | VirusTotal | 5/91 malicious (alphaMountain.ai, Chong Lua Dao, CRDF, Sophos, Webroot), 2 suspicious; RO (Romania); AS 9009 (M247 Europe SRL); network 45.11.181.0/24; community score -1 (screenshot: vt_ip2.png) | 2026-09-29 |
| Moereng[.]com | domain | VirusTotal | 9/91 malicious/phishing (e.g. Fortinet, Sophos, Webroot, BitDefender); tags: command and control, phishing and other frauds, compromised websites, top-1M; registrar GMO Internet Group (Onamae.com) (screenshot: vt_domain.png) | 2026-09-29 |
| 170.130.165[.]73 | ip | Shodan | no results found (no data for this address) (screenshot: shodan170_130_165_73.png) | 2026-09-29 |
| 45.11.181[.]44 | ip | Shodan | Romania, Bucharest; organization servinga GmbH; ISP M247 Europe SRL; AS9009; open ports 135 and 445; last seen 2026-09-26 (screenshot: shodan45_11_181_44.png) | 2026-09-29 |
| 66.42.118[.]54 | ip | Shodan | no results found (no data for this address) (screenshot: shodan66_42_118_54.png) | 2026-09-29 |
| 79.132.130[.]211 | ip | Shodan | Germany, Frankfurt am Main; organization/ISP servinga GmbH; AS39378; open port: 22/tcp only (OpenSSH 9.6p1, Ubuntu); last seen 2026-09-10 (screenshots: shodan79_132_130_211.png, shodan79_132_130_211_1_.png) | 2026-09-29 |
| Moereng[.]com | domain | Maltego (VirusTotal Public API, To Resolved IPs) | resolved to 5 IPs: 170.130.165[.]73 (also in CISA Table 7), 173.255.204[.]62, 129.212.134[.]63, 209.38.63[.]194, 129.212.146[.]52 (screenshot: maltego_graph.png) | 2026-10-01 |
| 170.130.165[.]73 | ip | Maltego (VirusTotal Public API) | resolved to 7 domain names: m165-73.uniteremind[.]com, paymentsdeposit[.]com, moereng[.]com, anyhowdo[.]com, mobilefundsaccess[.]com, wffm0b9r7st[.]com, witnessuseful[.]guru; netblock 170.130.160.0/21 (screenshot: maltego_graph.png) | 2026-10-01 |
| all IOCs above | mixed | Summary graph (drawn by me from the collected data) | relations between the group, files, IPs, domain and hosting organization (screenshot: ioc_graph.png) | 2026-10-01 |

### Behaviour of one sample (VirusTotal: Relations, Behavior and Details tabs)

Sample: EXE with SHA-256 0554eb2ffa3582b000d558b6950ec60e876f1259c41acff2eac47ab78a53e94a (53/70).

**History (Details tab)** (screenshot: vt_details_history.png)

| Field | Value (UTC) |
|---|---|
| Creation time | 2022-09-03 |
| First seen in the wild | 2024-05-11 |
| First submission | 2024-05-09 |
| Last submission | 2024-10-09 |
| Last analysis | 2026-09-29 |

The file was first uploaded to VirusTotal on 2024-05-09, one day before CISA published the advisory (2024-05-10).

**Contacted IPs (Relations tab)** (screenshot: vt_relations.png)

The sample contacted about 20 IP addresses, and every one of them has 0/91 detections. They belong to large providers: AS 8075 and AS 8068 (Microsoft) and AS 20940 and AS 16625 (Akamai), all in the US. The list also contains private addresses (192.168.0.x) without any AS or country; these come from the internal network of the sandbox, not from the attacker. This looks like ordinary background traffic during the sandbox run and not command-and-control infrastructure.

**Sandbox behaviour (Behavior tab)** (screenshot: vt_behavior.png)

- Detections: not found. IDS rules: not found.
- MITRE signatures: 15 informational items (CAPA 2, CAPE Sandbox 3, Zenbox 4, others 0).

### Shodan: attacker's view

Search query: `port:3389` (Remote Desktop Protocol, RDP).

Number of results: **2,223,716** hosts with port 3389 open (search made on 2026-09-29; screenshot: shodan_rdp.png).

Top countries: China (714,253), United States (395,334), Singapore (192,817), Germany (124,200), United Kingdom (86,674).

RDP is one of the most common ways ransomware operators enter a network: they find machines with RDP exposed to the internet and log in with stolen or guessed credentials. Black Basta uses RDP for lateral movement (see the advisory), so exposed RDP is an important item for defenders to check. More than two million machines are reachable for RDP from the internet, which gives ransomware operators a huge pool of potential targets. I only looked at the search results and did not connect to any host.

### Maltego: pivoting from the domain

1. I put the domain Moereng[.]com (from CISA Table 8) on an empty graph in Maltego.
2. I ran the transform **To Resolved IPs [VirusTotal Public API]**. It returned 5 IP addresses that the domain pointed to.
3. One of them, 170.130.165[.]73, is also in the CISA list (Table 7). I ran VirusTotal transforms on this IP and received 7 DNS names that resolved to it and the netblock 170.130.160.0/21 (the same network VirusTotal showed in the IP check).
4. Maltego shows the source of the data (VirusTotal) and the date of the resolution, which is in early October 2024, the same time as the advisory.

![Maltego graph](../images/maltego_graph.png)

The transforms query VirusTotal's database only. I did not open any of these domains or IP addresses.

## 3. Key observations

**Answer to the goal question.** Most of the infrastructure named by CISA in 2024 can no longer be tied to Black Basta with public data: two of the four IPs are unknown to Shodan, one is an ordinary SSH server, and one exposes Windows ports. The domain Moereng[.]com and the malware file hashes are still flagged, and Maltego shows that the domain and one of the CISA IPs were linked in October 2024. This is a snapshot from 2026-09-29 and does not prove that the infrastructure is inactive.

1. **IP addresses expire quickly.** Shodan has no data at all for 170.130.165[.]73 and 66.42.118[.]54. For 79.132.130[.]211 (CISA: likely Cobalt Strike, first seen October 2024) it shows an ordinary server in Frankfurt with only SSH (port 22) open and no sign of a command-and-control service. In VirusTotal, 170.130.165[.]73 and 45.11.181[.]44 have only 2/91 and 5/91 detections almost two years after the report. This is a practical example of the Pyramid of Pain: an IP address is trivial for an attacker to change, so blocking it hurts the attacker very little.
2. **Two IPs share one hosting organization.** Shodan lists servinga GmbH as the organization for both 45.11.181[.]44 (Bucharest) and 79.132.130[.]211 (Frankfurt), and CISA gives the same first-seen date (October 24, 2024) for them. This may mean the same operator rented servers from the same provider, but public data alone does not prove it.
3. **Maltego confirms a link between two CISA indicators and finds new candidates.** With the VirusTotal Public API transforms I found that Moereng[.]com resolved to 170.130.165[.]73, which is one of the IPs from CISA Table 7 (the resolution date in Maltego is in early October 2024, the same time as the advisory). The same IP also resolved to six other domain names that are not in the advisory: paymentsdeposit[.]com, anyhowdo[.]com, mobilefundsaccess[.]com, wffm0b9r7st[.]com, witnessuseful[.]guru and a subdomain of uniteremind[.]com. They are only candidate indicators: sharing one IP does not prove that they belong to Black Basta, so they need more checking before they go into a blocklist. Moereng[.]com also resolved to four other IPs (173.255.204[.]62, 129.212.134[.]63, 209.38.63[.]194, 129.212.146[.]52) that I did not investigate.
4. **Domains and file hashes live longer.** Moereng[.]com is still flagged by 9 of 91 vendors and tagged as command and control. The Black Basta file hashes are still detected by 40-57 vendors two years later. Hashes are precise, but they only identify one exact file and change with every recompilation, so they are also low on the Pyramid of Pain.
5. **A hash alone does not prove malicious use.** The hash of winscp.exe from the advisory has 0 detections and is a signed, legitimate program. Black Basta used it to copy data out of victim networks, so the indicator only makes sense together with context (where and how the tool was run). This is why the TTP level of the Pyramid is more valuable than single hashes.
6. **Sandbox data contains noise.** The sample 0554eb... contacted about 20 IP addresses, but they belong to Microsoft and Akamai (0/91 detections) or are private addresses of the sandbox (192.168.0.x). Such values must be filtered out before importing indicators into MISP. This is the reason for the filtering and normalization step in week 3.
7. **The group targets more than Windows.** The advisory hash 96339a7e... is a 64-bit Linux (ELF) file detected as Black Basta ransomware by 40 of 64 vendors, so Linux servers must be covered by detection too.
8. **Limitations.** All checks are a snapshot made on 2026-09-29. Shodan shows only what its scanners saw on the last visit, and VirusTotal detection counts differ between vendors, so a low count does not prove that an indicator was never malicious. I checked only some of the IOCs from the advisory, not all of them.

## 4. Source evaluation

| Source | Relevance | Reliability | Timeliness |
|---|---|---|---|
| CISA advisory | High | High | Medium |
| VirusTotal | High | Medium | High |
| Shodan | Medium | Medium | High |

## 5. Screenshots

**VirusTotal: files**

![VirusTotal, EXE 0554eb](../images/vt_hash1_exe.png)
![VirusTotal, EXE 90ba27](../images/vt_hash2_exe.png)
![VirusTotal, DLL 58ddbe](../images/vt_hash3_dll.png)
![VirusTotal, ELF 96339a](../images/vt_hash_elf.png)
![VirusTotal, winscp.exe](../images/vt_hash_winscp.png)

**VirusTotal: sample 0554eb (Relations, Behavior, Details)**

![Relations](../images/vt_relations.png)
![Behavior](../images/vt_behavior.png)
![History](../images/vt_details_history.png)

**VirusTotal: IPs and domain**

![IP 170.130.165.73](../images/vt_ip1.png)
![IP 45.11.181.44](../images/vt_ip2.png)
![Domain Moereng](../images/vt_domain.png)

**Shodan**

![Shodan 79.132.130.211](../images/shodan79_132_130_211.png)
![Shodan 79.132.130.211, ports](../images/shodan79_132_130_211_1_.png)
![Shodan 66.42.118.54](../images/shodan66_42_118_54.png)
![Shodan 170.130.165.73](../images/shodan170_130_165_73.png)
![Shodan 45.11.181.44](../images/shodan45_11_181_44.png)

**Shodan: RDP search**

![Shodan port:3389](../images/shodan_rdp.png)

**Maltego**

![Maltego graph](../images/maltego_graph.png)

**Summary graph (drawn by me from the collected data, not generated by Maltego)**

![Summary graph of the IOCs](../images/ioc_graph.png)

## 6. Problems and workarounds

- **Maltego transforms.** The free Maltego installation contained only the Utilities set, which has no DNS or Whois transforms. The transform Threat Miner "Domain to IP (pDNS)" returned HTTP error 522 (the service did not answer). I installed the VirusTotal (Public API) set from the Maltego Data Hub with my own free API key, and its transforms worked. The API key is not shown in any screenshot and is not stored in the repository.
- **VirusTotal Graph.** When I tried to open VirusTotal Graph, VirusTotal showed a "How can we help?" contact form instead of the graph, so this feature was not available with a free account.
- **Summary graph.** The file `images/ioc_graph.png` is a schematic I drew from the data collected in VirusTotal and Shodan to show all indicators in one picture. It is not an automatic result of Maltego.
- **Shodan.** For 170.130.165[.]73 and 66.42.118[.]54 Shodan returned "No results found". I recorded this as a result: the addresses are not (or no longer) visible to Shodan scanners.
- **Old indicators.** The current CISA page no longer contains the file hashes because they were removed as outdated; I took the hashes from the initial version of the advisory (May 2024).
