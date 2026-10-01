# OSINT Findings — Black Basta


## 1. Results


In VirusTotal, a number like 53/70 means that 53 of 70 antivirus engines said the file is malicious. I did not upload any files, I only searched by hash.

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


### Behaviour of one sample (VirusTotal: Details, Relations and Behavior tabs)

I looked closer at the first file, the EXE with SHA-256 0554eb2ffa3582b000d558b6950ec60e876f1259c41acff2eac47ab78a53e94a (53/70).

**Dates (Details tab)** (screenshot: vt_details_history.png)

| Field | Value (UTC) |
|---|---|
| Creation time | 2022-09-03 |
| First seen in the wild | 2024-05-11 |
| First submission | 2024-05-09 |
| Last submission | 2024-10-09 |
| Last analysis | 2026-09-29 |



### Shodan:

I searched for `port:3389`. This is the port of Remote Desktop (RDP), which lets you control a computer from far away.

Result: **2,223,716** computers with this port open (search on 2026-09-29, screenshot: shodan_rdp.png). Most of them are in China (714,253) and the United States (395,334), then Singapore (192,817), Germany (124,200) and the United Kingdom (86,674).

Ransomware groups often get into a network through open RDP, using stolen or guessed passwords. The CISA report says Black Basta also uses RDP to move between computers. With more than two million open machines, attackers have a lot to choose from. I only looked at the search results and did not connect to anything.

### Maltego: 

1. I put the domain Moereng[.]com (from CISA Table 8) on an empty graph in Maltego.
2. I ran the transform **To Resolved IPs [VirusTotal Public API]**. It showed 5 IP addresses that the domain pointed to.
3. One of them, 170.130.165[.]73, is also in the CISA list (Table 7). So the domain and this IP are connected.
4. I ran VirusTotal transforms on this IP. It showed 7 domain names that pointed to it, and the network 170.130.160.0/21 (the same network as in the VirusTotal IP check).
5. Maltego shows the date of the connection: early October 2024, which is the same time as the CISA report.

![Maltego graph](../images/maltego_graph.png)

 I did not open any of these domains or IPs.



## 3. Source evaluation


- **CISA** is a government agency and the report was written together with the FBI and other partners, so I trust it a lot. But the report is from 2024, and CISA itself removed old indicators later.
- **VirusTotal** is up to date and has a lot of data, but it is a mix of many vendors who sometimes disagree.
- **Shodan** is up to date, but it only shows what its scanners found, and some addresses just had no data.

## 4. Screenshots

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




