# Week 3 — Data Processing and Exploitation

1) Goal

The goal of this assignment was to work with threat intelligence data related to Black Basta ransomware. 
The main tasks were to collect IOC data, clean and normalize it with Python, import the processed indicators into MISP, add additional context, check correlations, and export the final event data.
The assignment helped me understand how raw threat intelligence can be processed before it is added to a CTI platform.

2) Environment

The practical work was completed on a Windows 10 computer.

The main tools used were:
* Windows 10
* Docker Desktop
* MISP
* Python
* Git

MISP was deployed using Docker and accessed through the local web interface at `https://localhost`
The MISP dashboard was checked after deployment to make sure that the platform was working correctly.
**Screenshot:** MISP dashboard

3) MISP Deployment

MISP was deployed using the official MISP Docker repository. 
Docker was used to run the MISP environment without installing all of its components manually on Windows.
After starting the containers, I opened the MISP web interface through `https://localhost` and logged in.
After the installation, I prepared MISP for the assignment. 
The Galaxies were updated, the TLP taxonomy was enabled, and the warninglists were updated. 
These features were useful later when adding context to the collected indicators.
I also enabled the CIRCL OSINT Feed. The feed provides additional threat intelligence data that can be used by MISP for comparison and correlation.

4) Filtering and Normalization

The collected IOC data was first saved in a raw text file. 
The data contained different types of indicators, including IP addresses, domains, URLs and file hashes.
Some indicators were intentionally left in a format that required processing. For example, domains could use `[.]` instead of `.`, and URLs could use `hxxp` instead of `http`. Duplicate values and private IP addresses were also included to test the filtering process.

A Python script called `normalize.py` was used to process the data.

The script performs several operations:

* converts defanged URLs and domains into a normal format;
* identifies hashes, IP addresses, URLs and domains;
* converts hashes and domains to lowercase;
* removes private IP addresses;
* removes unknown values;
* removes duplicate indicators;
* saves the cleaned data as a CSV file.

The input file was:

`week02/iocs_raw.txt`

The processed file was:

`data/iocs_clean.csv`

For example, a defanged domain such as:

`evil[.]com`

was converted to:

`evil.com`

A private IP such as:

`192.168.1.10`

was removed because it is an internal address and is not useful as an external threat indicator.

The normalization step made the dataset more consistent before importing it into MISP.

**Screenshot:** Python normalization output

## 5. MISP Event

After processing the IOC data, I created a new MISP event with the following information:

* **Event information:** Black Basta ransomware IOCs – CISA AA24-131A
* **Distribution:** Your organisation only
* **Threat level:** High
* **Analysis:** Completed

The cleaned IOC values were imported using the Freetext Import Tool. 
MISP automatically recognized the types of many indicators, such as IP addresses, domains, URLs and hashes.
The imported indicators were reviewed before being added to the event.
The event was also tagged with `tlp:clear`.
A Black Basta ransomware Galaxy was added to the event to provide additional context about the ransomware family. MITRE ATT&CK information was also considered when working with the event.

After the event was completed, it was published in MISP.

**Screenshots:** event, attributes, tags and Black Basta Galaxy

## 6. Correlation and Export

MISP correlation was used to check whether some of the collected indicators were already present in other events or feeds.
The correlation results depend on the data available in MISP. Some indicators had matches, while others did not. 
A missing correlation does not necessarily mean that an indicator is incorrect, since threat intelligence data can become outdated or may not be present in the available feeds.
After processing the event, the data was exported from MISP.

The exported files include:

- MISP JSON
- CSV
- `misp.event.list.csv`

The CSV format is useful for working with the data in a simple tabular form. JSON can be used for structured data exchange and further processing. MISP also supports STIX for standardized threat intelligence sharing, although the additional CISA STIX import was not performed in this assignment.

7) Findings and Conclusions

During this assignment, I worked through a basic threat intelligence processing workflow from raw IOC data to a structured MISP event.

The main part of the work was the filtering and normalization stage. Raw threat intelligence is not always ready to be used directly because it can contain duplicate indicators, defanged values, private IP addresses or other irrelevant data. The Python script helped automate this cleaning process.

After that, the cleaned indicators were imported into MISP and connected with Black Basta context. MISP also made it possible to check correlations with other available threat intelligence data and export the processed information in different formats.

One limitation of the work is that correlation results depend on the feeds and events available in the MISP installation. Another limitation is that some indicators can become inactive or irrelevant over time.

Overall, the assignment showed the basic process of collecting, processing, enriching and storing threat intelligence data before using it for further analysis.

8) Sources

1. CISA — #StopRansomware: Black Basta
2. MISP Documentation
3. MISP Docker Repository
4. MITRE ATT&CK
5. CIRCL OSINT Feed
