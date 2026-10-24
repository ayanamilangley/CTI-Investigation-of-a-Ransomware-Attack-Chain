# Week 7 — Using MITRE CAR (Assignment 4)

**Project:** CTI Investigation of the Black Basta Ransomware Attack Chain
**Team:** Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev

Assignment 4 = weeks 6 and 7. Part 1 (ATT&CK) is in [`../week06/`](../week06/README.md).

## Task (from the syllabus, week 7: "Using MITRE CAR")

1. Select an analytic model from CAR and implement it in a SIEM.
2. Map the analytic to related ATT&CK techniques.

## What we did

We chose the analytic **CAR-2020-05-001 "MiniDump of LSASS"**, implemented it in ELK (Kibana KQL) and in a
Python script, tested it on the 24,194 events from Week 5 and compared it with our own Week 5 query.
We mapped it to ATT&CK and described what must be done to turn the analytic into a real detection.

| Item | Result |
|---|---|
| Analytic | CAR-2020-05-001 (MiniDump of LSASS) |
| Events scanned | 24,194 (5 datasets from Week 5) |
| LSASS access events | 184 |
| CAR analytic hits | **1** (`rundll32.exe` + `comsvcs.dll` MiniDump on WORKSTATION5) |
| Hits in the control and other datasets | 0 |
| Our Week 5 filter hits (for comparison) | 2 |

## Files

| Path | What it is |
|---|---|
| [`report.md`](report.md) | The report |
| [`queries/car_2020_05_001.md`](queries/car_2020_05_001.md) | The CAR query and our KQL version |
| [`scripts/car_analytic.py`](scripts/car_analytic.py) | The analytic in Python (reads `../week05/data`) |
| [`elk/load_to_elk.py`](elk/load_to_elk.py) | Loader for the index `blackbasta-car` (Week 5 loader + the `CallTrace` field) |
| [`results/car_results.md`](results/car_results.md), [`results/car_results.csv`](results/car_results.csv) | Output of the script |
| `images/` | Kibana screenshots |

## How to repeat

```
cd week05/elk && docker compose up -d
cd ../../week07/elk && python3 load_to_elk.py
cd ../scripts && python3 car_analytic.py
```

(On Windows write `python` instead of `python3`.)

Then in Kibana create the data view `blackbasta-car` (timestamp field `@timestamp`) and run the queries from `queries/car_2020_05_001.md`.
