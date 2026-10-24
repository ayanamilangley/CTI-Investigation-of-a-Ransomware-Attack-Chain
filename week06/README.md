# Week 6 — ATT&CK framework (Assignment 4, part 1 of 2)

**Project:** CTI Investigation of the Black Basta Ransomware Attack Chain
**Team:** Botakoz Berikkyzy, Alina Ashirova, Timur Aktayev

## Task (from the syllabus, week 6: "ATT&CK Framework")

1. Study one specific technique.
2. Simulate an attack and map the results to ATT&CK tactics and techniques.

Assignment 4 = weeks 6 and 7. Part 2 (MITRE CAR) is in [`../week07/`](../week07/README.md).

## What we did

We studied **T1003.001 LSASS Memory**, took the recorded attacks from Week 5 as our "simulation", mapped every finding to ATT&CK (v20) and built a layer for the ATT&CK Navigator.

| Item | Result |
|---|---|
| Technique studied | T1003.001 OS Credential Dumping: LSASS Memory |
| Techniques seen in our logs | 12 |
| Tactics covered | 6 (Execution, Stealth, Defense Impairment, Credential Access, Lateral Movement, Command and Control) |
| Detected by the Week 7 CAR analytic | 1 of 12 |

## Files

| Path | What it is |
|---|---|
| [`report.md`](report.md) | The report |
| [`attack_navigator_layer.json`](attack_navigator_layer.json) | Layer for the ATT&CK Navigator |
| [`results/ttp_mapping.csv`](results/ttp_mapping.csv) | The mapping table |
| [`scripts/make_navigator_layer.py`](scripts/make_navigator_layer.py) | Builds the table and the layer from one list |
| `images/` | Screenshot of the layer in the Navigator |

## How to repeat

```
cd week06/scripts
python3 make_navigator_layer.py
```

(On Windows write `python` instead of `python3`.) Then open `attack_navigator_layer.json` in the Navigator (Open Existing Layer → Upload from local).
