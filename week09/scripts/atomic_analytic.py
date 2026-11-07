"""
Week 9 - turn the logs you exported from the lab VM into the real results table.

This is the Week 9 twin of week07/scripts/car_analytic.py. It does NOT need ELK.
It reads the events you exported after running the atomic tests (export_logs.ps1),
runs the same detection logic as our Kibana queries (Week 5 H1/H3, Week 7 CAR, and
the 4 new Week 9 queries), and writes:

  ../results/atomic_results.csv
  ../results/atomic_results.md

Input: a folder or .zip of JSON-lines files (one Windows event per line), with the
same field names as the OTRF datasets we used in Weeks 5-7 (Channel, EventID,
Image, CommandLine, TargetImage, GrantedAccess, CallTrace, TargetObject, Details,
ServiceName / ServiceFileName, DestinationIp, ...). export_logs.ps1 produces this.

Run:
  python3 atomic_analytic.py ../data/atomic_logs.zip
  python3 atomic_analytic.py C:\\path\\to\\exported\\logs   (Windows: python ...)

If no path is given it looks for ../data/atomic_logs.zip then ../data/.
"""

import csv
import json
import sys
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent


def g(ev, *keys):
    """Case-tolerant get: return the first present key as a string (lowercased)."""
    for k in keys:
        if k in ev and ev[k] is not None:
            return str(ev[k]).lower()
    low = {k.lower(): v for k, v in ev.items()}
    for k in keys:
        if k.lower() in low and low[k.lower()] is not None:
            return str(low[k.lower()]).lower()
    return ""


def eid(ev):
    try:
        return int(g(ev, "EventID", "EventCode") or -1)
    except ValueError:
        return -1


def chan(ev):
    return g(ev, "Channel")


# ---- one matcher per atomic test (returns True if this event is a hit) --------

def m_t9_1(ev):  # T1059.003 cmd.exe running a batch script
    if eid(ev) == 1 and "sysmon" in chan(ev):
        img, cl = g(ev, "Image"), g(ev, "CommandLine")
        return img.endswith("cmd.exe") and (".bat" in cl or ".cmd" in cl or "/c" in cl)
    return False


def m_t9_2(ev):  # T1059.001 encoded / hidden PowerShell  (Week 5 H1)
    if "sysmon" in chan(ev) and eid(ev) == 1:
        img, cl = g(ev, "Image"), g(ev, "CommandLine")
        if img.endswith("powershell.exe") and ("-enc" in cl or "-e " in cl
                                                or "encodedcommand" in cl
                                                or ("-w" in cl and "hidden" in cl)):
            return True
    if eid(ev) == 4104:  # PowerShell script block logging
        txt = g(ev, "ScriptBlockText", "Message")
        return "frombase64" in txt or "iex" in txt or "invoke-expression" in txt
    return False


def m_t9_3(ev):  # T1547.001 Run key
    if "sysmon" in chan(ev) and eid(ev) == 13:
        return "currentversion\\run" in g(ev, "TargetObject")
    if eid(ev) == 4657:
        return "currentversion\\run" in g(ev, "ObjectName", "TargetObject", "Message")
    return False


def m_t9_4(ev):  # T1543.003 new service  (Week 5 H1 pivot 2)
    if eid(ev) in (7045, 4697):
        return True
    if "sysmon" in chan(ev) and eid(ev) == 1:
        return g(ev, "Image").endswith("services.exe") is False and (
            "psexe" in g(ev, "Image", "CommandLine"))
    return False


def m_t9_5_car(ev):  # T1003.001 - Week 7 CAR-2020-05-001 (CallTrace)
    if "sysmon" in chan(ev) and eid(ev) == 10 and g(ev, "TargetImage").endswith("lsass.exe"):
        ct = g(ev, "CallTrace")
        return "dbghelp.dll" in ct or "dbgcore.dll" in ct
    return False


def m_t9_5_h3(ev):  # T1003.001 - Week 5 H3 (access mask + command line)
    if "sysmon" in chan(ev) and eid(ev) == 10 and g(ev, "TargetImage").endswith("lsass.exe"):
        acc = g(ev, "GrantedAccess")
        src = g(ev, "SourceImage")
        noisy = ("msmpeng.exe", "svchost.exe", "wmiprvse.exe", "csrss.exe",
                 "wininit.exe", "services.exe", "vboxservice.exe")
        if acc in ("0x1fffff", "0x1010", "0x1410", "0x143a", "0x1438") and not any(
                src.endswith(n) for n in noisy):
            return True
    if "sysmon" in chan(ev) and eid(ev) == 1:
        cl = g(ev, "CommandLine")
        return "comsvcs" in cl and "minidump" in cl
    return False


def m_t9_6(ev):  # T1074.001 staging: file-create into one folder
    if "sysmon" in chan(ev) and eid(ev) == 11:
        tf = g(ev, "TargetFilename")
        return "\\temp\\" in tf or "\\stage" in tf or "\\decoy" in tf or "patient_records" in tf
    return False


def m_t9_7(ev):  # T1560.001 archive utility
    if "sysmon" in chan(ev) and eid(ev) == 1:
        img, cl = g(ev, "Image"), g(ev, "CommandLine")
        arch = ("tar.exe", "7z.exe", "7za.exe", "rar.exe", "winrar.exe")
        return any(img.endswith(a) for a in arch) or "compress-archive" in cl
    return False


def m_t9_8(ev):  # T1567.002 rclone / exfil
    if "sysmon" in chan(ev) and eid(ev) == 1:
        return g(ev, "Image").endswith("rclone.exe") or "rclone" in g(ev, "CommandLine")
    if "sysmon" in chan(ev) and eid(ev) == 3:
        return "rclone" in g(ev, "Image")
    return False


def m_t9_9(ev):  # T1490 shadow copy deletion - CAR-2021-01-009
    if eid(ev) in (1, 4688):
        cl = g(ev, "CommandLine")
        return (("vssadmin" in cl and "delete" in cl and "shadow" in cl)
                or ("wmic" in cl and "shadowcopy" in cl and "delete" in cl)
                or ("vssadmin" in cl and "resize" in cl and "shadowstorage" in cl))
    return False


TESTS = [
    ("T9-1", "T1059.003", "Windows Command Shell", "Week 5 H1", "no", [m_t9_1]),
    ("T9-2", "T1059.001", "PowerShell (encoded)", "Week 5 H1", "yes", [m_t9_2]),
    ("T9-3", "T1547.001", "Registry Run Key", "Week 9 Q1", "no", [m_t9_3]),
    ("T9-4", "T1543.003", "Windows Service", "Week 5 H1 pivot", "yes", [m_t9_4]),
    ("T9-5", "T1003.001", "LSASS (CAR + H3)", "Week 7 CAR / Week 5 H3", "yes",
     [m_t9_5_car, m_t9_5_h3]),
    ("T9-6", "T1074.001", "Local Data Staging", "Week 9 Q2", "no", [m_t9_6]),
    ("T9-7", "T1560.001", "Archive via Utility", "Week 9 Q3", "no", [m_t9_7]),
    ("T9-8", "T1567.002", "Exfil Rclone", "Week 9 Q4", "yes", [m_t9_8]),
    ("T9-9", "T1490", "Shadow Copy Deletion", "Week 9 Q5 (CAR-2021-01-009)", "no", [m_t9_9]),
]


def load_events(path):
    path = Path(path)
    out = []
    files = []
    if path.is_file() and path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if n.endswith(".json") or n.endswith(".jsonl") or n.endswith(".ndjson"):
                    files.append(("zip", n))
        zf = zipfile.ZipFile(path)
        for _, n in files:
            for raw in zf.open(n):
                yield_line(raw, out)
    else:
        for p in sorted(path.glob("**/*")):
            if p.suffix in (".json", ".jsonl", ".ndjson") and p.is_file():
                for raw in p.open("rb"):
                    yield_line(raw, out)
    return out


def yield_line(raw, out):
    raw = raw.strip()
    if not raw:
        return
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return
    if isinstance(obj, list):
        out.extend(x for x in obj if isinstance(x, dict))
    elif isinstance(obj, dict):
        # a single big export may wrap events under a key
        if "events" in obj and isinstance(obj["events"], list):
            out.extend(x for x in obj["events"] if isinstance(x, dict))
        else:
            out.append(obj)


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if not arg:
        for cand in (BASE / "data" / "atomic_logs.zip", BASE / "data"):
            if cand.exists():
                arg = cand
                break
    if not arg or not Path(arg).exists():
        sys.exit("Give the path to your exported logs, e.g.\n"
                 "  python3 atomic_analytic.py ../data/atomic_logs.zip\n"
                 "(export them on the VM with export_logs.ps1 - see lab-tutorial.md)")

    events = load_events(arg)
    print(f"Loaded {len(events)} events from {arg}")

    rows = []
    for step, tid, name, query, must, matchers in TESTS:
        hits = sum(1 for ev in events if any(m(ev) for m in matchers))
        detected = "yes" if hits > 0 else "no"
        rows.append((step, tid, name, query, must, hits, detected))

    (BASE / "results").mkdir(exist_ok=True)
    with open(BASE / "results" / "atomic_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["step", "attack_id", "technique", "elk_query", "must_detect", "hits", "detected"])
        w.writerows(rows)

    run = rows
    must = [r for r in run if r[4] == "yes"]
    must_ok = [r for r in must if r[6] == "yes"]
    det = [r for r in run if r[6] == "yes"]

    lines = ["# Week 9 - Atomic Red Team results (generated by scripts/atomic_analytic.py)\n",
             f"Source: `{arg}` | events analyzed: **{len(events)}**\n",
             f"Tests detected: **{len(det)}/{len(run)}** | "
             f"Must-detect (Week 8 B2,C2,D1,E3) passed: **{len(must_ok)}/{len(must)}**\n",
             "| Step | ATT&CK | Technique | ELK query | Must-detect | Hits | Detected |",
             "|---|---|---|---|---|---|---|"]
    for step, tid, name, query, must_f, hits, det_f in rows:
        lines.append(f"| {step} | **{tid}** | {name} | {query} | {must_f} | {hits} | "
                     f"{'YES' if det_f == 'yes' else 'no'} |")
    lines.append("")
    lines.append("Hits = number of events in your export that match the detection logic. "
                 "0 hits means either the test was not run or the log that carries the signal "
                 "was not enabled (see lab-tutorial.md, step on Sysmon config).")
    (BASE / "results" / "atomic_results.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"Detected {len(det)}/{len(run)} tests; must-detect {len(must_ok)}/{len(must)}")
    print("Wrote results/atomic_results.csv and results/atomic_results.md")


if __name__ == "__main__":
    main()
