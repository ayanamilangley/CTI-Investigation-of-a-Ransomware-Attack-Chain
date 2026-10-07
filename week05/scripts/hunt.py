"""
Week 5 - Hypothesis-driven threat hunt for Black Basta / Storm-1811 behavior.

The script reads Windows event logs (Sysmon + Security + PowerShell) from the
zip files in ../data, runs our 3 hunting hypotheses on them and writes:

  ../results/findings.csv       one row per hit
  ../results/hunt_results.md    summary tables for the report
  ../images/hunt_funnel.png     all events -> process events -> hits

The same logic is written as Kibana (KQL), Splunk (SPL) and Sigma queries
in ../queries. This script is our "mini SIEM" so anyone can repeat the hunt
without installing ELK or Splunk.

Run:  python3 hunt.py
"""

import base64
import csv
import json
import re
import zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data"
RESULTS = BASE / "results"
IMAGES = BASE / "images"

SYSMON = "microsoft-windows-sysmon/operational"


# ---------------------------------------------------------------- loading

def parse_time(r):
    """Different datasets keep the time in different fields."""
    for key in ("UtcTime", "@timestamp", "TimeCreated", "EventTime"):
        v = r.get(key)
        if not v:
            continue
        v = str(v).replace("Z", "").replace("T", " ")[:23]
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(v, fmt)
            except ValueError:
                pass
    return None


def load_events():
    events = []
    for z in sorted(DATA.glob("*.zip")):
        with zipfile.ZipFile(z) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                for line in zf.open(name):
                    r = json.loads(line)
                    r["_dataset"] = z.stem
                    r["_time"] = parse_time(r)
                    r["_host"] = str(r.get("Hostname", "")).split(".")[0].upper()
                    r["_channel"] = str(r.get("Channel", "")).lower()
                    events.append(r)
    return events


def exe(path):
    """C:\\Windows\\System32\\cmd.exe -> cmd.exe"""
    return str(path or "").split("\\")[-1].lower()


def is_sysmon(r, event_id):
    return r["_channel"] == SYSMON and r.get("EventID") == event_id


def decode_powershell(cmd):
    """Return the decoded text of 'powershell -enc <base64>', or ''."""
    m = re.search(r"\s-e[a-z]*\s+([A-Za-z0-9+/=]{20,})", cmd, re.IGNORECASE)
    if not m:
        return ""
    try:
        return base64.b64decode(m.group(1)).decode("utf-16le", errors="ignore")
    except Exception:
        return ""


# ---------------------------------------------------------------- hypotheses

PS_EXE = {"powershell.exe", "pwsh.exe"}
ENC = re.compile(r"\s-e(n|nc|ncodedcommand)?\s", re.IGNORECASE)
HIDDEN = re.compile(r"\s-w(indowstyle)?\s+(h(idden)?|1)\b", re.IGNORECASE)
NOPROFILE = re.compile(r"\s-nop(rofile)?\b", re.IGNORECASE)

DOWNLOAD_TOOLS = {"curl.exe", "bitsadmin.exe", "certutil.exe"}
PS_DOWNLOAD = re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|"
                         r"start-bitstransfer|invoke-restmethod", re.IGNORECASE)
URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)

LSASS_ACCESS = {"0x1fffff", "0x1010", "0x1410", "0x143a", "0x1438"}
LSASS_NORMAL = {"msmpeng.exe", "svchost.exe", "wmiprvse.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsm.exe", "mrt.exe", "vmtoolsd.exe", "taskmgr.exe"}


def hunt_h1(proc):
    """H1 - suspicious PowerShell: encoded command, or hidden window + no profile."""
    hits = []
    for r in proc:
        cmd = r.get("CommandLine", "")
        if exe(r.get("Image")) not in PS_EXE:
            continue
        encoded = bool(ENC.search(cmd + " "))
        hidden = bool(HIDDEN.search(cmd)) and bool(NOPROFILE.search(cmd))
        if encoded or hidden:
            parent = exe(r.get("ParentImage"))
            sev = "high" if encoded and parent in {"cmd.exe", "services.exe", "wmiprvse.exe", "rundll32.exe"} else "medium"
            hits.append(("H1", r, "T1059.001, T1027.010", sev,
                         "encoded command" if encoded else "hidden window + -nop"))
    return hits


def hunt_h2(proc):
    """H2 - built-in tools downloading files (incl. text inside decoded PowerShell).
    If Quick Assist started on the same host up to 10 minutes before, the hit is
    'critical': this is the Storm-1811 pattern from our Week 4 report."""
    quick_assist = [(r["_host"], r["_time"]) for r in proc if exe(r.get("Image")) == "quickassist.exe"]
    hits = []
    for r in proc:
        cmd = r.get("CommandLine", "")
        image = exe(r.get("Image"))
        decoded = decode_powershell(cmd) if image in PS_EXE else ""
        if image in DOWNLOAD_TOOLS and URL.search(cmd):
            tech = "T1197, T1105" if image == "bitsadmin.exe" else "T1105"
            qa = any(h == r["_host"] and t and r["_time"] and timedelta(0) <= r["_time"] - t <= timedelta(minutes=10)
                     for h, t in quick_assist)
            why = f"{image} downloads {URL.search(cmd).group(0)[:60]}"
            hits.append(("H2", r, tech + (", T1219.002" if qa else ""), "critical" if qa else "medium",
                         why + (" after Quick Assist" if qa else "")))
        elif image in PS_EXE and (PS_DOWNLOAD.search(cmd) or PS_DOWNLOAD.search(decoded)):
            where = "decoded -enc payload" if PS_DOWNLOAD.search(decoded) else "command line"
            hits.append(("H2", r, "T1105, T1071.001", "high", f"PowerShell web client in {where}"))
    return hits


def hunt_h3(proc, lsass_access):
    """H3 - credential theft and backup tampering before encryption."""
    hits = []
    for r in proc:
        cmd = r.get("CommandLine", "").lower()
        image = exe(r.get("Image"))
        if image == "vssadmin.exe" and "shadow" in cmd:
            if "delete" in cmd or "resize" in cmd:
                hits.append(("H3", r, "T1490", "critical", "vssadmin deletes/resizes shadow copies"))
            else:
                hits.append(("H3", r, "T1003.003", "high", "vssadmin creates a shadow copy (NTDS.dit theft)"))
        if image == "wmic.exe" and "shadowcopy" in cmd and "delete" in cmd:
            hits.append(("H3", r, "T1490", "critical", "wmic deletes shadow copies"))
        if image == "rundll32.exe" and "comsvcs" in cmd and "minidump" in cmd:
            hits.append(("H3", r, "T1003.001, T1218.011", "critical", "comsvcs.dll MiniDump (LSASS dump)"))
    for r in lsass_access:
        src = exe(r.get("SourceImage"))
        if src not in LSASS_NORMAL and str(r.get("GrantedAccess", "")).lower() in LSASS_ACCESS:
            hits.append(("H3", r, "T1003.001", "high",
                         f"{src} opens lsass.exe with access {r.get('GrantedAccess')}"))
    return hits


# ---------------------------------------------------------------- pivots

def pivot_h1(hit, events):
    """For an H1 hit: what else happened on the same host +-5 minutes?"""
    r = hit[1]
    t, host = r["_time"], r["_host"]
    notes = []
    for e in events:
        if e["_host"] != host or not e["_time"] or abs(e["_time"] - t) > timedelta(minutes=5):
            continue
        if e.get("EventID") in (7045, 4697) and e.get("ServiceName"):
            notes.append(f"service '{e.get('ServiceName')}' installed (EventID {e.get('EventID')})")
        if is_sysmon(e, 3) and exe(e.get("Image")) in PS_EXE:
            notes.append(f"powershell.exe network connection to {e.get('DestinationIp')}:{e.get('DestinationPort')}")
    # attackers split words to hide them ('Amsi'+'Utils'), so we join them back
    decoded = decode_powershell(r.get("CommandLine", "")).replace("'+'", "").replace("`", "")
    if decoded:
        inner = re.findall(r"FroMBASe64StrinG\('([A-Za-z0-9+/=]+)'\)", decoded, re.IGNORECASE)
        for b in inner:
            try:
                notes.append("C2 server in payload: " + base64.b64decode(b).decode("utf-16le"))
            except Exception:
                pass
        for word, meaning in (("amsiInitFailed", "AMSI bypass"),
                              ("EnableScriptBlockLogging", "turns off PowerShell Script Block Logging"),
                              ("WebClient", "downloads next stage with Net.WebClient")):
            if word.lower() in decoded.lower():
                notes.append(meaning)
    return sorted(set(notes))


# ---------------------------------------------------------------- main

def main():
    events = load_events()
    # Sysmon EventID 1 is our main source; Security 4688 is used as a cross-check.
    proc = [r for r in events if is_sysmon(r, 1)]
    proc4688 = [r for r in events if r.get("EventID") == 4688 and r["_channel"] == "security"]
    lsass_access = [r for r in events if is_sysmon(r, 10) and exe(r.get("TargetImage")) == "lsass.exe"]

    hits = hunt_h1(proc) + hunt_h2(proc) + hunt_h3(proc, lsass_access)
    all_ps = sum(1 for r in proc if exe(r.get("Image")) in PS_EXE)
    n_qa = sum(1 for r in proc if exe(r.get("Image")) == "quickassist.exe")

    # Cross-check: is the same command line also visible in Security 4688?
    cmd4688 = {(r["_host"], (r.get("CommandLine") or "").strip().lower()) for r in proc4688}

    RESULTS.mkdir(exist_ok=True)
    rows = []
    for h, r, tech, sev, why in hits:
        cmd = (r.get("CommandLine") or "").strip()
        rows.append({
            "hypothesis": h,
            "dataset": r["_dataset"],
            "host": r["_host"],
            "time_utc": r["_time"].strftime("%Y-%m-%d %H:%M:%S") if r["_time"] else "",
            "sysmon_event": r.get("EventID"),
            "process": exe(r.get("Image") or r.get("SourceImage")),
            "parent": exe(r.get("ParentImage")),
            "user": r.get("User", ""),
            "why": why,
            "attack": tech,
            "severity": sev,
            "also_in_4688": "yes" if (r["_host"], cmd.lower()) in cmd4688 else ("n/a" if r.get("EventID") == 10 else "no"),
            "pivot_notes": "; ".join(pivot_h1((h, r), events)) if h == "H1" else "",
            "command_line": cmd[:300],
        })

    with open(RESULTS / "findings.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    # ---- summary per dataset
    datasets = sorted({r["_dataset"] for r in events})
    total = Counter(r["_dataset"] for r in events)
    nproc = Counter(r["_dataset"] for r in proc)
    nhits = Counter(row["dataset"] for row in rows)
    byhyp = Counter((row["dataset"], row["hypothesis"]) for row in rows)

    md = ["# Hunt results (generated by scripts/hunt.py)", "",
          f"Events scanned: **{len(events)}** | process creation (Sysmon 1): **{len(proc)}** | "
          f"LSASS access (Sysmon 10): **{len(lsass_access)}** | hits: **{len(rows)}**", "",
          f"Filters: PowerShell starts {all_ps} -> H1 hits {sum(1 for r in rows if r['hypothesis']=='H1')}; "
          f"LSASS accesses {len(lsass_access)} -> after access-mask filter "
          f"{sum(1 for r in rows if r['sysmon_event']==10)}; QuickAssist.exe starts: {n_qa}", "",
          "| Dataset | All events | Sysmon 1 | H1 | H2 | H3 |", "|---|---|---|---|---|---|"]
    for d in datasets:
        md.append(f"| {d} | {total[d]} | {nproc[d]} | {byhyp[(d,'H1')]} | {byhyp[(d,'H2')]} | {byhyp[(d,'H3')]} |")
    md += ["", "| # | Hyp. | Host | Time (UTC) | Process ← parent | Why | ATT&CK | Severity | In 4688 |",
           "|---|---|---|---|---|---|---|---|---|"]
    for i, row in enumerate(rows, 1):
        pp = f"`{row['process']}` ← `{row['parent']}`" if row["parent"] else f"`{row['process']}`"
        md.append(f"| {i} | {row['hypothesis']} | {row['host']} | {row['time_utc']} | {pp} | {row['why']} | "
                  f"{row['attack']} | {row['severity']} | {row['also_in_4688']} |")
    pivots = [r for r in rows if r["pivot_notes"]]
    if pivots:
        md += ["", "**H1 pivot (same host, ±5 minutes):**", ""]
        for r in pivots:
            md.append(f"- {r['host']} {r['time_utc']}: " + "; ".join(r["pivot_notes"].split("; ")))
    (RESULTS / "hunt_results.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    draw_funnel(datasets, total, nproc, nhits)

    print(f"Scanned {len(events)} events ({len(proc)} process creations, {len(lsass_access)} LSASS accesses)")
    for h in ("H1", "H2", "H3"):
        print(f"  {h}: {sum(1 for r in rows if r['hypothesis'] == h)} hits")
    print("Wrote results/findings.csv, results/hunt_results.md, images/hunt_funnel.png")


def draw_funnel(datasets, total, nproc, nhits):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = [d.replace("_", " ") for d in datasets]
    y = range(len(datasets))
    fig, ax = plt.subplots(figsize=(10, 4.8))
    h = 0.26
    ax.barh([i - h for i in y], [total[d] for d in datasets], h, color="#c9ced6", label="all events")
    ax.barh(list(y), [nproc[d] for d in datasets], h, color="#6b8fc7", label="process creations (Sysmon 1)")
    ax.barh([i + h for i in y], [nhits[d] for d in datasets], h, color="#d1495b", label="hunt hits")
    for i, d in enumerate(datasets):
        ax.text(max(nhits[d], 1) * 1.15, i + h, str(nhits[d]), va="center", fontsize=9, color="#d1495b")
        ax.text(total[d] * 1.15, i - h, str(total[d]), va="center", fontsize=9, color="#555")
    ax.set_xscale("log")
    ax.set_xlim(0.8, max(total.values()) * 4)
    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("number of events (log scale)")
    ax.set_title("Finding the needle: hunt hits vs all events per dataset", fontsize=11, loc="left")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.16), ncol=3, fontsize=8, frameon=False)
    fig.tight_layout()
    IMAGES.mkdir(exist_ok=True)
    fig.savefig(IMAGES / "hunt_funnel.png", dpi=150)


if __name__ == "__main__":
    main()
