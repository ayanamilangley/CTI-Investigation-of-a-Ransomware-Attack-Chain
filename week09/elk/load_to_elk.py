"""
Load the atomic-test logs you exported from the lab VM into Elasticsearch,
index "blackbasta-atomic", so you can run the Week 9 KQL in Kibana for screenshots.

Same loader as Week 5 / Week 7, with two extra indexed fields that the Week 9
queries need: CallTrace (LSASS), TargetFilename (staging) and ObjectName (registry).
The Week 5 and Week 7 indexes are not touched.

Run after `cd ../../week05/elk && docker compose up -d`:
    python3 load_to_elk.py ../data/atomic_logs.zip
Then in Kibana: Stack Management -> Data Views -> Create data view
    name/pattern: blackbasta-atomic, timestamp field: @timestamp
    open Discover, set the time range to "Last 1 year".
"""

import json
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ES = "http://localhost:9200"
INDEX = "blackbasta-atomic"
DEFAULT = Path(__file__).resolve().parent.parent / "data" / "atomic_logs.zip"

KEYWORD_FIELDS = [
    "Channel", "Hostname", "Image", "ParentImage", "CommandLine", "ParentCommandLine",
    "User", "SourceImage", "TargetImage", "GrantedAccess", "ServiceName", "ImagePath",
    "ServiceFileName", "DestinationIp", "DestinationPort", "TargetObject", "Details",
    "NewProcessName", "ParentProcessName", "ScriptBlockText", "CallTrace",
    "TargetFilename", "ObjectName", "dataset",
]

MAPPING = {
    "settings": {
        "number_of_replicas": 0,
        "analysis": {"normalizer": {"lower": {"type": "custom", "filter": ["lowercase"]}}},
    },
    "mappings": {
        "dynamic": False,
        "properties": {
            "@timestamp": {"type": "date"},
            "EventID": {"type": "integer"},
            **{f: {"type": "keyword", "normalizer": "lower", "ignore_above": 32766}
               for f in KEYWORD_FIELDS},
        },
    },
}


def request(method, path, body=None, ndjson=False):
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(ES + path, data=data, method=method)
    req.add_header("Content-Type", "application/x-ndjson" if ndjson else "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        if method == "DELETE" and e.code == 404:
            return {}
        sys.exit(f"Elasticsearch error {e.code}: {e.read()[:500]}")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach Elasticsearch at {ES} ({e}). Did you run `docker compose up -d`?")


def timestamp(r):
    if r.get("UtcTime"):
        return str(r["UtcTime"]).replace(" ", "T") + "Z"
    for key in ("TimeCreated", "@timestamp", "EventTime"):
        if r.get(key):
            v = str(r[key]).replace(" ", "T")
            return v if v.endswith("Z") or "+" in v[10:] else v + "Z"
    return None


def iter_lines(src):
    src = Path(src)
    if src.is_file() and src.suffix == ".zip":
        with zipfile.ZipFile(src) as zf:
            for name in zf.namelist():
                if name.endswith((".json", ".jsonl", ".ndjson")):
                    for raw in zf.open(name):
                        yield raw
    else:
        for p in sorted(src.glob("**/*")):
            if p.suffix in (".json", ".jsonl", ".ndjson") and p.is_file():
                for raw in p.open("rb"):
                    yield raw


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    if not Path(src).exists():
        sys.exit(f"Not found: {src}\nExport the logs first (export_logs.ps1), then pass the zip path.")

    request("DELETE", f"/{INDEX}")
    request("PUT", f"/{INDEX}", MAPPING)

    lines, total = [], 0
    for raw in iter_lines(src):
        raw = raw.strip()
        if not raw:
            continue
        try:
            r = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        doc = {k: v for k, v in r.items() if not k.startswith("@")}
        doc["@timestamp"] = timestamp(r)
        doc["dataset"] = "atomic_run"
        try:
            doc["EventID"] = int(r.get("EventID"))
        except (TypeError, ValueError):
            doc.pop("EventID", None)
        for f in KEYWORD_FIELDS:
            if f in doc and doc[f] is not None and not isinstance(doc[f], str):
                doc[f] = str(doc[f])
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(doc))
        if len(lines) >= 4000:
            request("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True)
            total += len(lines) // 2
            lines = []
    if lines:
        request("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True)
        total += len(lines) // 2

    request("POST", f"/{INDEX}/_refresh")
    count = request("GET", f"/{INDEX}/_count")["count"]
    print(f"Done: sent {total} events, index '{INDEX}' now has {count} documents")


if __name__ == "__main__":
    main()
