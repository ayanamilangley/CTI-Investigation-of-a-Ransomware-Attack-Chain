"""
Load the Week 5 datasets (../data/*.zip) into Elasticsearch, index "blackbasta-hunt".

Only standard Python is needed (no pip install).
Run after `docker compose up -d`:   python3 load_to_elk.py
Then in Kibana: Stack Management -> Data Views -> Create data view
                name/pattern: blackbasta-hunt, timestamp field: @timestamp
                and open Discover. Set the time range to "Last 10 years".

All text fields use a lowercase normalizer, so the KQL queries in
../queries/kibana_kql.md are NOT case sensitive (write them in lowercase).
"""

import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ES = "http://localhost:9200"
INDEX = "blackbasta-hunt"
DATA = Path(__file__).resolve().parent.parent / "data"

KEYWORD_FIELDS = [
    "Channel", "Hostname", "Image", "ParentImage", "CommandLine", "ParentCommandLine",
    "User", "SourceImage", "TargetImage", "GrantedAccess", "ServiceName", "ImagePath",
    "ServiceFileName", "DestinationIp", "DestinationPort", "TargetObject", "Details",
    "NewProcessName", "ParentProcessName", "ScriptBlockText", "dataset",
]

MAPPING = {
    "settings": {
        "number_of_replicas": 0,
        "analysis": {"normalizer": {"lower": {"type": "custom", "filter": ["lowercase"]}}},
    },
    "mappings": {
        # other fields stay in the document but are not indexed -> no type conflicts
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


def timestamp(r):
    """Use Sysmon UtcTime when it exists (most exact), else @timestamp / TimeCreated."""
    if r.get("UtcTime"):
        return r["UtcTime"].replace(" ", "T") + "Z"
    for key in ("@timestamp", "TimeCreated", "EventTime"):
        if r.get(key):
            v = str(r[key]).replace(" ", "T")
            return v if v.endswith("Z") or "+" in v[10:] else v + "Z"
    return None


def main():
    request("DELETE", f"/{INDEX}")
    request("PUT", f"/{INDEX}", MAPPING)
    total = 0
    for z in sorted(DATA.glob("*.zip")):
        lines = []
        with zipfile.ZipFile(z) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                for raw in zf.open(name):
                    r = json.loads(raw)
                    doc = {k: v for k, v in r.items() if not k.startswith("@")}
                    doc["@timestamp"] = timestamp(r)
                    doc["dataset"] = z.stem
                    try:
                        doc["EventID"] = int(r.get("EventID"))
                    except (TypeError, ValueError):
                        doc.pop("EventID", None)
                    for f in KEYWORD_FIELDS:
                        if f in doc and doc[f] is not None and not isinstance(doc[f], str):
                            doc[f] = str(doc[f])
                    lines.append(json.dumps({"index": {"_index": INDEX}}))
                    lines.append(json.dumps(doc))
        for i in range(0, len(lines), 4000):
            res = request("POST", "/_bulk", "\n".join(lines[i:i + 4000]) + "\n", ndjson=True)
            if res.get("errors"):
                bad = [it["index"]["error"] for it in res["items"] if "error" in it["index"]][:3]
                print("  some documents failed:", bad)
        total += len(lines) // 2
        print(f"{z.stem}: {len(lines) // 2} events")
    request("POST", f"/{INDEX}/_refresh")
    count = request("GET", f"/{INDEX}/_count")["count"]
    print(f"Done: sent {total} events, index '{INDEX}' now has {count} documents")


if __name__ == "__main__":
    main()
