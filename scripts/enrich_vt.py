import csv, os, time, requests

API_KEY = os.environ["VT_API_KEY"]          # export VT_API_KEY=... in the terminal
HEADERS = {"x-apikey": API_KEY}
ENDPOINT = {"sha256": "files", "sha1": "files", "md5": "files",
            "ip": "ip_addresses", "domain": "domains"}

results = []
with open("iocs_clean.csv", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        kind = ENDPOINT.get(row["type"])
        if not kind:
            continue
        url = f"https://www.virustotal.com/api/v3/{kind}/{row['value']}"
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
            verdict = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
        elif r.status_code == 404:
            verdict = "not found"
        else:
            verdict = f"error {r.status_code}"
        results.append({**row, "vt_malicious": verdict,
                        "checked_at": time.strftime("%Y-%m-%d %H:%M")})
        print(row["value"], verdict)
        time.sleep(16)                      # free API allows 4 requests per minute

with open("iocs_enriched.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
    w.writeheader()
    w.writerows(results)
