import csv, re, ipaddress
 
RAW = "../../week02/iocs_raw.txt"
OUT = "../data/iocs_clean.csv"
 
def refang(value):
    """Turn 'hxxp://evil[.]com' back into 'http://evil.com'."""
    value = value.strip()
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    value = re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)
    return value
 
def classify(value):
    if re.fullmatch(r"[a-fA-F0-9]{64}", value): return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value): return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value): return "md5"
    try:
        ip = ipaddress.ip_address(value)
        return "ip-private" if ip.is_private else "ip"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")): return "url"
    if re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", value): return "domain"
    return "unknown"
 
seen, kept, dropped = set(), [], []
with open(RAW, encoding="utf-8") as f:
    for line in f:
        value = refang(line)
        if not value or value.startswith("#"):
            continue                                
        kind = classify(value)
        if kind in ("sha256", "sha1", "md5", "domain"):
            value = value.lower()                    
        if kind in ("ip-private", "unknown"):
            dropped.append((value, kind)); continue  
        if value in seen:
            dropped.append((value, "duplicate")); continue
        seen.add(value)
        kept.append({"value": value, "type": kind, "source": "CISA AA24-131A"})
 
with open(OUT, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["value", "type", "source"])
    writer.writeheader()
    writer.writerows(kept)
 
print(f"Kept {len(kept)} indicators, dropped {len(dropped)}:")
for value, reason in dropped:
    print(f"  {reason:10} {value}")
