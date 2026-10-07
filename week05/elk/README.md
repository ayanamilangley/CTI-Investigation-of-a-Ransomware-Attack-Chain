# ELK lab for the Week 5 hunt

Needs Docker Desktop (the same as for MISP in Week 3) and about 4 GB of free RAM.

## 1. Start Elasticsearch and Kibana

```bash
cd week05/elk
docker compose up -d
```

Wait 1–2 minutes, then open http://localhost:9200 — you should see a JSON answer with `"cluster_name"`.

## 2. Load the logs

```bash
python3 load_to_elk.py
```

Expected output ends with:

```
Done: sent 24194 events, index 'blackbasta-hunt' now has 24194 documents
```

## 3. Create a data view in Kibana

1. Open http://localhost:5601
2. ☰ menu → **Stack Management → Data Views → Create data view**
3. Name and index pattern: `blackbasta-hunt`, timestamp field: `@timestamp` → **Save**
4. ☰ menu → **Discover**, choose `blackbasta-hunt`, set the time range to **Last 10 years**
5. Add columns: `Hostname`, `EventID`, `Image`, `ParentImage`, `CommandLine`, `dataset`

## 4. Run the hunts and take screenshots

Paste each query from [`../queries/kibana_kql.md`](../queries/kibana_kql.md) into the search bar. Save screenshots with these names in `week05/images/` (the report already links to them):

| Screenshot file | Query | Expected |
|---|---|---|
| `kibana_overview.png` | (empty search) | 24,194 hits |
| `kibana_h1.png` | H1 | 1 hit, WORKSTATION6, `-enc` |
| `kibana_h1_pivot.png` | H1 pivot 2 | 7045 + 4697 "Updater", Sysmon 3 to 10.10.10.5:80 |
| `kibana_h2.png` | H2 | 1 hit, bitsadmin |
| `kibana_h3.png` | H3 | 2 hits, vssadmin + rundll32 comsvcs |
| `kibana_h3_lsass.png` | H3 LSASS access | 2 hits, rundll32 |

Tip: click a row and open the document view to show the full `CommandLine`.

## 5. Stop

```bash
docker compose down        # keep the data
docker compose down -v     # delete the data too
```

Security is turned off in this lab (`xpack.security.enabled=false`), and the ports listen only on localhost. Do not use this setup on a real server.
