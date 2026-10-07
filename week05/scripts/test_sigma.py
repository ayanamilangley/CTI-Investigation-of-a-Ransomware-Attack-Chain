"""
Check that our 4 Sigma rules (../queries/sigma/*.yml) are valid and find the
same events as hunt.py. Also prints each rule converted to Splunk and Lucene.

Run:  pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
      python3 test_sigma.py
"""

import fnmatch
import re
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

import hunt

RULES = Path(__file__).resolve().parent.parent / "queries" / "sigma"


def item_matches(item, event):
    value = str(event.get(item.field, "")).lower()
    patterns = [str(v).lower().replace("[", "[[]") for v in item.value]
    need_all = any(m.__name__ == "SigmaAllModifier" for m in item.modifiers)
    check = all if need_all else any
    return check(fnmatch.fnmatchcase(value, p) for p in patterns)


def rule_matches(rule, event):
    det = rule.detection
    results = {name: all(item_matches(i, event) for i in sel.detection_items)
               for name, sel in det.detections.items()}
    condition = re.sub(r"\b(selection\w*)\b", lambda m: f"R['{m.group(1)}']", det.condition[0])
    return eval(condition, {}, {"R": results})  # condition text comes from our own rule files


def main():
    proc = [r for r in hunt.load_events() if hunt.is_sysmon(r, 1)]
    for f in sorted(RULES.glob("*.yml")):
        coll = SigmaCollection.from_yaml(f.read_text())
        rule = coll.rules[0]
        hits = [r for r in proc if rule_matches(rule, r)]
        print(f"\n== {f.name}: {len(hits)} hit(s)")
        for r in hits:
            print(f"   {r['_host']}  {hunt.exe(r['Image'])}  {r['CommandLine'][:70]}")
        print("   Splunk:", SplunkBackend().convert(coll)[0])
        print("   Lucene:", LuceneBackend().convert(coll)[0])


if __name__ == "__main__":
    main()
