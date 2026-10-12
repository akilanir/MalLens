#!/usr/bin/env python3
"""scripts/e0b_fn_autopsy.py — why did the behavior gate kill these TPs?"""
from droidlens.eval.common import load_labels, load_reports
from eA_sweep import ACTION_PAT, NAMING_PAT, reaggregate   # or copy the patterns

labels = load_labels("labels.csv")
for rep in load_reports("reports"):
    sha = rep["apk"]["sha256"].lower()
    if labels.get(sha) != "malware":
        continue
    if reaggregate(rep, 0.7, "off", 0, 2) == "malicious":
        continue                                    # still a TP, skip
    print(f"\n=== FN {sha[:12]} ===")
    for c in rep["clusters"]:
        v = c.get("llm")
        if not v or v["verdict"] not in ("malicious", "suspicious"):
            continue
        for b in v.get("behaviors", []):
            tag = "ACTION" if ACTION_PAT.search(b) else \
                  "NAMING" if NAMING_PAT.search(b) else "OTHER "
            print(f"  [{tag}] {b}")
