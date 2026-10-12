#!/usr/bin/env python3
"""FP autopsy: which rules leak, and is confidence separable?"""
import argparse
from collections import Counter
from droidlens.eval.common import load_labels, load_reports

def flagged_clusters(rep):
    return [c for c in rep["clusters"] if c.get("llm")
            and c["llm"]["verdict"] in ("malicious", "suspicious")]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--labels", default="labels.csv")
    args = ap.parse_args()
    labels = load_labels(args.labels)

    fp_rules, tp_rules = Counter(), Counter()
    fp_conf, tp_conf = [], []
    fp_behav = Counter()
    fp_shas = []

    for rep in load_reports(args.reports):
        lab = labels.get(rep["apk"]["sha256"].lower())
        if lab is None or rep["verdict"]["verdict"] != "malicious":
            continue
        bucket = "FP" if lab == "benign" else "TP"
        # first token of each rule string = rule family
        rules = tuple(sorted(r.split(":")[0] + ":" + r.split(":")[1][:40]
                             for r in rep["verdict"]["rules_fired"]))
        confs = [c["llm"]["confidence"] for c in flagged_clusters(rep)]
        if bucket == "FP":
            fp_rules[rules] += 1; fp_conf += confs; fp_shas.append(rep["apk"]["sha256"][:12])
            for c in flagged_clusters(rep):
                fp_behav.update(c["llm"]["behaviors"])
        else:
            tp_rules[rules] += 1; tp_conf += confs

    def hist(confs, tag):
        bins = Counter(round(c, 1) for c in confs)
        print(f"  {tag} cluster-confidence histogram: "
              + "  ".join(f"{b:.1f}:{n}" for b, n in sorted(bins.items())))

    print("=== RULES FIRED (FP) ===")
    for r, n in fp_rules.most_common():
        print(f"  {n:3d}x  {r}")
    print("=== RULES FIRED (TP) ===")
    for r, n in tp_rules.most_common():
        print(f"  {n:3d}x  {r}")
    print("=== CONFIDENCE SEPARABILITY ===")
    hist(fp_conf, "FP"); hist(tp_conf, "TP")
    print("=== TOP BEHAVIORS CITED IN FP CLUSTERS ===")
    for b, n in fp_behav.most_common(15):
        print(f"  {n:3d}x  {b}")
    print(f"\nFP shas: {fp_shas}")

if __name__ == "__main__":
    main()
