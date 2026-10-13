#!/usr/bin/env python3
"""Sweep aggregation params over existing reports. Zero LLM calls."""
import re
import argparse, itertools
from mallens.eval.common import load_labels, load_reports, metrics

ACTION_PAT = re.compile(
    r"sms|premium|exfil|c2|command.and.control|dynamic.*(load|dex|code)|"
    r"dexclassloader|shell|su\b|root|keylog|overlay|accessibility|"
    r"record|screenshot|contact|location.*(upload|send|exfil)|"
    r"encrypt.*(file|storage)|ransom|device.admin|hide.*icon|"
    r"install.*(apk|package)|abort.*broadcast", re.I)

NAMING_PAT = re.compile(r"framework.style|masquerad|spoof|class.nam|obfuscat", re.I)

def has_action_evidence(v):
    return any(ACTION_PAT.search(b) and not NAMING_PAT.fullmatch(b)
               for b in v.get("behaviors", []))


def reaggregate(rep, t_mal, corrob, min_quotes, min_ev_classes,
                quote_key="evidence"):
    hard, soft = [], []
    for c in rep["clusters"]:
        v = c.get("llm")
        if not v or v["verdict"] not in ("malicious", "suspicious"):
            continue
        ev = v.get(quote_key, [])
        n_classes = len({e["class_name"] for e in ev})
        if len(ev) < min_quotes or n_classes < min_ev_classes:
            continue                      # evidence-gate: cluster doesn't count
        if not has_action_evidence(v):
            continue
        if v["verdict"] == "malicious" and v["confidence"] >= t_mal:
            hard.append(c)
        if v["confidence"] >= 0.5:
            soft.append(c)
    if hard:
        return "malicious"
    if corrob == "host" and len(soft) >= 2:
        def hosts(c):
            out = set()
            for i in c["llm"]["network_indicators"]:
                h = i.lower()
                for p in ("https://", "http://"): h = h.removeprefix(p)
                out.add(h.split("/")[0].split(":")[0])
            return out
        for a, b in itertools.combinations(soft, 2):
            if hosts(a) & hosts(b):
                return "malicious"
    return "suspicious" if soft else "benign"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--labels", default="labels.csv")
    ap.add_argument("--report-name", default="report.json")
    ap.add_argument("--quote-key", default="evidence")   # eB sets 'verified_evidence'
    args = ap.parse_args()
    labels = load_labels(args.labels)
    reps = [r for r in load_reports(args.reports, args.report_name)
            if r["apk"]["sha256"].lower() in labels]

    grid = itertools.product(
        [0.7, 0.8, 0.9, 0.95],       # t_mal
        ["off", "host"],             # corroboration
        [0, 2],                      # min_quotes
        [0, 2])                      # min_evidence_classes
    results = []
    for t, co, mq, mc in grid:
        rows = [(labels[r["apk"]["sha256"].lower()],
                 reaggregate(r, t, co, mq, mc, args.quote_key)) for r in reps]
        results.append(((t, co, mq, mc), metrics(rows)))
    results.sort(key=lambda x: -x[1]["f1"])
    print(f"{'t_mal':>5} {'corrob':>6} {'minQ':>4} {'minC':>4} | "
          f"{'P':>5} {'R':>5} {'F1':>5} | TP FP TN FN")
    for (t, co, mq, mc), m in results:
        print(f"{t:>5} {co:>6} {mq:>4} {mc:>4} | "
              f"{m['precision']:>5} {m['recall']:>5} {m['f1']:>5} | "
              f"{m['TP']} {m['FP']} {m['TN']} {m['FN']}")

if __name__ == "__main__":
    main()



# change if you want
# SDK_HOSTS = 
# def hosts(c):
#     out = set()
#     for i in c["llm"]["network_indicators"]:
#         h = i.lower()
#         for p in ("https://", "http://"): h = h.removeprefix(p)
#         h = h.split("/")[0].split(":")[0]
#         if not any(s in h for s in SDK_HOSTS):   # <-- here
#             out.add(h)
#     return out
