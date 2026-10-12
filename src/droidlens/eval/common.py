from __future__ import annotations
import csv, json
from pathlib import Path

def load_labels(path: str) -> dict[str, str]:
    with open(path) as f:
        return {r["sha256"].lower(): r["label"].strip().lower()
                for r in csv.DictReader(f)}

def load_reports(reports_dir: str, name: str = "report.json") -> list[dict]:
    out = []
    for p in Path(reports_dir).glob(f"*/{name}"):
        out.append(json.loads(p.read_text()))
        out[-1]["_path"] = str(p)
    return out

def metrics(rows: list[tuple[str, str]]) -> dict:
    """rows: (label, predicted_verdict). positive = malware/malicious."""
    tp = sum(1 for l, v in rows if l == "malware" and v == "malicious")
    fp = sum(1 for l, v in rows if l == "benign" and v == "malicious")
    fn = sum(1 for l, v in rows if l == "malware" and v != "malicious")
    tn = sum(1 for l, v in rows if l == "benign" and v != "malicious")
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}
