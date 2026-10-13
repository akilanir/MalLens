"""Stage-3 localization probe: does the known payload reach the clusters?
No LLM calls. Runs stages 1-3 (cached) per APK, compares against
ground-truth payload package prefixes, emits per-APK PNGs + summary CSV.
"""
from __future__ import annotations
import argparse, csv, sys
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict

from mallens.config import Config
from mallens.importance.scorers import get_scorer
# ... whatever scripts/03_rank_clusters.py uses to produce s1, s2, s3.
# Factor that into a function there and import it:
from scripts.misc.scripts_common import run_stages_1_to_3      # (s1, s2, s3) = f(cfg, apk)

# SCORERS = ["pagerank", "naive", "propagation"]     # adapt to your registry
SCORERS = ["pagerank"]
TOPK = (1, 5, 10, 15, 20)


def to_dex_prefix(pkg: str) -> str:
    return "L" + pkg.strip().rstrip(".").replace(".", "/") + "/"

def compute_scores(s1, s2, cfg, scorer_name: str) -> dict[str, float]:
    scorer = get_scorer(scorer_name)
    # print(f"------------- SCORER: {scorer_name} | {scorer}")
    scores = scorer.score(s1, s2, cfg)
    # print(f"---------- Scores: {scores}")
    return scores

def probe_apk(cfg, apk: Path, prefixes: list[str], out_dir: Path) -> dict:
    s1, s2, s3 = run_stages_1_to_3(apk,cfg, force=True) #(This is where we generate graphs, suspicion classes, and rank clusters Sample code is given later)
    app_classes = list(s2.records.keys())
    payload = {c for c in app_classes if any(c.startswith(p) for p in prefixes)}
    clusters = sorted(s3.clusters, key=lambda c: -c.importance)

    # This you can add
    print("=="*30)
    print(f"Payload: {payload}")
    for c in clusters:
        print(f"Clusters: {c.class_names}\n")
    print("=="*30)


    hits_per_cluster = [len(payload & set(c.class_names)) for c in clusters]
    covered_at = {k: len(payload & {m for c in clusters[:k]
                                    for m in c.class_names}) for k in TOPK}
    first_hit = next((i + 1 for i, h in enumerate(hits_per_cluster) if h), None)
    seed_hits = sum(1 for c in clusters if c.seed_class in payload)

    # payload importance percentile under each scorer (cheap: graph reuse)
    pctl = {}
    for sc in SCORERS:
        scores = compute_scores(s1, s2, cfg, sc)   # adapt: your scorer API
        # print("Point 8-I")
        vals = np.array([scores.get(c, 0.0) for c in app_classes])
        # print("Point 8-II")
        ranks = vals.argsort().argsort() / max(len(vals) - 1, 1)
        # print("Point 8-III")
        pp = [ranks[app_classes.index(c)] for c in payload] if payload else []
        # print("Point 8-IV")
        pctl[sc] = float(np.median(pp)) if pp else float("nan")
        # print("Point 8-V")

    row = dict(
        apk=apk.name[:12], family=apk.parent.name,
        n_app=len(app_classes), n_payload=len(payload),
        payload_found_in_dex=bool(payload),
        seed_hits=seed_hits, first_hit_rank=first_hit,
        **{f"cov@{k}": (covered_at[k] / len(payload) if payload else 0.0)
           for k in TOPK},
        **{f"pctl_{sc}": round(pctl[sc], 3) for sc in SCORERS},
    )
    # print("Point 8-VI")
    plot_apk(row,scores, clusters, hits_per_cluster, payload,
             s1, s2, out_dir / apk.parent.name / f"{apk.name[:12]}.png")
    # print("Point 10")
    return row


def plot_apk(row, scores, clusters, hits, payload, s1, s2, png: Path):
    png.parent.mkdir(parents=True, exist_ok=True)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # print("Point 8-VII")

    # left: clusters by rank, stacked payload (red) / other (grey)
    sizes = [len(c.class_names) for c in clusters]
    other = [s - h for s, h in zip(sizes, hits)]
    x = range(1, len(clusters) + 1)
    ax1.bar(x, other, color="#bbbbbb", label="non-payload")
    ax1.bar(x, hits, bottom=other, color="#d62728", label="payload")
    ax1.axvline(10.5, ls="--", c="k", lw=1)         # analysis budget line
    ax1.set(xlabel="cluster rank (by importance)", ylabel="classes",
            title=f"{row['family']}/{row['apk']}  "
                  f"cov@10={row['cov@10']:.0%}  seeds={row['seed_hits']}")
    ax1.legend()

    # print("Point 8-VIII")
    ordered = sorted(scores, key=scores.get, reverse=True)
    ys = [scores[c] for c in ordered]
    pos = {c: i for i, c in enumerate(ordered)}         # O(1) lookup,
    pidx = [pos[c] for c in payload if c in pos]        # not list.index()
    ax2.plot(ys, ".", ms=2, c="#bbbbbb")
    ax2.plot(pidx, [ys[i] for i in pidx], "o", ms=5, c="#d62728")
    ax2.set(yscale="log", xlabel="class rank", ylabel="importance (log)",
            title="payload classes in the importance ranking")
    fig.tight_layout(); fig.savefig(png, dpi=130); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", default="probe_out")
    a = ap.parse_args()
    cfg, out = Config.load(a.config), Path(a.out)

    rows = []
    def load_prefixes(apk_name, payload_data):
        """
        apk_name: "apk_1.apk" or Path(...)
        payload_data: dict[str, list[str]]
        """
        print(f"APK: {apk_name}")
        if not isinstance(apk_name, str):
            apk_name = apk_name.stem
        return payload_data.get(apk_name, [])

    for fam_dir in sorted(Path(a.root).iterdir()):
        if not fam_dir.is_dir(): continue

        # prefixes = [to_dex_prefix(l) for l in (fam_dir / "payload.txt").read_text().splitlines() if l.strip()]
        # We should extract prefixes for each apk (prefixes is a list of strings
        payload_data = defaultdict(list)
        payload_file = fam_dir / "payload.txt"
        for line in payload_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            apk_name, prefix = map(str.strip, line.split(":", 1))
            payload_data[apk_name].append(to_dex_prefix(prefix))
        # payload.txt will have data 
        """
        apk_1: android/system
        apk_1: com/facebook
        apk_2: me.hawkshaw
        apk_3: com/google/gms
        apk_3: org/util
        apk_3: ur/log/logger
        """
        for apk in sorted(fam_dir.glob("*.apk")):
            try:
                prefixes = load_prefixes(apk.stem,payload_data)
                print(f"Prefixes: {prefixes}")
                rows.append(probe_apk(cfg, apk, prefixes, out))
                # print("Point 9 -----------")
                print(f"{rows[-1]['family']:14s} {rows[-1]['apk']}  "
                      f"payload={rows[-1]['n_payload']:4d}  "
                      f"cov@10={rows[-1]['cov@10']:.0%}  "
                      f"first_hit={rows[-1]['first_hit_rank']}")
                # print("Point 11")
            except Exception as e:
                print(f"FAIL {apk.name}: {e}", file=sys.stderr)

    with open(out / "probe_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)

    # family-level summary figure
    fams = sorted({r["family"] for r in rows})
    fig, ax = plt.subplots(figsize=(10, 4))
    for i, fam in enumerate(fams):
        vals = [r["cov@10"] for r in rows if r["family"] == fam]
        ax.scatter([i] * len(vals), vals, c="#d62728", zorder=3)
        ax.bar(i, np.mean(vals), color="#bbbbbb", zorder=2)
    ax.set_xticks(range(len(fams)), fams)
    ax.set(ylabel="payload coverage@10", ylim=(0, 1.05),
           title="Oracle recall ceiling per family (Stage-3 localization)")
    fig.tight_layout(); fig.savefig(out / "family_summary.png", dpi=130)
    print(f"\nMean cov@10: {np.mean([r['cov@10'] for r in rows]):.2%}")

if __name__ == "__main__":
    main()
