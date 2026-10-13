#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, math, warnings
from pathlib import Path
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

try:
    from scipy.stats import wilcoxon, friedmanchisquare, spearmanr
    SCIPY = True
except Exception:
    SCIPY = False

TOPK = [1, 5, 10, 15, 20]


# ---------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------

def finite(x):
    a = pd.to_numeric(pd.Series(x), errors="coerce").to_numpy(float)
    return a[np.isfinite(a)]

def avg(x):
    a = finite(x)
    return float(np.mean(a)) if len(a) else np.nan

def med(x):
    a = finite(x)
    return float(np.median(a)) if len(a) else np.nan

def sd(x):
    a = finite(x)
    return float(np.std(a, ddof=1)) if len(a) > 1 else 0.0

def mkdir(p):
    p.mkdir(parents=True, exist_ok=True)
    return p

def savefig(fig, path):
    mkdir(path.parent)
    fig.tight_layout()
    fig.savefig(path, dpi=220, bbox_inches="tight")
    plt.close(fig)

def parse_exp(name):
    r = {"family": name.split("_", 1)[0], "value": np.nan}
    if name == "E01_api_score": r.update(family="E01", value=0)
    elif name == "E01_attack_score": r.update(family="E01", value=1)
    elif name == "E04_manifest_0": r.update(family="E04", value=0)
    elif name == "E04_manifest_5": r.update(family="E04", value=5)
    elif name.startswith("E02_ppr_mu_"): r.update(family="E02", value=float(name.split("_")[-1]))
    elif name.startswith("E03_evidence_budget_K"): r.update(family="E03", value=float(name.split("K")[-1]))
    elif name.startswith("E05_seed_threshold_"): r.update(family="E05", value=float(name.split("threshold_")[-1]))
    elif name.startswith("E06_hops_"): r.update(family="E06", value=float(name.split("_")[-1]))
    elif name.startswith("E07_overlap_"): r.update(family="E07", value=float(name.split("_")[-1]))
    return r


# ---------------------------------------------------------------------
# LOAD STAGE-3 RESULTS
# ---------------------------------------------------------------------

def load_results(root):
    rows = []
    exp_dirs = []

    for d in sorted(root.iterdir()):
        if not d.is_dir() or not d.name.startswith("E"):
            continue
        p = d / "per_apk.csv"
        if p.exists():
            try:
                x = pd.read_csv(p)
                if not x.empty:
                    rows.append(x)
                    exp_dirs.append(d)
            except Exception as e:
                print(f"[WARN] {p}: {e}")

    if not rows:
        raise RuntimeError("No usable experiment/per_apk.csv files found.")

    df = pd.concat(rows, ignore_index=True)
    parsed = df["experiment"].map(parse_exp)
    df = pd.concat([df, pd.DataFrame(list(parsed))], axis=1)
    return df, exp_dirs


# ---------------------------------------------------------------------
# SUMMARIES
# ---------------------------------------------------------------------

def make_summary(df):
    metrics = [
        *[f"class_recall@{k}" for k in TOPK],
        *[f"cluster_coverage@{k}" for k in TOPK],
        "seed_payload_recall",
        "clusters_formed",
        "classes_covered",
        "coverage_ratio",
        "total_est_tokens",
        "mean_cluster_size",
        "payload_score_mean",
        "non_payload_score_mean",
    ]

    rows = []
    for exp, g in df.groupby("experiment"):
        r = {
            "experiment": exp,
            "family": g.family.iloc[0],
            "score_variant": g.score_variant.iloc[0],
            "n": len(g),
        }
        for m in metrics:
            if m in g:
                r[m+"_mean"] = avg(g[m])
                r[m+"_median"] = med(g[m])
                r[m+"_std"] = sd(g[m])
        rows.append(r)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------
# STATISTICS
# ---------------------------------------------------------------------

def paired_test(df, a, b, metric):
    if a not in set(df.experiment) or b not in set(df.experiment):
        return None

    x = df[df.experiment == a].set_index("sha256")[metric]
    y = df[df.experiment == b].set_index("sha256")[metric]
    common = x.index.intersection(y.index)

    if len(common) < 2:
        return None

    x, y = x.loc[common], y.loc[common]
    mask = x.notna() & y.notna()
    x, y = x[mask], y[mask]

    if len(x) < 2:
        return None

    d = y.to_numpy(float) - x.to_numpy(float)

    if not SCIPY:
        return {
            "n": len(d),
            "mean_difference": float(np.mean(d)),
            "median_difference": float(np.median(d)),
        }

    try:
        stat, p = wilcoxon(x, y)
        return {
            "n": len(d),
            "statistic": float(stat),
            "p_value": float(p),
            "mean_difference": float(np.mean(d)),
            "median_difference": float(np.median(d)),
            "positive_fraction": float(np.mean(d > 0)),
        }
    except Exception as e:
        return {"n": len(d), "error": repr(e)}


def run_stats(df, out):
    tests = {}
    comparisons = [
        ("api_vs_attack", "E01_api_score", "E01_attack_score"),
        ("manifest_0_vs_5", "E04_manifest_0", "E04_manifest_5"),
        ("base_vs_mixed", "E02_ppr_mu_1", "E02_ppr_mu_0.5"),
        ("mixed_vs_ppr", "E02_ppr_mu_0.5", "E02_ppr_mu_0"),
    ]
    metrics = [
        "class_recall@5",
        "class_recall@10",
        "class_recall@15",
        "class_recall@20",
        "cluster_coverage@10",
        "cluster_coverage@20",
    ]

    for name, a, b in comparisons:
        tests[name] = {}
        for m in metrics:
            z = paired_test(df, a, b, m)
            if z:
                tests[name][m] = z

    # Friedman for the three PPR settings.
    mus = ["E02_ppr_mu_0", "E02_ppr_mu_0.5", "E02_ppr_mu_1"]
    if SCIPY and all(x in set(df.experiment) for x in mus):
        tests["E02_friedman"] = {}
        for m in metrics:
            p = df[df.experiment.isin(mus)].pivot(
                index="sha256", columns="experiment", values=m
            ).dropna()
            if len(p) >= 3:
                try:
                    stat, pv = friedmanchisquare(
                        p[mus[0]], p[mus[1]], p[mus[2]]
                    )
                    tests["E02_friedman"][m] = {
                        "n": len(p),
                        "statistic": float(stat),
                        "p_value": float(pv),
                    }
                except Exception as e:
                    tests["E02_friedman"][m] = {"error": repr(e)}

    # Spearman parameter-response trends.
    for fam in ["E03", "E05", "E06"]:
        x = df[df.family == fam].copy()
        if x.empty:
            continue

        tests[f"{fam}_spearman"] = {}
        for m in [
            "class_recall@10",
            "class_recall@15",
            "class_recall@20",
            "cluster_coverage@20",
            "total_est_tokens",
        ]:
            z = x[["sha256", "value", m]].dropna()
            if SCIPY and len(z) >= 3:
                try:
                    rho, pv = spearmanr(z.value, z[m])
                    tests[f"{fam}_spearman"][m] = {
                        "n": len(z),
                        "rho": float(rho),
                        "p_value": float(pv),
                    }
                except Exception as e:
                    tests[f"{fam}_spearman"][m] = {"error": repr(e)}

    for k, v in tests.items():
        (out / f"{k}.json").write_text(
            json.dumps(v, indent=2),
            encoding="utf-8",
        )
    return tests


# ---------------------------------------------------------------------
# PLOTS
# ---------------------------------------------------------------------

def violin(values, labels, ylabel, title, path):
    vals = [finite(v) for v in values]
    vals = [v for v in vals if len(v)]
    if not vals:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.violinplot(vals, showmeans=True, showmedians=True)
    ax.set_xticks(range(1, len(vals)+1), labels[:len(vals)])
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    savefig(fig, path)


def line_family(df, family, metric, xlabel, ylabel, title, path):
    g = df[df.family == family].copy()
    if g.empty or metric not in g:
        return

    z = g.groupby("value")[metric].agg(["mean", "std"]).reset_index()
    z = z.sort_values("value")
    if z.empty:
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.errorbar(
        z.value,
        z["mean"],
        yerr=z["std"],
        marker="o",
        capsize=4,
    )
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    savefig(fig, path)


def plot_e01(df, root):
    g = df[df.experiment.isin(
        ["E01_api_score", "E01_attack_score"]
    )]

    if g.empty:
        return

    d = mkdir(root / "E01")

    fig, ax = plt.subplots(figsize=(8, 5))
    for exp, label in [
        ("E01_api_score", "API"),
        ("E01_attack_score", "ATT&CK"),
    ]:
        x = g[g.experiment == exp]
        ax.plot(
            TOPK,
            [avg(x[f"class_recall@{k}"]) for k in TOPK],
            marker="o",
            label=label,
        )
    ax.set_xlabel("Top-K ranked classes")
    ax.set_ylabel("Mean payload Recall@K")
    ax.set_ylim(0, 1.05)
    ax.legend()
    savefig(fig, d / "recall_at_k.png")

    violin(
        [
            g[g.experiment == "E01_api_score"]["class_recall@15"],
            g[g.experiment == "E01_attack_score"]["class_recall@15"],
        ],
        ["API", "ATT&CK"],
        "Payload Recall@15",
        "API vs ATT&CK Recall@15",
        d / "violin_recall15.png",
    )

    metrics = [
        "class_recall@5",
        "class_recall@10",
        "class_recall@15",
        "class_recall@20",
    ]

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(metrics))
    w = .35

    for off, exp, label in [
        (-w/2, "E01_api_score", "API"),
        (w/2, "E01_attack_score", "ATT&CK"),
    ]:
        z = g[g.experiment == exp]
        ax.bar(
            x + off,
            [avg(z[m]) for m in metrics],
            w,
            label=label,
        )

    ax.set_xticks(x, ["R@5", "R@10", "R@15", "R@20"])
    ax.set_ylabel("Mean payload recall")
    ax.set_ylim(0, 1.05)
    ax.legend()
    savefig(fig, d / "bar_recall.png")


def plot_e02(df, root):
    g = df[df.family == "E02"]
    if g.empty:
        return

    d = mkdir(root / "E02")

    line_family(
        df,
        "E02",
        "class_recall@15",
        "mu",
        "Mean payload Recall@15",
        "PPR mixing sensitivity",
        d / "mu_recall15.png",
    )

    line_family(
        df,
        "E02",
        "cluster_coverage@20",
        "mu",
        "Mean payload coverage@20",
        "PPR mixing and payload coverage",
        d / "mu_coverage20.png",
    )

    exps = ["E02_ppr_mu_0", "E02_ppr_mu_0.5", "E02_ppr_mu_1"]
    violin(
        [
            g[g.experiment == e]["class_recall@15"]
            for e in exps
        ],
        ["mu=0", "mu=0.5", "mu=1"],
        "Payload Recall@15",
        "Recall distribution by PPR mixing",
        d / "violin_recall15.png",
    )


def plot_e03(df, root):
    g = df[df.family == "E03"]
    if g.empty:
        return

    d = mkdir(root / "E03")

    line_family(df, "E03", "class_recall@15",
                 "Evidence-unit budget K",
                 "Mean payload Recall@15",
                 "Evidence budget vs recall",
                 d / "budget_recall15.png")

    line_family(df, "E03", "cluster_coverage@20",
                 "Evidence-unit budget K",
                 "Mean payload coverage@20",
                 "Evidence budget vs coverage",
                 d / "budget_coverage20.png")

    line_family(df, "E03", "total_est_tokens",
                 "Evidence-unit budget K",
                 "Mean estimated evidence tokens",
                 "Evidence budget vs evidence size",
                 d / "budget_tokens.png")

    vals, labels = [], []
    for v in sorted(g.value.dropna().unique()):
        vals.append(g[g.value == v]["class_recall@15"])
        labels.append(f"K={int(v)}")

    violin(
        vals,
        labels,
        "Payload Recall@15",
        "Recall distribution across evidence budgets",
        d / "violin_recall15.png",
    )


def plot_e04(df, root):
    g = df[df.family == "E04"]
    if g.empty:
        return

    d = mkdir(root / "E04")
    exps = ["E04_manifest_0", "E04_manifest_5"]

    metrics = [
        "class_recall@10",
        "class_recall@15",
        "cluster_coverage@20",
        "seed_payload_recall",
    ]

    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(metrics))
    w = .35

    for off, exp, label in [
        (-w/2, exps[0], "Manifest=0"),
        (w/2, exps[1], "Manifest=5"),
    ]:
        z = g[g.experiment == exp]
        ax.bar(
            x + off,
            [avg(z[m]) for m in metrics],
            w,
            label=label,
        )

    ax.set_xticks(
        x,
        ["Recall@10", "Recall@15", "Coverage@20", "Seed recall"],
    )
    ax.set_ylim(0, 1.05)
    ax.legend()
    ax.set_ylabel("Mean value")
    ax.set_title("Manifest-seed ablation")
    savefig(fig, d / "manifest_ablation.png")


def plot_e05(df, root):
    if df[df.family == "E05"].empty:
        return
    d = mkdir(root / "E05")
    line_family(df, "E05", "class_recall@15",
                 "Seed suspicion threshold",
                 "Mean payload Recall@15",
                 "Seed threshold sensitivity",
                 d / "threshold_recall15.png")
    line_family(df, "E05", "cluster_coverage@20",
                 "Seed suspicion threshold",
                 "Mean payload coverage@20",
                 "Seed threshold vs coverage",
                 d / "threshold_coverage20.png")


def plot_e06(df, root):
    if df[df.family == "E06"].empty:
        return
    d = mkdir(root / "E06")
    line_family(df, "E06", "class_recall@15",
                 "Maximum graph hops",
                 "Mean payload Recall@15",
                 "Graph expansion depth vs recall",
                 d / "hops_recall15.png")
    line_family(df, "E06", "cluster_coverage@20",
                 "Maximum graph hops",
                 "Mean payload coverage@20",
                 "Graph expansion depth vs coverage",
                 d / "hops_coverage20.png")
    line_family(df, "E06", "total_est_tokens",
                 "Maximum graph hops",
                 "Mean estimated evidence tokens",
                 "Graph expansion depth vs evidence size",
                 d / "hops_tokens.png")


def plot_e07(df, root):
    if df[df.family == "E07"].empty:
        return
    d = mkdir(root / "E07")
    line_family(df, "E07", "class_recall@15",
                 "Maximum class membership",
                 "Mean payload Recall@15",
                 "Overlap limit vs recall",
                 d / "overlap_recall15.png")


def plot_overview(df, root):
    d = mkdir(root / "overview")

    z = df.groupby("experiment")["class_recall@15"].agg(
        ["mean", "std"]
    ).sort_values("mean", ascending=True)

    if not z.empty:
        fig, ax = plt.subplots(figsize=(10, 7))
        y = np.arange(len(z))
        ax.barh(y, z["mean"], xerr=z["std"])
        ax.set_yticks(y, z.index)
        ax.set_xlabel("Mean payload Recall@15")
        ax.set_xlim(0, 1.05)
        ax.set_title("Stage-3 experiment comparison")
        savefig(fig, d / "all_experiments_recall15.png")

    cols = [f"class_recall@{k}" for k in TOPK]
    h = df.groupby("experiment")[cols].mean()

    if not h.empty:
        fig, ax = plt.subplots(
            figsize=(9, max(6, len(h) * .35))
        )
        im = ax.imshow(
            h.to_numpy(),
            aspect="auto",
            vmin=0,
            vmax=1,
        )
        ax.set_xticks(
            range(len(cols)),
            ["R@1", "R@5", "R@10", "R@15", "R@20"],
        )
        ax.set_yticks(
            range(len(h)),
            h.index,
        )
        ax.set_title("Mean payload Recall@K")
        fig.colorbar(im, ax=ax, label="Recall")
        savefig(fig, d / "recall_heatmap.png")

    z = df.groupby("experiment").agg(
        recall15=("class_recall@15", "mean"),
        tokens=("total_est_tokens", "mean"),
    ).reset_index()

    if not z.empty:
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.scatter(z.tokens, z.recall15, s=60)
        for _, r in z.iterrows():
            ax.annotate(
                r.experiment,
                (r.tokens, r.recall15),
                xytext=(5, 5),
                textcoords="offset points",
                fontsize=8,
            )
        ax.set_xlabel("Mean estimated evidence tokens")
        ax.set_ylabel("Mean payload Recall@15")
        ax.set_ylim(0, 1.05)
        ax.set_title("Evidence-selection efficiency frontier")
        savefig(fig, d / "recall_vs_tokens.png")


# ---------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------

def write_report(df, summary, stats, path):
    lines = [
        "DROIDLEN / MYSTIQUE STAGE-3 ANALYSIS",
        "=" * 60,
        "",
        f"APKs: {df.sha256.nunique()}",
        f"Experiment rows: {len(df)}",
        f"Experiments: {df.experiment.nunique()}",
        "",
        "BEST EXPERIMENTS",
        "-" * 60,
    ]

    for metric in [
        "class_recall@5",
        "class_recall@10",
        "class_recall@15",
        "class_recall@20",
        "cluster_coverage@10",
        "cluster_coverage@20",
    ]:
        col = metric + "_mean"
        if col not in summary:
            continue

        z = summary.dropna(subset=[col])
        if z.empty:
            continue

        r = z.loc[z[col].idxmax()]
        lines.append(
            f"{metric:25s} {r.experiment:30s} {r[col]:.4f}"
        )

    lines += [
        "",
        "E07 NOTE",
        "-" * 60,
        (
            "E07 overlap analysis is included only when E07 results "
            "exist. Missing E07 is expected when max_membership is not "
            "available in the active DroidLens configuration."
        ),
        "",
        "INTERPRETATION",
        "-" * 60,
        (
            "These Mystique experiments evaluate Stage-3 evidence "
            "selection/localization using known malicious payload "
            "classes. They do not measure end-to-end LLM malware "
            "classification performance."
        ),
        (
            "With only 10 APKs, use the results primarily for "
            "debugging, parameter screening, and selecting promising "
            "configurations before the full Mystique run."
        ),
    ]

    path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--results-root",
        required=True,
        help="Timestamped Stage-3 results directory.",
    )
    ap.add_argument(
        "--no-stats",
        action="store_true",
    )
    args = ap.parse_args()

    root = Path(args.results_root)
    if not root.exists():
        raise SystemExit(f"Not found: {root}")

    analysis = mkdir(root / "analysis")
    extracted = mkdir(analysis / "extracted")
    plots = mkdir(analysis / "plots")
    stats = mkdir(analysis / "statistical_tests")

    print("[1/6] Loading results...")
    df, exp_dirs = load_results(root)

    print(f"      APKs={df.sha256.nunique()}")
    print(f"      experiments={df.experiment.nunique()}")

    print("[2/6] Extracting tables...")
    df.to_csv(
        extracted / "all_per_apk.csv",
        index=False,
    )

    summary = make_summary(df)
    summary.to_csv(
        extracted / "experiment_summary.csv",
        index=False,
    )

    payload_cols = [
        "experiment",
        "family",
        "sha256",
        "apk",
        "n_payload_classes",
        "class_recall@1",
        "class_recall@5",
        "class_recall@10",
        "class_recall@15",
        "class_recall@20",
        "cluster_coverage@1",
        "cluster_coverage@5",
        "cluster_coverage@10",
        "cluster_coverage@15",
        "cluster_coverage@20",
        "seed_payload_recall",
        "first_payload_cluster_rank",
    ]
    payload_cols = [
        c for c in payload_cols if c in df
    ]
    df[payload_cols].to_csv(
        extracted / "payload_level.csv",
        index=False,
    )

    # Copy cluster-level JSON information into a flat table.
    cluster_rows = []
    for exp in exp_dirs:
        cdir = exp / "clusters"
        if not cdir.exists():
            continue
        for f in cdir.glob("*.json"):
            try:
                x = json.loads(
                    f.read_text(
                        encoding="utf-8"
                    )
                )
                for c in x.get("clusters", []):
                    cluster_rows.append({
                        "experiment": exp.name,
                        "sha256": f.stem,
                        "rank": c.get("rank"),
                        "cluster_id": c.get("cluster_id"),
                        "seed_class": c.get("seed_class"),
                        "importance": c.get("importance"),
                        "estimated_tokens": c.get("est_tokens"),
                        "n_classes": c.get("n_classes"),
                        "contains_payload": bool(
                            c.get("payload_classes")
                        ),
                        "n_payload_classes": len(
                            c.get(
                                "payload_classes",
                                []
                            )
                        ),
                    })
            except Exception as e:
                print(f"[WARN] {f}: {e}")

    if cluster_rows:
        pd.DataFrame(cluster_rows).to_csv(
            extracted / "cluster_level.csv",
            index=False,
        )

    print("[3/6] Paired/statistical analysis...")
    tests = {}
    if not args.no_stats:
        tests = run_stats(
            df,
            stats,
        )

    print("[4/6] Generating experiment plots...")
    plot_e01(df, plots)
    plot_e02(df, plots)
    plot_e03(df, plots)
    plot_e04(df, plots)
    plot_e05(df, plots)
    plot_e06(df, plots)
    plot_e07(df, plots)

    print("[5/6] Generating overview plots...")
    plot_overview(df, plots)

    print("[6/6] Writing report...")

    report = {
        "n_apks": int(df.sha256.nunique()),
        "n_rows": int(len(df)),
        "experiments": sorted(
            df.experiment.unique().tolist()
        ),
        "families": sorted(
            df.family.unique().tolist()
        ),
        "scipy_available": SCIPY,
        "E07_available": bool(
            (df.family == "E07").any()
        ),
    }

    (analysis / "analysis_report.json").write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    write_report(
        df,
        summary,
        tests,
        analysis / "analysis_report.txt",
    )

    print(
        f"\nDONE\nAnalysis: {analysis}"
    )


if __name__ == "__main__":
    main()