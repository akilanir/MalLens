#!/usr/bin/env python3
"""feature_census.py -- raw feature-frequency census over a labeled corpus.

Phases (all runnable independently, later phases read earlier outputs):
  extract    S1+S2 per APK (cache-aware, crash-resumable) -> census_raw.jsonl
  aggregate  jsonl -> feature_census.csv (+ sorted views)
  plot       csv   -> PNGs in <out>/plots/

Usage:
  python feature_census.py --benign /data/icse/benign --malware /data/icse/malware \
      --out results/census_icse [--phase all|extract|aggregate|plot] [--limit N]

No scoring, no weighting -- raw stats only.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import traceback
from pathlib import Path

import pandas as pd

from droidlens.config import Config
from droidlens.ingest.runner import build_class_graph
from droidlens.features.vectorize import extract_features
from droidlens.utils.cache import ArtifactCache, sha256_of_file
from droidlens.utils.logsetup import setup_logging
from droidlens.features.api_taxonomy import ApiTaxonomy

# log = logging.getLogger("droidlens.census")
from loguru import logger
cfg = Config.load("/mnt/SATA_3/akila/AK_PHD3/droidlens3/configs/default.yaml")
setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)

TAGS = {
    "Ldalvik/system/DexClassLoader;": "dexload",
    "Ldalvik/system/InMemoryDexClassLoader;": "dexload",
    "Ldalvik/system/PathClassLoader;": "dexload",
    "Ljava/lang/Runtime;->exec": "exec",
    "Ljava/lang/ProcessBuilder;": "exec",
    "Ljava/lang/System;->loadLibrary": "native_load",
    "Ljava/lang/System;->load(": "native_load",
    "->sendTextMessage": "sms_send",
    "->sendMultipartTextMessage": "sms_send",
    "->sendDataMessage": "sms_send",
    "->abortBroadcast": "sms_abort",
    "->getSimOperator": "sim_info", "->getSimCountryIso": "sim_info",
    "->getNetworkOperator": "sim_info",
    "->getDeviceId": "device_id", "->getImei": "device_id",
    "->getSubscriberId": "device_id", "->getLine1Number": "device_id",
    "->getSimSerialNumber": "device_id",
    "->getInstalledPackages": "pkg_list",
    "->getInstalledApplications": "pkg_list",
    "Ljava/net/URL;->openConnection": "http",
    "Ljava/net/HttpURLConnection;": "http",
    "Lokhttp3/": "http", "Lorg/apache/http/": "http_legacy",
    "Ljava/net/Socket;": "socket", "Ljava/net/DatagramSocket;": "socket",
    "Ljavax/crypto/Cipher;": "crypto",
    "Ljavax/crypto/spec/SecretKeySpec;": "crypto",
    "Landroid/app/admin/DevicePolicyManager;": "device_admin",
    "Landroid/accessibilityservice/": "accessibility",
    "->setComponentEnabledSetting": "component_toggle",
    "Landroid/content/pm/PackageInstaller": "pkg_install",
    "->addView": "addview",              # overlay needs LayoutParams; approximate
    "Ljava/lang/reflect/Method;->invoke": "reflect",
    "Ldalvik/system/BaseDexClassLoader;": "dexload",
    "Landroid/content/ContentResolver;->query": "content_query",
    "->getRunningTasks": "task_snoop", "->getRunningAppProcesses": "task_snoop",
    "Landroid/media/MediaRecorder;": "record_media",
    "Landroid/hardware/Camera;->open": "record_media",
    "Landroid/location/LocationManager;->getLastKnownLocation": "location",
    "->getLastLocation": "location",
}

PAIRS = [
    ("dexload", "http"), ("dexload", "crypto"), ("sms_send", "sim_info"),
    ("pkg_list", "http"), ("device_id", "http"), ("reflect", "crypto"),
    ("accessibility", "addview"), ("sms_abort", "sms_send"),
    ("exec", "http"), ("location", "http"), ("record_media", "http"),
]

_REFLECT_SIG = "Ljava/lang/reflect/Method;->invoke"


def _vec(rec) -> dict[str, float]:
    """FeatureVector -> name->value dict."""
    return dict(zip(rec.vector.feature_names, rec.vector.values))

def tag_of(api_name: str) -> str | None:
    for key, tag in TAGS.items():
        if key in api_name:
            return tag
    return None


def features_from_stage2(s1, s2, tax) -> dict:
    """One census row per APK.

    Raw API identity comes from stage-1 RawClassRecord.api_calls (smali sigs
    with counts); taxonomy/flags/entropy come from stage 2. features maps
    feature-id -> number of DISTINCT classes exhibiting it.
    """
    declared_perms = set(s1.apk.permissions)
    feat_classes: dict[str, set] = collections.defaultdict(set)
    n_spoofed = 0

    for cname, s2rec in s2.records.items():
        raw = s1.class_records.get(cname)
        if raw is None:
            continue
        v = _vec(s2rec)
        tags_here: set[str] = set()

        # ---- raw framework API calls (stage 1) ------------------------
        for sig, cnt in raw.api_calls.items():
            # taxonomy-matched APIs get an api: row + permission split
            rule = tax.match(sig)
            if rule is not None:
                feat_classes[f"api:{sig}"].add(cname)
                feat_classes[f"apicat:{rule.category}"].add(cname)
                if rule.permission:
                    which = ("declared" if rule.permission in declared_perms
                             else "undeclared")
                    feat_classes[f"perm_{which}:{rule.permission}"].add(cname)
            # coarse behavior tags (independent of taxonomy)
            for key, tag in TAGS.items():
                if key in sig:
                    tags_here.add(tag)

        for t in tags_here:
            feat_classes[f"tag:{t}"].add(cname)
        for a, b in PAIRS:
            if a in tags_here and b in tags_here:
                feat_classes[f"pair:{a}+{b}"].add(cname)

        # ---- structural / flags (stage 1 + stage 2) --------------------
        if raw.native_method_count > 0:
            feat_classes["struct:has_native"].add(cname)
        if raw.api_calls.get(_REFLECT_SIG, 0) >= 5:
            feat_classes["struct:reflect_heavy"].add(cname)
        if raw.spoofed_framework_name:
            n_spoofed += 1
            feat_classes["struct:spoofed_framework"].add(cname)
        if v.get("is_component") and v.get("is_exported"):
            feat_classes["struct:exported_component"].add(cname)
            if tags_here:
                feat_classes["struct:exported_component_sensitive"].add(cname)
        if not s2rec.jadx_ok and tags_here:
            # decompilation failed on a class doing sensitive things
            feat_classes["struct:jadx_fail_sensitive"].add(cname)

        # ---- string entropy (stage-2 vector, names per your _STR block) --
        # ADAPT if your _STR feature names differ:
        for sname, fid in (("high_entropy_strings", "str:high_entropy"),
                           ("url_count", "str:has_url"),
                           ("ip_count", "str:has_ip"),
                           ("base64_like", "str:base64_like")):
            if v.get(sname, 0) > 0:
                feat_classes[fid].add(cname)

    return {
        "n_classes": len(s2.records),
        "n_spoofed_framework": n_spoofed,
        "jadx_coverage": s2.stats.get("jadx_coverage"),
        "perms": sorted(declared_perms),
        "minsdk": getattr(s1.apk, "min_sdk", None),      # ADAPT field names
        "targetsdk": getattr(s1.apk, "target_sdk", None),
        "features": {f: len(c) for f, c in feat_classes.items()},
    }


# ---------------------------------------------------------------------------
# phase 1: extract
# ---------------------------------------------------------------------------
def phase_extract(args, cfg, tax, jsonl_path: Path):
    logger.info(f"Cache DIR: {cfg.paths.cache_dir}------")
    cache = ArtifactCache(cfg.paths.cache_dir)
    done = set()
    if jsonl_path.exists():                       # crash-resume
        for line in jsonl_path.open():
            try:
                done.add(json.loads(line)["sha"])
            except json.JSONDecodeError:
                pass
        logger.info(f"resuming: {len(done)} APKs already in {jsonl_path}")

    seen_sha = set(done)                          # in-corpus dedup
    tasks = [(p, "benign") for p in sorted(Path(args.benign).rglob("*.apk"))]
    tasks_mal = [(p, "malware") for p in sorted(Path(args.malware).rglob("*.apk"))]
    if args.limit:
        tasks = tasks[: args.limit]
        tasks += tasks_mal[: args.limit]

    ok = err = skip = 0
    with jsonl_path.open("a") as out:
        for i, (apk, label) in enumerate(tasks, 1):
            try:
                sha = sha256_of_file(str(apk))
                if sha in seen_sha:
                    skip += 1
                    continue
                seen_sha.add(sha)

                s1 = build_class_graph(str(apk), cfg)
                s2 = (cache.load(sha, "stage2_features")
                      if cache.has(sha, "stage2_features")
                      else extract_features(s1, str(apk), cfg))
                cache.save(sha, "stage2_features", s2)

                row = {"sha": sha, "label": label, "apk": apk.name}
                row.update(features_from_stage2(s1, s2, tax))
                out.write(json.dumps(row) + "\n")
                out.flush()
                ok += 1
            except Exception:
                err += 1
                logger.error(f"FAILED {apk}\n{traceback.format_exc(limit=3)}")
            if i % 50 == 0:
                logger.info(f"INFO---[{i}/{len(tasks)}] ok={ok} dup={skip} err={err}")
    logger.info(f"extract done: ok={ok} dup_skipped={skip} errors={err}", ok, skip, err)


# ---------------------------------------------------------------------------
# phase 2: aggregate
# ---------------------------------------------------------------------------
def phase_aggregate(out_dir: Path, jsonl_path: Path) -> pd.DataFrame:
    rows = [json.loads(l) for l in jsonl_path.open()]
    n = collections.Counter(r["label"] for r in rows)
    ben = n["benign"]
    mal = n["malware"]
    logger.info(f"aggregating {len(rows)} APKs (benign={ben} malware={mal})")

    per_feat: dict[str, dict[str, list]] = collections.defaultdict(
        lambda: {"malware": [], "benign": []})
    for r in rows:
        feats = dict(r["features"])
        for p in r["perms"]:
            feats[f"perm:{p}"] = 1
        for f, c in feats.items():
            per_feat[f][r["label"]].append(c)

    recs = []
    for f, d in per_feat.items():
        rec = {"feature": f,
               "kind": f.split(":", 1)[0]}
        for lab, tag in (("malware", "mal"), ("benign", "ben")):
            hits = d[lab]
            rec[f"{tag}_apks"] = len(hits)
            rec[f"{tag}_apk_pct"] = round(100 * len(hits) / max(n[lab], 1), 2)
            rec[f"{tag}_cls_per_apk"] = float(pd.Series(hits).median()) if hits else 0.0
            rec[f"{tag}_hits_total"] = int(sum(hits))
        rec["apk_pct_gap"] = round(rec["mal_apk_pct"] - rec["ben_apk_pct"], 2)
        recs.append(rec)

    df = pd.DataFrame(recs)
    df.sort_values("mal_apk_pct", ascending=False).to_csv(
        out_dir / "feature_census.csv", index=False)
    # convenience sorted views
    df.sort_values("apk_pct_gap", ascending=False).head(60).to_csv(
        out_dir / "view_top_gap_malware.csv", index=False)
    df.sort_values("apk_pct_gap").head(60).to_csv(
        out_dir / "view_top_gap_benign.csv", index=False)
    df[(df.mal_apks > 0) & (df.ben_apks == 0)].sort_values(
        "mal_apks", ascending=False).to_csv(
        out_dir / "view_malware_exclusive.csv", index=False)

    # corpus summary
    (out_dir / "corpus_summary.json").write_text(json.dumps({
        "n_benign": n["benign"], "n_malware": n["malware"],
        "n_features": len(df),
        "median_classes_benign": float(pd.Series(
            [r["n_classes"] for r in rows if r["label"] == "benign"]).median()),
        "median_classes_malware": float(pd.Series(
            [r["n_classes"] for r in rows if r["label"] == "malware"]).median()),
    }, indent=2))
    logger.info(f"wrote feature_census.csv ({len(df)} features) + 3 views")
    return df


# ---------------------------------------------------------------------------
# phase 3: plots
# ---------------------------------------------------------------------------
def _barpair(df, title, fname, plots_dir, top=25):
    import matplotlib.pyplot as plt
    import numpy as np
    d = df.head(top).iloc[::-1]
    y = np.arange(len(d))
    fig, ax = plt.subplots(figsize=(10, max(5, 0.32 * len(d))))
    ax.barh(y + 0.2, d.mal_apk_pct, 0.4, label="malware APKs %", color="#d62728")
    ax.barh(y - 0.2, d.ben_apk_pct, 0.4, label="benign APKs %", color="#1f77b4")
    ax.set_yticks(y)
    ax.set_yticklabels([f[:60] for f in d.feature], fontsize=8)
    ax.set_xlabel("% of APKs in corpus containing feature")
    ax.set_title(title)
    ax.legend()
    fig.tight_layout()
    fig.savefig(plots_dir / fname, dpi=200)
    plt.close(fig)


def phase_plot(out_dir: Path, jsonl_path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    df = pd.read_csv(out_dir / "feature_census.csv")
    plots = out_dir / "plots"
    plots.mkdir(exist_ok=True)

    _barpair(df.sort_values("apk_pct_gap", ascending=False),
             "Features over-represented in malware (APK prevalence gap)",
             "01_top_malware_leaning.png", plots)
    _barpair(df.sort_values("apk_pct_gap"),
             "Features over-represented in benign apps",
             "02_top_benign_leaning.png", plots)
    _barpair(df[df.kind == "perm"].sort_values("apk_pct_gap", ascending=False),
             "Permissions: malware vs benign prevalence",
             "03_permissions.png", plots)
    _barpair(df[df.feature.str.startswith("api_undeclared")]
             .sort_values("mal_apk_pct", ascending=False),
             "Undeclared-permission API usage",
             "04_undeclared_perm_apis.png", plots)
    _barpair(df[df.kind.isin(["tag", "pair"])]
             .sort_values("apk_pct_gap", ascending=False),
             "Behavior tags & within-class co-occurrence pairs",
             "05_tags_and_pairs.png", plots)

    # concentration scatter: prevalence vs how many classes carry the feature
    d = df[(df.mal_apks >= 5)]
    fig, ax = plt.subplots(figsize=(9, 7))
    ax.scatter(d.mal_apk_pct, d.mal_cls_per_apk, s=14, alpha=0.6, color="#d62728")
    for _, r in d.nlargest(12, "apk_pct_gap").iterrows():
        ax.annotate(r.feature[:40], (r.mal_apk_pct, r.mal_cls_per_apk),
                    fontsize=7, alpha=0.8)
    ax.set_yscale("log")
    ax.set_xlabel("% of malware APKs containing feature")
    ax.set_ylabel("median # classes carrying it per affected APK (log)")
    ax.set_title("Feature concentration in malware:\n"
                 "low = localizes to few classes, high = smeared/library noise")
    fig.tight_layout()
    fig.savefig(plots / "06_concentration_malware.png", dpi=200)
    plt.close(fig)

    # SDK-era skew check
    rows = [json.loads(l) for l in jsonl_path.open()]
    fig, ax = plt.subplots(figsize=(9, 5))
    for lab, color in (("benign", "#1f77b4"), ("malware", "#d62728")):
        vals = [r["targetsdk"] for r in rows
                if r["label"] == lab and r.get("targetsdk")]
        ax.hist(vals, bins=range(1, 36), alpha=0.5, density=True,
                label=f"{lab} (n={len(vals)})", color=color)
    ax.set_xlabel("targetSdkVersion")
    ax.set_ylabel("density")
    ax.set_title("Corpus age skew check: targetSdk distribution by label\n"
                 "(large separation => 'malware features' may be era artifacts)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(plots / "07_sdk_skew.png", dpi=200)
    plt.close(fig)
    logger.info(f"plots written to {plots}")


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", required=True)
    ap.add_argument("--malware", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--config", default=None)
    ap.add_argument("--phase", default="all",
                    choices=["all", "extract", "aggregate", "plot"])
    ap.add_argument("--limit", type=int, default=None,
                    help="process only first N APKs (smoke test)")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl = out_dir / "census_raw.jsonl"

    if args.phase in ("all", "extract"):
        tax = ApiTaxonomy.load(cfg.features.sensitive_api_csv)
        phase_extract(args, cfg, tax, jsonl)
    if args.phase in ("all", "aggregate"):
        phase_aggregate(out_dir, jsonl)
    if args.phase in ("all", "plot"):
        phase_plot(out_dir, jsonl)


if __name__ == "__main__":
    sys.exit(main())
