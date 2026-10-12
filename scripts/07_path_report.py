#!/usr/bin/env python3
"""07_path_report.py -- End-to-end fact-sheet pipeline with deterministic
APK verdict.

Chain:
  stages 1-3 (graph, features, clusters)   cache-aware
  stage 4a   per-class fact sheets          LLM, content-hash cached, verified
  stage 4b   path enumeration + adjudication  deterministic + LLM per path
  stage 5p   cluster -> APK verdict          deterministic rules

Baseline arms (tier-1 whole-cluster LLM + rule engine) run in SHADOW mode:
computed and logged for the ablation, never authoritative.

Usage:
  python scripts/07_path_report.py --config configs/default.yaml app.apk
  python scripts/07_path_report.py --force app.apk              # redo everything
  python scripts/07_path_report.py --force-4b --force-verdict app.apk
"""
import argparse
import dataclasses
import json
import sys
from pathlib import Path
from loguru import logger

from droidlens.config import Config
from droidlens.ingest.runner import build_class_graph
from droidlens.features.vectorize import extract_features
from droidlens.clustering.expand import rank_clusters
from droidlens.llm.client import LLMClient
from droidlens.llm.factsheet import (build_factsheet, feats_dict,FS_PROMPT_VERSION)
from droidlens.llm.pack import get_class_source
from droidlens.llm.fscache import FactSheetCache, src_hash
from droidlens.llm.pathfind import enumerate_paths
from droidlens.llm.adjudicate import adjudicate_path, render_path
from droidlens.llm.analyze import cluster_permission_lines
from droidlens.report.pathverdict import cluster_verdict, apk_verdict
from droidlens.core.datatypes import ApkPathVerdict
from droidlens.utils.cache import ArtifactCache, sha256_of_file
from droidlens.utils.logsetup import setup_logging

# shadow arms
from droidlens.report.llm_aggregate import llm_aggregate
from droidlens.report.aggregate import aggregate as rule_aggregate


# ----------------------------------------------------------------------------
# report rendering
# ----------------------------------------------------------------------------
def write_reports(apk: str, sha: str, av: ApkPathVerdict, out_dir: str) -> str:
    out = Path(out_dir) / sha[:12]
    out.mkdir(parents=True, exist_ok=True)

    (out / "verdict.json").write_text(
        json.dumps(dataclasses.asdict(av), indent=2, ensure_ascii=False,
                   default=str))

    lines = [
        f"# DroidLens path report -- {Path(apk).name}",
        "",
        f"**Verdict: {av.verdict.upper()}** "
        f"(confidence {av.confidence}, source: {av.source})",
        "",
        f"**Rationale:** {av.rationale}",
        "",
        "**Cluster verdicts:** "
        + ", ".join(f"#{cid}={v}" for cid, v in
                    sorted(av.cluster_verdicts.items())),
        "",
    ]
    if av.verdict == "malicious":
        lines += [f"**Family hint:** {av.family_hint or 'unknown'}", "",
                  "## Hostile data-flow paths", ""]
        for hp in av.hostile_paths:
            lines += [f"### `{hp['path']}` : {hp['flow']}",
                      "",
                      "Classes: " + " ->; ".join(f"`{c}`" for c in hp["classes"]),
                      "",
                      f"> {hp['why']}",
                      ""]
        lines += ["## Localized classes", ""]
        lines += [f"- `{c}`" for c in av.malicious_classes[:40]]
    if av.shadow:
        lines += ["", "---", "_Shadow arms (not authoritative):_",
                  f"_tier1 LLM: {av.shadow.get('tier1_llm', 'n/a')}  |  "
                  f"rules: {av.shadow.get('rules', 'n/a')}_"]
    md = out / "report.md"
    md.write_text("\n".join(lines), encoding="utf-8")
    return str(md)


# ----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default="configs/default.yaml")
    ap.add_argument("--force", action="store_true",
                    help="recompute every cached stage")
    ap.add_argument("--force-s2", action="store_true",
                    help="recompute stage-2 features")
    ap.add_argument("--force-4a", action="store_true",
                    help="rebuild fact sheets (APK-level artifact; the "
                         "corpus fact-sheet cache is still consulted -- bump "
                         "factsheet.prompt_version to invalidate that)")
    ap.add_argument("--force-4b", action="store_true",
                    help="re-enumerate and re-adjudicate paths")
    ap.add_argument("--force-verdict", action="store_true",
                    help="recompute APK verdict + shadow arms")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    assert cfg.factsheet.prompt_version == FS_PROMPT_VERSION, \
        "config factsheet.prompt_version out of sync with llm/factsheet.py"
    setup_logging(cfg.logging.level, cfg.logging.androguard_level,
                  cfg.paths.log_file)

    f_all = args.force
    f_s2 = f_all or args.force_s2
    f_4a = f_all or args.force_4a
    f_4b = f_all or args.force_4b or f_4a       # new sheets invalidate paths
    f_ver = f_all or args.force_verdict or f_4b  # new paths invalidate verdict

    cache = ArtifactCache(cfg.paths.cache_dir)
    fscache = FactSheetCache(cfg.paths.cache_dir, cfg.llm.model,
                             cfg.factsheet.prompt_version)
    client = LLMClient(cfg)

    s4a_key = f"stage4a_{cfg.factsheet.prompt_version}"
    s4b_key = f"stage4b_{cfg.adjudicate.prompt_version}"
    s5p_key = (f"stage5p_{cfg.factsheet.prompt_version}"
               f"_{cfg.adjudicate.prompt_version}")

    for apk in args.apks:
        logger.info(f"{'=' * 70}\n{apk}\n{'=' * 70}")
        sha = sha256_of_file(apk)

        # ---- stages 1-3 ----------------------------------------------------
        s1 = build_class_graph(apk, cfg)
        if not f_s2 and cache.has(sha, "stage2_features"):
            s2 = cache.load(sha, "stage2_features")
            logger.info("stage2: cache hit")
        else:
            s2 = extract_features(s1, apk, cfg)
            cache.save(sha, "stage2_features", s2, meta=s2.stats)
        s3 = rank_clusters(s1, s2, cfg)

        targets = [c for c in s3.clusters
                   if c.importance >= cfg.llm.min_cluster_importance
                   ][:cfg.llm.max_clusters]
        logger.info(f"stage3: {len(targets)} target clusters "
                    f"(of {len(s3.clusters)})")

        # ---- stage 4a: fact sheets ------------------------------------------
        if not f_4a and cache.has(sha, s4a_key):
            sheets = cache.load(sha, s4a_key)
            logger.info(f"stage4a: cache hit ({len(sheets)} sheets)")
        else:
            sheets, hits = {}, 0
            for cl in targets:
                for cname in cl.class_names:
                    if cname in sheets:
                        continue
                    record = s2.records.get(cname)
                    src = get_class_source(record, cfg)
                    if src is None:
                        continue
                    if fscache.get(src_hash(src)):
                        hits += 1
                    sheets[cname] = build_factsheet(
                        cname, src, feats_dict(record), client, fscache, cfg)
            n_drop = sum(len(f.dropped) for f in sheets.values())
            n_err = sum(1 for f in sheets.values() if f.status != "ok")
            cache.save(sha, s4a_key, sheets,
                       meta={"n": len(sheets), "cache_hits": hits,
                             "dropped": n_drop, "errors": n_err})
            logger.info(f"stage4a: {len(sheets)} sheets "
                        f"({hits} corpus-cache hits, {n_drop} claims dropped, "
                        f"{n_err} errors)")

        # ---- stage 4b: paths + adjudication ---------------------------------
        if not f_4b and cache.has(sha, s4b_key):
            s4b = cache.load(sha, s4b_key)
            all_paths = s4b["paths"]
            all_pvs = s4b["path_verdicts"]
            cvs = s4b["cluster_verdicts"]
            logger.info(f"stage4b: cache hit ({len(all_paths)} paths)")
        else:
            out_dir = Path("Stage4bResults") / sha
            out_dir.mkdir(parents=True, exist_ok=True)
            all_paths, all_pvs, cvs = {}, {}, {}
            n_raw = 0

            from droidlens.features.api_taxonomy import ApiTaxonomy
            tax = ApiTaxonomy.load(cfg.features.sensitive_api_csv)
            declared_perm = set(s1.apk.permissions)
            for cl in targets:
                cl_sheets = {n: sheets[n] for n in cl.class_names
                             if n in sheets and sheets[n].status == "ok"}
                n_missing = len(cl.class_names) - len(cl_sheets)
                perm_lines = cluster_permission_lines(cl, s1, tax, declared_perm)

                paths = enumerate_paths(cl, cl_sheets, s1.graph, cfg)
                n_raw += len(paths)

                pvs = {}
                for p in paths:
                    pvs[p.path_id] = adjudicate_path(p, cl_sheets, perm_lines,
                                                     client, cfg)

                cv = cluster_verdict(cl.cluster_id, paths, pvs,
                                     any_sheets=bool(cl_sheets))
                if n_missing:
                    cv.notes = (f"{cv.notes} {n_missing} classes without "
                                f"fact sheets").strip()
                cvs[cl.cluster_id] = cv
                all_paths.update({p.path_id: p for p in paths})
                all_pvs.update(pvs)

                # audit file: exact LLM inputs + all adjudications
                lines = [f"CLUSTER #{cl.cluster_id}  verdict={cv.verdict}  "
                         f"paths={cv.n_paths}  hostile={len(cv.hostile_paths)}  "
                         f"unresolved_terminated={cv.n_unresolved_terminated}  "
                         f"missing_sheets={n_missing}", ""]
                for p in paths:
                    v = pvs[p.path_id]
                    lines += ["=" * 60,
                              f"PATH {p.path_id}: {p.source_type} -> "
                              f"{p.sink_type} (trigger={p.trigger_type}, "
                              f"transform={p.has_transform})",
                              "-" * 60, "LLM INPUT:",
                              render_path(p, cl_sheets, perm_lines,
                                          cfg.factpaths.alias_names),
                              "-" * 60,
                              f"hostile={v.exceeds_legitimate_purpose} "
                              f"verified={v.verified} conf={v.confidence:.2f}",
                              f"reading: {v.reading}",
                              f"legit:   {v.legitimate_explanation}",
                              f"why:     {v.why}", ""]
                (out_dir / f"cluster_{cl.cluster_id}_paths.txt"
                 ).write_text("\n".join(lines), encoding="utf-8")

                logger.info(f"  cluster {cl.cluster_id}: {cv.verdict} "
                            f"({cv.n_paths} paths, "
                            f"{len(cv.hostile_paths)} hostile)")

            n_hostile = sum(1 for v in all_pvs.values()
                            if v.verified and v.exceeds_legitimate_purpose)
            (out_dir / "cluster_verdicts.json").write_text(json.dumps(
                {"apk": Path(apk).name, "sha256": sha,
                 "clusters": {cid: dataclasses.asdict(cv)
                              for cid, cv in cvs.items()},
                 "n_paths_adjudicated": len(all_pvs),
                 "n_hostile": n_hostile},
                indent=2, ensure_ascii=False))
            cache.save(sha, s4b_key,
                       {"paths": all_paths, "path_verdicts": all_pvs,
                        "cluster_verdicts": cvs},
                       meta={"n_paths": len(all_paths), "n_raw": n_raw,
                             "n_hostile": n_hostile})
            logger.info(f"stage4b: {len(all_paths)} paths adjudicated, "
                        f"{n_hostile} hostile")

        # ---- stage 5p: APK verdict + shadow arms ----------------------------
        if not f_ver and cache.has(sha, s5p_key):
            av = cache.load(sha, s5p_key)
            logger.info("stage5p: cache hit")
        else:
            av = apk_verdict(sha, list(cvs.values()), all_paths, all_pvs, cfg)

            # shadow: tier-1 LLM aggregate + rule engine (never authoritative)
            shadow = {}
            try:
                t1_key = f"stage4_{cfg.llm.model.replace('/', '_')}"
                s4 = cache.load(sha, t1_key) if cache.has(sha, t1_key) else None
                if s4 is not None:
                    try:
                        shadow["tier1_llm"] = llm_aggregate(
                            s1, s2, s3, s4, cfg).verdict
                    except Exception as e:
                        shadow["tier1_llm"] = f"error: {e}"
                    try:
                        shadow["rules"] = rule_aggregate(
                            s1, s2, s3, s4, cfg).verdict
                    except Exception as e:
                        shadow["rules"] = f"error: {e}"
                else:
                    shadow["tier1_llm"] = shadow["rules"] = "not_run"
            except Exception as e:
                shadow["error"] = str(e)
            av.shadow = shadow
            cache.save(sha, s5p_key, av,
                       meta={"verdict": av.verdict, "source": av.source})

        # ---- output ----------------------------------------------------------
        mp = write_reports(apk, sha, av, cfg.report.out_dir)
        logger.info(f"VERDICT: {av.verdict.upper()} ({av.confidence}) "
                    f"[{av.source}]")
        logger.info(f"  rationale: {av.rationale}")
        if av.verdict == "malicious":
            logger.info(f"  hostile paths: "
                        f"{[hp['path'] for hp in av.hostile_paths]}")
            logger.info(f"  localized: {len(av.malicious_classes)} classes")
        if av.shadow:
            for arm in ("tier1_llm", "rules"):
                sv = av.shadow.get(arm, "n/a")
                marker = ("AGREE" if sv == av.verdict
                          else ">>> DISAGREE <<<")
                logger.info(f"  shadow({arm}): {sv}  {marker}")
        logger.info(f"  report: {mp}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
