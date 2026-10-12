#!/usr/bin/env python3
"""Stage-4b: enumerate source->sink paths per cluster, adjudicate each with the
LLM, derive deterministic cluster verdicts. Requires stage-4a fact sheets in
the artifact cache (run scripts/04a_factsheets.py first).
Usage: python scripts/04b_pathverdicts.py --config configs/default.yaml app.apk
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
from droidlens.llm.factsheet import FS_PROMPT_VERSION
from droidlens.llm.pathfind import enumerate_paths
from droidlens.llm.adjudicate import adjudicate_path, render_path
from droidlens.llm.analyze import cluster_permission_lines
from droidlens.report.pathverdict import cluster_verdict
from droidlens.utils.cache import ArtifactCache, sha256_of_file
from droidlens.utils.logsetup import setup_logging


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    assert cfg.factsheet.prompt_version == FS_PROMPT_VERSION
    setup_logging(cfg.logging.level, cfg.logging.androguard_level,
                  cfg.paths.log_file)
    cache = ArtifactCache(cfg.paths.cache_dir)
    client = LLMClient(cfg)

    for apk in args.apks:
        sha = sha256_of_file(apk)

        # ---- stages 1-3 (cache-aware, same as everywhere else) -----------
        s1 = build_class_graph(apk, cfg)
        s2 = (cache.load(sha, "stage2_features")
              if cache.has(sha, "stage2_features")
              else extract_features(s1, apk, cfg))
        s3 = rank_clusters(s1, s2, cfg)

        # ---- load stage-4a; do NOT rebuild here ---------------------------
        s4a_key = f"stage4a_{cfg.factsheet.prompt_version}"
        if not cache.has(sha, s4a_key):
            logger.error(f"{apk}: no fact sheets ({s4a_key}); "
                         f"run 04a_factsheets.py first")
            continue
        sheets = cache.load(sha, s4a_key)     # dict[class_name -> ClassFactSheet]

        s4b_key = f"stage4b_{cfg.adjudicate.prompt_version}"
        if not args.force and cache.has(sha, s4b_key):
            logger.info(f"{apk}: stage4b cache hit")
            continue

        targets = [c for c in s3.clusters
                   if c.importance >= cfg.llm.min_cluster_importance
                   ][:cfg.llm.max_clusters]

        out_dir = Path("Stage4bResults") / sha
        out_dir.mkdir(parents=True, exist_ok=True)

        all_paths, all_pvs, cluster_verdicts = {}, {}, {}
        n_raw = 0

        from droidlens.features.api_taxonomy import ApiTaxonomy
        tax = ApiTaxonomy.load(cfg.features.sensitive_api_csv)
        declared_perm = set(s1.apk.permissions)
        for cl in targets:
            cl_sheets = {n: sheets[n] for n in cl.class_names
                         if n in sheets and sheets[n].status == "ok"}
            perm_lines = cluster_permission_lines(cl, s1, tax, declared_perm)

            paths = enumerate_paths(cl, cl_sheets, s1.graph, cfg)  # adapt: your graph attr
            n_raw += len(paths)

            pvs = {}
            for p in paths:
                pvs[p.path_id] = adjudicate_path(p, cl_sheets, perm_lines,
                                                 client, cfg)

            cv = cluster_verdict(cl.cluster_id, paths, pvs,
                                 any_sheets=bool(cl_sheets))
            cluster_verdicts[cl.cluster_id] = cv
            all_paths.update({p.path_id: p for p in paths})
            all_pvs.update(pvs)

            # ---- per-cluster audit file (LLM input + verdicts) ------------
            lines = [f"CLUSTER #{cl.cluster_id}  verdict={cv.verdict}  "
                     f"paths={cv.n_paths}  hostile={len(cv.hostile_paths)}  "
                     f"unresolved_terminated={cv.n_unresolved_terminated}", ""]
            for p in paths:
                v = pvs[p.path_id]
                lines += ["=" * 60,
                          f"PATH {p.path_id}: {p.source_type} -> {p.sink_type} "
                          f"(trigger={p.trigger_type}, transform={p.has_transform})",
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

            hostile = len(cv.hostile_paths)
            logger.info(f"  cluster {cl.cluster_id}: {cv.verdict} "
                        f"({cv.n_paths} paths, {hostile} hostile)")

        # ---- per-APK summary json + cache save -----------------------------
        summary = {
            "apk": Path(apk).name, "sha256": sha,
            "clusters": {cid: dataclasses.asdict(cv)
                         for cid, cv in cluster_verdicts.items()},
            "n_paths_adjudicated": len(all_pvs),
            "n_hostile": sum(1 for v in all_pvs.values()
                             if v.verified and v.exceeds_legitimate_purpose),
        }
        (out_dir / "cluster_verdicts.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False))

        cache.save(sha, s4b_key,
                   {"paths": all_paths, "path_verdicts": all_pvs,
                    "cluster_verdicts": cluster_verdicts},
                   meta={"n_paths": len(all_paths), "n_raw": n_raw,
                         "n_hostile": summary["n_hostile"]})

        logger.info(f"{apk}: {len(all_paths)} paths adjudicated, "
                    f"{summary['n_hostile']} hostile; "
                    f"results in {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
