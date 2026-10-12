#!/usr/bin/env python3
"""Stage-4: LLM verdicts on top clusters. Reuses all cached stages.
Usage: python scripts/04_llm_analyze.py --config configs/default.yaml app.apk
"""
import argparse
import sys
from loguru import logger

from droidlens.config import Config
from droidlens.ingest.runner import build_class_graph
from droidlens.features.vectorize import extract_features
from droidlens.clustering.expand import rank_clusters
from droidlens.llm.analyze import analyze_clusters, summarize_clusters
from droidlens.utils.cache import ArtifactCache, sha256_of_file
from droidlens.utils.logsetup import setup_logging


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    cache = ArtifactCache(cfg.paths.cache_dir)

    for apk in args.apks:
        logger.info(f"\n{'='*70}\n{apk}\n{'='*70}")
        sha = sha256_of_file(apk)
        s1 = build_class_graph(apk, cfg, True)
        if not args.force and cache.has(sha, "stage2_features"):
            s2 = cache.load(sha, "stage2_features")
            logger.info("  (stage2 cache hit)")
        else:
            s2 = extract_features(s1, apk, cfg)
        s3 = rank_clusters(s1, s2, cfg)
        s4_key = f"stage4_{cfg.llm.model.replace('/', '_')}"
        if not args.force and cache.has(sha, s4_key):
            s4 = cache.load(sha, s4_key)
        else:
            # s4 = analyze_clusters(s1, s2, s3, cfg)
            s4 = summarize_clusters(s1, s2, s3, cfg)
            cache.save(sha, s4_key, s4, meta=s4.stats)


        for cid, v in s4.verdicts.items():
            cl = next(c for c in s3.clusters if c.cluster_id == cid)
            print(f"\n  cluster #{cid} [{cl.seed_class}]")
            print(f"    -> {v.verdict.upper()} ({v.confidence:.2f}) {v.behaviors}")
            print(f"    {v.summary}")
            for e in v.evidence[:3]:
                print(f"      * {e.class_name}: {e.quote[:80]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
