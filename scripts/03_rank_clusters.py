#!/usr/bin/env python3
"""Stage-3 smoke test. Reuses cached Stage-1/2.
Usage: python scripts/03_rank_clusters.py --config configs/default.yaml app.apk
       add --scorer naive|pagerank|propagation to override config (ablation).
"""
import argparse
import sys

from mallens.config import Config
from mallens.ingest.runner import build_class_graph
from mallens.features.vectorize import extract_features
from mallens.clustering.expand import rank_clusters
from mallens.utils.cache import ArtifactCache, sha256_of_file
from mallens.utils.logsetup import setup_logging


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    ap.add_argument("--scorer", default=None)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    if args.scorer:
        cfg.importance.scorer = args.scorer
    setup_logging(cfg.logging.level, cfg.logging.androguard_level)
    cache = ArtifactCache(cfg.paths.cache_dir)

    for apk in args.apks:
        print(f"\n{'='*70}\n{apk}  [scorer={cfg.importance.scorer}]\n{'='*70}")
        sha = sha256_of_file(apk)
        s1 = build_class_graph(apk, cfg)          # cache-aware already
        if not args.force and cache.has(sha, "stage2_features"):
            s2 = cache.load(sha, "stage2_features")
        else:
            s2 = extract_features(s1, apk, cfg)
            cache.save(sha, "stage2_features", s2, meta=s2.stats)
        s3 = rank_clusters(s1, s2, cfg)
        cache.save(sha, f"stage3_{cfg.importance.scorer}", s3, meta=s3.stats)

        print(f"  stats: {s3.stats}")
        print(f"  top-5 clusters:")
        for c in s3.clusters[:10]:
            print(f"    #{c.cluster_id} imp={c.importance:.3f} "
                  f"n={len(c.class_names)} tokens~{c.est_tokens} "
                  f"seed={c.seed_class}")
            for m in c.class_names[:8]:
                print(f"        {s3.scores.get(m, 0):.3f}  {m}")
            if len(c.class_names) > 8:
                print(f"        ... +{len(c.class_names) - 8} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
