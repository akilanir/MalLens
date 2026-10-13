#!/usr/bin/env python3
"""End-to-end: all stages (cache-aware) -> APK verdict + report files."""
import argparse
import sys

from mallens.config import Config
from mallens.ingest.runner import build_class_graph
from mallens.features.vectorize import extract_features
from mallens.clustering.expand import rank_clusters
from mallens.llm.analyze import analyze_clusters
from mallens.report.aggregate import aggregate
from mallens.report.render import render
from mallens.utils.cache import ArtifactCache, sha256_of_file
from mallens.utils.logsetup import setup_logging


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    cfg = Config.load(args.config)
    setup_logging(cfg.logging.level, cfg.logging.androguard_level)
    cache = ArtifactCache(cfg.paths.cache_dir)

    for apk in args.apks:
        sha = sha256_of_file(apk)
        s1 = build_class_graph(apk, cfg)
        s2 = (cache.load(sha, "stage2_features")
              if cache.has(sha, "stage2_features")
              else extract_features(s1, apk, cfg))
        s3 = rank_clusters(s1, s2, cfg)
        s4_key = f"stage4_{cfg.llm.model.replace('/', '_')}"
        s4 = (cache.load(sha, s4_key) if cache.has(sha, s4_key)
              else analyze_clusters(s1, s2, s3, cfg))
        cache.save(sha, s4_key, s4, meta=s4.stats)

        av = aggregate(s2, s3, s4, cfg)
        jp, mp = render(s1, s3, s4, av, cfg.report.out_dir)
        print(f"\n{apk}\n  VERDICT: {av.verdict.upper()} ({av.confidence})")
        for r in av.rules_fired:
            print(f"    - {r}")
        print(f"  localized: {len(av.malicious_classes)} classes")
        print(f"  report: {mp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
