#!/usr/bin/env python3
"""Stage-2 smoke test. Reuses cached Stage-1; runs Stage-1 if missing.
Usage: python scripts/02_extract_features.py --config configs/default.yaml app.apk
"""
import argparse
import sys

from mallens.config import Config
from mallens.core.exceptions import IngestError
from mallens.ingest.runner import build_class_graph
from mallens.features.vectorize import extract_features
from mallens.utils.cache import ArtifactCache, sha256_of_file
from mallens.utils.logsetup import setup_logging

STAGE = "stage2_ap_features"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    setup_logging(cfg.logging.level, cfg.logging.androguard_level)
    cache = ArtifactCache(cfg.paths.cache_dir)
    failures = 0

    for apk in args.apks:
        print(f"\n{'='*70}\n{apk}\n{'='*70}")
        try:
            sha = sha256_of_file(apk)
            if not args.force and cache.has(sha, STAGE):
                s2 = cache.load(sha, STAGE)
                print("  (stage2 cache hit)")
            else:
                s1 = build_class_graph(apk, cfg, args.force)
                s2 = extract_features(s1, apk, cfg)
                cache.save(sha, STAGE, s2, meta=s2.stats)
        except (IngestError, Exception) as exc:
            print(f"  FAILED: {exc}")
            failures += 1
            continue

        print(f"  stats: {s2.stats}")
        top = sorted(s2.records.values(), key=lambda r: -r.suspicion_naive)[:20]
        print("  top-20 by naive suspicion:")
        for r in top:
            cats = ", ".join(f"{k}:{v}" for k, v in
                             sorted(r.api_categories.items(), key=lambda kv: -kv[1])[:4])
            print(f"    {r.suspicion_naive:>7.2f}  {r.vector.class_name}")
            print(f"             [{cats}] jadx={r.jadx_ok}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
