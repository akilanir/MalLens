#!/usr/bin/env python3
"""Stage-1 smoke test.
Usage: python scripts/01_build_graph.py --config configs/default.yaml app1.apk [app2.apk ...]
"""
import argparse
import sys
from collections import Counter

from mallens.config import Config
from mallens.core.exceptions import IngestError
from mallens.ingest.runner import build_class_graph
from mallens.utils.logsetup import setup_logging


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    ap.add_argument("--force", action="store_true", help="ignore cache")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    setup_logging(cfg.logging.level, cfg.logging.androguard_level)

    failures = 0
    for apk in args.apks:
        print(f"\n{'='*70}\n{apk}\n{'='*70}")
        try:
            res = build_class_graph(apk, cfg, force=args.force)
        except IngestError as exc:
            print(f"  FAILED: {exc}")
            failures += 1
            continue

        g = res.graph
        print(f"  package      : {res.apk.package_name}")
        print(f"  permissions  : {len(res.apk.permissions)} "
              f"({[p.split('.')[-1] for p in res.apk.permissions[:8]]}...)")
        print(f"  components   : A={len(res.apk.activities)} S={len(res.apk.services)} "
              f"R={len(res.apk.receivers)} P={len(res.apk.providers)}")
        print(f"  stats        : {res.stats}")

        deg = Counter({n: g.degree(n, weight='weight') for n in g})
        print("  top-5 hub classes (weighted degree):")
        for n, d in deg.most_common(5):
            print(f"    {d:>6}  {n}")

        api_rich = sorted(res.class_records.values(),
                          key=lambda r: sum(r.api_calls.values()), reverse=True)[:5]
        print("  top-5 classes by framework-API usage:")
        for r in api_rich:
            top = sorted(r.api_calls.items(), key=lambda kv: -kv[1])[:3]
            print(f"    {sum(r.api_calls.values()):>5}  {r.name}")
            for sig, c in top:
                print(f"           {c}x {sig}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

