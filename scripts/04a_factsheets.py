#!/usr/bin/env python3
"""Stage-4a: per-class fact sheets for classes in top clusters."""
import argparse, sys
from mallens.config import Config
from mallens.ingest.runner import build_class_graph
from mallens.features.vectorize import extract_features
from mallens.clustering.expand import rank_clusters
from mallens.llm.client import LLMClient
from mallens.llm.factsheet import build_factsheet, FS_PROMPT_VERSION, feats_dict
from mallens.llm.fscache import FactSheetCache
from mallens.llm.pack import get_class_source
from mallens.utils.cache import ArtifactCache, sha256_of_file
from mallens.utils.logsetup import setup_logging

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+"); ap.add_argument("--config", default=None)
    args = ap.parse_args()
    cfg = Config.load(args.config)
    assert cfg.factsheet.prompt_version == FS_PROMPT_VERSION
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    cache = ArtifactCache(cfg.paths.cache_dir)
    fscache = FactSheetCache(cfg.paths.cache_dir, cfg.llm.model, cfg.factsheet.prompt_version)
    client = LLMClient(cfg)

    for apk in args.apks:
        sha = sha256_of_file(apk)
        s1 = build_class_graph(apk, cfg)
        s2 = (cache.load(sha, "stage2_features") if cache.has(sha, "stage2_features")
              else extract_features(s1, apk, cfg))
        s3 = rank_clusters(s1, s2, cfg)
        targets = [c for c in s3.clusters
                   if c.importance >= cfg.llm.min_cluster_importance][:cfg.llm.max_clusters]
        sheets, hits = {}, 0
        for cl in targets:
            for cname in cl.class_names:
                if cname in sheets: continue
                from mallens.llm.fscache import src_hash
                rec = s2.records.get(cname)
                src = get_class_source(rec, cfg)
                if src is None: continue
                if fscache.get(src_hash(src)): hits += 1
                sheets[cname] = build_factsheet(
                    cname, src, feats_dict(rec), client, fscache, cfg)
        cache.save(sha, f"stage4a_{cfg.factsheet.prompt_version}", sheets,
                   meta={"n": len(sheets), "cache_hits": hits,
                         "dropped": sum(len(f.dropped) for f in sheets.values())})
        print(f"{apk}: {len(sheets)} sheets ({hits} cache hits, "
              f"{sum(len(f.dropped) for f in sheets.values())} claims dropped)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
