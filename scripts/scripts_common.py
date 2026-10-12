#!/usr/bin/env python3
from droidlens.ingest.runner import build_class_graph
from droidlens.features.vectorize import extract_features
from droidlens.clustering.expand import rank_clusters
from droidlens.utils.cache import ArtifactCache, sha256_of_file

def run_stages_1_to_3(apk, cfg, force):
    cache = ArtifactCache(cfg.paths.cache_dir)
    sha = sha256_of_file(apk)
    # s1 = build_class_graph(apk, cfg, force) 
    s1 = build_class_graph(apk, cfg, False) 
    if not force and cache.has(sha, "stage2_ap_features"):
        print("LOADING STAGE 2 FROM CASH")
        s2 = cache.load(sha, "stage2_ap_features")
    else:
        s2 = extract_features(s1, apk, cfg)

    s3 = rank_clusters(s1, s2, cfg)

    print("Done loading S1, S2, and generating S3")

    return s1, s2, s3
