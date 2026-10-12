#!/usr/bin/env python3

"""
Graph-guided agentic cluster malware analysis.
Pipeline:
Stage 1:
    APK -> classes + call graph
Stage 2:
    classes -> feature vectors
Stage 3:
    importance -> ranked clusters
Stage 4:
    graph-guided agent:
        Interpreter
            ->
        Navigator
            ->
        Interpreter
            ->
        ...
            ->
        Judge

IMPORTANT:
This script analyses clusters only.
APK-level aggregation is deliberately handled separately.
Usage:
python scripts/04_agentic_cluster.py --config configs/default.yaml --model llama3.1:8b app.apk

Multiple APKs:
python scripts/04_agentic_cluster.py --config configs/default.yaml --model llama3.1:8b app1.apk app2.apk
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from loguru import logger

from droidlens.config import Config
from droidlens.ingest.runner import build_class_graph
from droidlens.features.vectorize import extract_features
from droidlens.clustering.expand import rank_clusters
from droidlens.utils.cache import (ArtifactCache, sha256_of_file,)
from droidlens.utils.logsetup import setup_logging
from droidlens.agentic.ollama_client import (OllamaClient,)
from droidlens.agentic.cluster_agent import (GraphGuidedClusterAgent,)


def save_cluster_results(output_dir: Path, apk_sha: str, results: list,):
    output_dir.mkdir(parents=True, exist_ok=True,)
    path = (output_dir/ f"{apk_sha}_cluster_verdicts.json")
    data = {"apk_sha256": apk_sha,"clusters": [],}
    for result in results:
        data["clusters"].append(
            {
                "cluster_id": result.cluster_id,
                "seed_class": result.seed_class,
                "verdict": result.verdict,
                "confidence": result.confidence,
                "investigated_classes": (result.investigated_classes),
                "evidence_paths": (result.evidence_paths),
                "verified_evidence": (result.verified_evidence),
                "reasoning": result.reasoning,
                "navigation_steps": (result.navigation_steps),
                "stop_reason": (result.stop_reason),
                "raw_judge_response": (result.raw_judge_response),
            }
        )
    with path.open("w",encoding="utf-8",) as f:
        json.dump(data, f, indent=2, ensure_ascii=False,)
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks",nargs="+",)
    ap.add_argument("--config",default="configs/default.yaml",)
    ap.add_argument("--model",default="llama3.1:8b",)
    ap.add_argument("--ollama-host",default="http://localhost:11434",)
    ap.add_argument("--max-steps",type=int,default=8,)
    ap.add_argument("--min-steps",type=int,default=2,)
    ap.add_argument("--output-dir",default="outputs/agentic",)
    ap.add_argument("--force",action="store_true",)
    args = ap.parse_args()
    cfg = Config.load(args.config)
    setup_logging(cfg.logging.level,cfg.logging.androguard_level,"agentic_v1.log")

    cache = ArtifactCache(cfg.paths.cache_dir)
    ollama = OllamaClient(host=args.ollama_host, model=args.model, temperature=0.0,)
    output_dir = Path(args.output_dir)
    for apk in args.apks:
        logger.info("\n" + "=" * 80)
        logger.info(f"APK: {apk}")
        logger.info(f"MODEL: {args.model}")
        logger.info("=" * 80)
        sha = sha256_of_file(apk)
        # ------------------------------------------------------------
        # Stage 1
        # ------------------------------------------------------------
        logger.info("\n[Stage 1] Building class graph...")
        s1 = build_class_graph(apk, cfg,)

        # ------------------------------------------------------------
        # Stage 2
        # ------------------------------------------------------------
        logger.info("[Stage 2] Extracting features...")
        if (not args.force and cache.has(sha,"stage2_features",)):
            s2 = cache.load(sha,"stage2_features",)
        else:
            s2 = extract_features(s1, apk, cfg,)
            cache.save(sha, "stage2_features", s2, meta=s2.stats,)

        # ------------------------------------------------------------
        # Stage 3
        # ------------------------------------------------------------
        logger.info("[Stage 3] Ranking clusters...")
        scorer_name = (cfg.importance.scorer)
        stage3_key = (f"stage3_{scorer_name}")
        if (not args.force and cache.has(sha, stage3_key,)):
            s3 = cache.load(sha,stage3_key,)
        else:
            s3 = rank_clusters(s1,s2,cfg,)
            cache.save(sha,stage3_key,s3,meta=s3.stats,)
        logger.info( f"\nClusters: " f"{len(s3.clusters)}")
        logger.info(f"Coverage: " f"{s3.stats.get('coverage_ratio')}")

        # ------------------------------------------------------------
        # Stage 4 — Agentic analysis
        # ------------------------------------------------------------
        agent = GraphGuidedClusterAgent(s1=s1,s2=s2,s3=s3,ollama=ollama,max_steps=args.max_steps,min_steps_before_judge=args.min_steps,)
        results = []
        for cluster in s3.clusters:
            logger.info( "\n" + "-" * 80)
            logger.info(f"CLUSTER #{cluster.cluster_id}")
            logger.info(f"Importance: "f"{cluster.importance:.4f}")
            logger.info(f"Seed: "f"{cluster.seed_class}")
            logger.info(f"Classes: "f"{len(cluster.class_names)}")
            logger.info(f"Estimated tokens: "f"{cluster.est_tokens}")
            logger.info("-" * 80)
            logger.info("=== Running Agent for Clsuter.")
            logger.info("=== Running Agent for Clsuter..")
            logger.info("=== Running Agent for Clsuter...")
            logger.info("=== Running Agent for Clsuter....")
            result = agent.run_cluster(cluster)
            results.append(result)
            logger.info("\nRESULT")
            logger.info(f"Verdict: "f"{result.verdict}")
            logger.info(f"Confidence: "f"{result.confidence:.3f}")
            logger.info(f"Investigated: "f"{len(result.investigated_classes)}")
            logger.info(f"      Paths: "f"{result.evidence_paths}")
            logger.info(f"      Reason: "f"{result.reasoning}")

        # ------------------------------------------------------------
        # Save
        # ------------------------------------------------------------
        output_path = save_cluster_results(output_dir,sha,results,)
        # ------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------
        benign = sum(r.verdict == "BENIGN"for r in results)
        malware = sum(r.verdict == "MALWARE"for r in results)
        logger.info("\n"+ "=" * 80)
        logger.info("CLUSTER ANALYSIS COMPLETE")
        logger.info(f"BENIGN clusters : {benign}")
        logger.info(f"MALWARE clusters: {malware}")
        logger.info(f"Saved: {output_path}")
        logger.info("=" * 80)
    return 0

if __name__ == "__main__":
    sys.exit(main())