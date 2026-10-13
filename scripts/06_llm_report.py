#!/usr/bin/env python3
"""End-to-end (cache-aware) with LLM-based final aggregation.

Legacy rule engine runs in SHADOW mode: its verdict is computed, logged and
stored alongside the LLM verdict, but the LLM verdict is authoritative.
On any aggregator failure the rule verdict takes over (source=rule_fallback).
"""
import argparse
import dataclasses
import json
import sys
from pathlib import Path
from loguru import logger

from mallens.config import Config
from mallens.ingest.runner import build_class_graph
from mallens.features.vectorize import extract_features
from mallens.clustering.expand import rank_clusters
from mallens.llm.analyze import analyze_clusters_sys
from mallens.report.aggregate import aggregate as rule_aggregate
from mallens.utils.cache import ArtifactCache, sha256_of_file
from mallens.utils.logsetup import setup_logging

from mallens.report.llm_aggregate import llm_aggregate
from mallens.core.datatypes import LLMAggregateVerdict

from mallens.llm.client import LLMClient
from mallens.llm.openai_client import OpenAIClient


def write_reports(apk: str, sha: str, av: LLMAggregateVerdict, out_dir: str) -> str:
    out = Path(out_dir) / sha[:12]
    out.mkdir(parents=True, exist_ok=True)

    (out / "verdict.json").write_text(
        json.dumps(dataclasses.asdict(av), indent=2, ensure_ascii=False,
                   default=str))

    lines = [
        f"# DroidLens report -- {Path(apk).name}",
        "",
        f"**Verdict: {av.verdict.upper()}** "
        f"(confidence {av.confidence}, source: {av.source})",
        "",
    ]
    if av.verdict == "malicious":
        lines += [
            f"**Payload:** {av.payload_description or 'n/a'}",
            "",
            f"**Payload clusters:** {av.payload_clusters}",
            f"**Family hint:** {av.family_hint or 'unknown'}",
            "",
            "**Localized classes:**",
            *[f"- `{c}`" for c in av.malicious_classes[:40]],
            "",
            "**Key evidence:**",
            *[f"> {q}" for q in av.key_evidence],
        ]
    else:
        lines += [f"**Rationale:** {av.benign_rationale or 'n/a'}"]
    if av.shadow:
        lines += ["", "---",
                  f"_Shadow (rule engine): {av.shadow['verdict']} "
                  f"({av.shadow['confidence']}) "
                  f"rules={av.shadow['rules_fired']}_"]
    md = out / "report.md"
    md.write_text("\n".join(lines))
    return str(md)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apks", nargs="+")
    ap.add_argument("--config", default=None)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    cfg = Config.load(args.config)
    client = LLMClient(cfg)
    # client = OpenAIClient(cfg)

    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    cache = ArtifactCache(cfg.paths.cache_dir)

    logger.info("--------- FROM SINGLE SYSTEM LLM DETECTOR -----------------")

    disagreements = 0
    for apk in args.apks:
        sha = sha256_of_file(apk)

        # ---- stages 1-4, cache-aware (unchanged from 05_report) ----------
        # Rebuilding graph again and agin now will be expensive now (extra 30 - 60 seconds)
        s1 = build_class_graph(apk, cfg, False) # True: We re-build the graphs and extract apis again (If you change Lib Detection YOu need to re run this)
        if not args.force and cache.has(sha, "stage2_features"):
            s2 = cache.load(sha, "stage2_features")
            logger.info("  (stage2 cache hit)")
        else:
            s2 = extract_features(s1, apk, cfg) #If you want to change the suspicion score you need to run this, IF not dont force it
            cache.save(sha, "stage2_features", s2, meta=s2.stats)
        s3 = rank_clusters(s1, s2, cfg)

        # ---- stage 4: llm querying
        import time
        time1=time.time()
        # ratio = "conceptDrift"
        ratio = "aggObfLarge"
        s4_key = f"stage4_{ratio}_{cfg.llm.model.replace('/', '_')}"
        if not args.force and cache.has(sha, s4_key):
            s4 = cache.load(sha, s4_key)
        else:
            logger.info("Generating Stage 4 results...")
            s4 = analyze_clusters_sys(s1, s2, s3, cfg)
            cache.save(sha, s4_key, s4, meta=s4.stats)
        time2=time.time()
         
        # ---- stage 5: LLM aggregation, cache-aware ------------------------
        s5_key = f"stage5llm_{ratio}_{cfg.llm.model.replace('/', '_')}"

        if not args.force and cache.has(sha, s5_key):
            av = cache.load(sha, s5_key)
        else:
            try:
                av = llm_aggregate(s1, s2, s3, s4, cfg)
                logger.info(f"Result Verdict: {av}")
            except Exception as e:
                # print(f"  !! LLM aggregation failed ({e}); " f"falling back to rule engine", file=sys.stderr)
                logger.error(f"!! LLM aggregation failed ({e}); " f"No falling back at the moment")
                av = LLMAggregateVerdict(
                    verdict="UNKWN",
                    confidence="UNKWN",
                    malicious_classes=["UNKWN"],
                    rules_fired=["UNKWN"],
                    source="PLACEHOLDER",
                )
            cache.save(sha, s5_key, av, meta={"verdict": av.verdict, "source": av.source})

        
        # ---- output ---------------------------------------------------------
        time3 = time.time()
        # Uncomment if you are using with Bert..
        try:
            client.unload_model()
        except Exception as exc:
            logger.warning(f"Error unloading model: {exc}")
        
        logger.info(f"TIME TOOK TO STAGE4: {time2-time1}")
        logger.info(f"TIME TOOK FOR STAGE5: {time3-time2}")

        mp = write_reports(apk, sha, av, cfg.report.out_dir)
        logger.info(f"\n{apk}")
        logger.info(f"  VERDICT: {av.verdict.upper()} "
              f"({av.confidence}) [{av.source}]")
        if av.verdict == "malicious":
            logger.info(f"  payload clusters: {av.payload_clusters}  "
                  f"family: {av.family_hint or '?'}")
            logger.info(f"  payload: {av.payload_description}")
        else:
            logger.info(f"  rationale: {av.benign_rationale}")
        if av.shadow:
            marker = ("AGREE" if av.shadow["verdict"] == av.verdict
                      else ">>> DISAGREE <<<")
            logger.info(f"  shadow(rules): {av.shadow['verdict']} "
                  f"({av.shadow['confidence']})  {marker}")
        logger.info(f"  localized: {len(av.malicious_classes)} classes")
        logger.info(f"  report: {mp}")

if __name__ == "__main__":
    sys.exit(main())
