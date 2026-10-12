from __future__ import annotations

from dataclasses import dataclass, field

from loguru import logger
from droidlens.utils.logsetup import setup_logging

from droidlens.config import Config
from droidlens.core.datatypes import Stage1Result, Stage2Result, Stage3Result
from droidlens.llm.client import LLMClient
from droidlens.llm.openai_client import OpenAIClient

# from droidlens.llm.pack import pack_cluster
from droidlens.llm.prompts import SYSTEM, USER_TEMPLATE
from droidlens.llm.verdict import ClusterVerdict, parse_verdict, parse_verdict_fallback
from droidlens.features.api_taxonomy import ApiTaxonomy

# from droidlens.llm.pack_cluster_bert import pack_cluster_with_graph, pack_cluster_class_blocks_with_graph
from droidlens.llm.pack_cluster_bert_saliency import pack_cluster_class_blocks_with_graph


from pathlib import Path

_RETRY_SUFFIX = "\n\nYour previous reply was not valid JSON. Either you had invalid json format (due to code quotes) or different json object. Reply with ONLY the JSON object."


@dataclass
class Stage4Result:
    apk_sha256: str
    model: str
    verdicts: dict[int, ClusterVerdict] = field(default_factory=dict)  # cluster_id ->
    errors: dict[int, str] = field(default_factory=dict)
    usage: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)


def cluster_permission_lines(cl, s1, tax: ApiTaxonomy,
                             declared_perms: set[str]) -> str:
    """Per-cluster permission slice, computed from stage-1 records + taxonomy
    (no stage-2 re-extraction needed)."""
    by_perm: dict[tuple[str, bool], set[str]] = {}
    for cname in cl.class_names:
        rec = s1.class_records.get(cname)
        if rec is None:
            continue
        for sig in rec.api_calls:
            rule = tax.match(sig)
            if rule and rule.permission:
                key = (rule.permission, rule.permission in declared_perms)
                by_perm.setdefault(key, set()).add(sig.split("(")[0])
    if not by_perm:
        return "(none)"
    lines = []
    for (perm, declared), sigs in sorted(by_perm.items()):
        status = "declared" if declared else "NOT DECLARED in manifest"
        lines.append(f"- {perm} ({status}): {', '.join(sorted(sigs)[:5])}")
    return "\n".join(lines)


# APK_SYSTEM = """You are an Android App Analyst specialist. Analyse the given static features extracted from a Android App and explain the apps main role/context in couple of sentences.
#     Just Output:
#     APP ROLE/CONTEXT: 2-3 well detailed sentences about the app role"""

# APP_USER_PROMPT = f"The main app features extracted are: {app_context_data}"

def analyze_clusters(s1: Stage1Result, s2: Stage2Result, s3: Stage3Result, cfg: Config) -> Stage4Result:
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    client = LLMClient(cfg)
    app_context_data = s1.apk.app_role

    out = Stage4Result(apk_sha256=s1.apk.sha256, model=cfg.llm.model)
    # targets = [c for c in s3.clusters
    #            if c.importance >= cfg.llm.min_cluster_importance #(We miss some clusters if the cluster_importance is lower than min_cluster_importance)
    #            ][:cfg.llm.max_clusters]
    CLUSTERS_TO_ANALYZE = 20
    targets = [c for c in s3.clusters][:CLUSTERS_TO_ANALYZE]

    total_in = total_out = 0

    packed_clusters = []
    for cl in targets:
        # packed = pack_cluster(cl, s2, s3, char_budget=cl.est_tokens * 4) # Packing or Truncation: Do we miss cluster classes? est_tokens = bytecode token per cluster
        # Now we bert run whole cluster at once
        import time
        time_1 = time.time()
        # packed = pack_cluster_with_graph(cl, s1, s2, s3, char_budget=cl.est_tokens * 4, cfg=cfg)
        packed, cluster_class_size = pack_cluster_class_blocks_with_graph(cl, s1, s2, s3, char_budget=cl.est_tokens * 4, cfg=cfg)
        cluster_size = len(packed)
        if cluster_size > 200:
            packed_clusters.append(packed)
            time_2 = time.time()
            logger.info(f"CLUSTER size: {cluster_class_size} ID: {cl.cluster_id} TOOK {time_2-time_1} Seconds to run with CodeBert....")
        else:
            logger.info(f"CLUSTER {cl.cluster_id} with size {cluster_size} contains no important details --> Skipping")

 
    # app_role, usage = client.complete(APK_SYSTEM, APP_USER_PROMPT)
    # logger.info(f"----> App Role for the analysing app: {app_role}")
    
    cluster_id = 0
    # for cl in targets:
    for packed in packed_clusters:
        # print(packed)
        # cluster_id = cl.cluster_id
        print(f"----------------------------{cluster_id}---------------------------------")
        # packed = pack_cluster(cl, s2, s3, char_budget=cl.est_tokens * 4) # Packing or Truncation: Do we miss cluster classes? est_tokens = bytecode token per cluster
        # Raw Clusters

        # import time
        # time_1 = time.time()
        # packed = pack_cluster_with_graph(cl, s1, s2, s3, char_budget=cl.est_tokens * 4, cfg=cfg)
        # time_2 = time.time()
        # logger.info(f"CLUSTER {cl.cluster_id} TOOK {time_2-time_1} Seconds to run with CodeBert....")
        # packed = pack_summary_cluster(cl, s1, s2, s3, char_budget=cl.est_tokens * 4, cfg=cfg) # Packing or Truncation: Do we miss cluster classes? est_tokens = bytecode token per cluster
        # What if cluster token is over the llms context length
        # tax = ApiTaxonomy.load(cfg.features.sensitive_api_csv)
        # declared_perm = set(s1.apk.permissions)
        # cluster_premissions = cluster_permission_lines(cl, s1, tax, declared_perm)

        # print("="*100)
        # print(packed)
        # print("="*100)

        # No Permmission details
        user = USER_TEMPLATE.format(
                    package=s1.apk.package_name,
                    app_context = app_context_data,
                    cluster_id=cluster_id,
                    n_classes=len(cl.class_names),
                    packed=packed)

        #############
        # Save Stage 4 LLM input/output for this cluster
        # result_dir = Path("Stage4Results-ClusterSummary_QWEN3_10Clusters_WithAppContext-NOBert-NEWSYS-malradar-0") / s1.apk.sha256
        # result_dir = Path("Stage4Results-SaliencyTest2_malradar2") / s1.apk.sha256
        result_dir = Path("Stage4Results") / s1.apk.sha256
        result_dir.mkdir(parents=True, exist_ok=True)
        result_file = result_dir / f"cluster_{cluster_id}_llmAnalysis.txt"
        result_file.write_text("============================================================\n"
                                "LLM INPUT\n"
                                "============================================================\n\n"
                                + user
                                + "\n\n",
                                encoding="utf-8")
        #############
        try:
            text, usage = client.complete(SYSTEM, user)
            # print("#"*50)
            # logger.info(f"Response:\n{text}")
            # print("#"*50)
            # logger.info(f"LLM Input--------------------------------------")
            # logger.info(user)
            try:
                verdict = parse_verdict(text)
            except Exception:
                print("----------------------------------------Parsing to fallback.........")
                try:
                    verdict = parse_verdict_fallback(text)
                except Exception as e:
                    verdict = None
                    logger.info(f"Verdict Fall back failed due to: {e}")
                print(f"FALLBACKED: {verdict}")
                if verdict is None:
                    logger.warning(f"cluster {cluster_id}: bad JSON, retrying")
                    text, usage2 = client.complete(SYSTEM, user + _RETRY_SUFFIX)
                    usage = {k: usage.get(k, 0) + usage2.get(k, 0) for k in set(usage) | set(usage2)}
                    verdict = parse_verdict(text)

            out.verdicts[cluster_id] = verdict
            #######
            with result_file.open("a", encoding="utf-8") as f:
                f.write(
                    "============================================================\n"
                    "LLM RAW OUTPUT\n"
                    "============================================================\n\n"
                    f"{text}\n\n"
                    "============================================================\n"
                    "PARSED VERDICT\n"
                    "============================================================\n\n"
                    f"Verdict      : {verdict.verdict}\n"
                    f"Confidence   : {verdict.confidence:.4f}\n"
                    f"Behaviors    : {verdict.behaviors}\n"
                    f"Description  : {getattr(verdict, 'description', '(none)')}\n")
            #######
            total_in += usage.get("prompt", 0)
            total_out += usage.get("completion", 0)
            logger.info(f"cluster {cluster_id}: {verdict.verdict} ({verdict.confidence:.2f})")
            # logger.info(f"cluster {cluster_id}: {verdict.verdict} "
            #             f"({verdict.confidence:.2f}) {verdict.behaviors}")
            cluster_id += 1
        except Exception as exc:
            logger.error(f"cluster {cluster_id} failed: {exc}")
            out.errors[cluster_id] = str(exc)
            cluster_id += 1

    out.usage = {"prompt_tokens": total_in, "completion_tokens": total_out}
    out.stats = {
        "clusters_analyzed": len(out.verdicts),
        "clusters_failed": len(out.errors),
        "malicious": sum(1 for v in out.verdicts.values()
                         if v.verdict == "malicious"),
        "suspicious": sum(1 for v in out.verdicts.values()
                          if v.verdict == "suspicious"),
        "benign": sum(1 for v in out.verdicts.values()
                      if v.verdict == "benign"),
    }
    logger.info(f"stage4 done: {out.stats} usage={out.usage}")
    return out


def analyze_clusters_sys(s1: Stage1Result, s2: Stage2Result, s3: Stage3Result, cfg: Config):
    setup_logging(cfg.logging.level,cfg.logging.androguard_level,cfg.paths.log_file)

    client = LLMClient(cfg)
    app_context_data = s1.apk.app_role

    CLUSTERS_TO_ANALYZE = 20
    targets = list(s3.clusters)[:CLUSTERS_TO_ANALYZE]

    packed_clusters = []
    for cl in targets:
        import time
        time_1 = time.time()
        packed, cluster_class_size = pack_cluster_class_blocks_with_graph(cl,s1,s2,s3,char_budget=cl.est_tokens * 4,cfg=cfg)
        cluster_size = len(packed)

        if cluster_size > 200:
            packed_clusters.append((cl, packed))
            time_2 = time.time()
            logger.info(f"CLUSTER ID: {cl.cluster_id} with Size: {cluster_class_size} | TOOK {time_2 - time_1:.2f} seconds to run with BERT...")
        else:
            logger.info(f"CLUSTER {cl.cluster_id} with size {cluster_size} contains no important details --> Skipping")

    
    from droidlens.llm.prompts import SYSTEM_CONTEXTUAL_CONGRUENCE
    
    total_in = 0
    total_out = 0
    out = Stage4Result(apk_sha256=s1.apk.sha256,model=cfg.llm.model)

    logger.info(f"Running System Prompt: SYSTEM_CONTEXTUAL_CONGRUENCE")
    for cl, packed in packed_clusters:
        cluster_id = cl.cluster_id
        logger.info(f"----------------------------Cluster {cluster_id}---------------------------------")
        user = USER_TEMPLATE.format(
            package=s1.apk.package_name,
            app_context=app_context_data,
            cluster_id=cluster_id,
            n_classes=len(cl.class_names),
            packed=packed
        )
        result_dir = (Path(f"Stage4Results-System_SYSTEM_CONTEXTUAL_CONGRUENCE_aggObfLarge") / s1.apk.sha256)
        # result_dir = (Path(f"Stage4Results-System_SYSTEM_CONTEXTUAL_CONGRUENCE_conceptDrift") / s1.apk.sha256)
        result_dir.mkdir(parents=True, exist_ok=True)
        result_file = (result_dir / f"cluster_{cluster_id}_llmAnalysis.txt")
        result_file.write_text(
            "============================================================\n"
            "LLM INPUT\n"
            "============================================================\n\n"
            + user
            + "\n\n",
            encoding="utf-8"
        )
        try:
            text, usage = client.complete(SYSTEM_CONTEXTUAL_CONGRUENCE, user)
            try:
                verdict = parse_verdict(text)
            except Exception:
                logger.info("[IMPORTANT]: Parsing to fallback.........")
                try:
                    verdict = parse_verdict_fallback(text)
                except Exception as e:
                    verdict = None
                    logger.info(f"Verdict fallback failed due to: {e}")
                logger.info(f"FALLBACKED RESPONSE FULL: {verdict}")
                if verdict is None:
                    logger.warning(f"cluster {cluster_id}: bad JSON, retrying")
                    text, usage2 = client.complete(SYSTEM_CONTEXTUAL_CONGRUENCE,user + _RETRY_SUFFIX)
                    usage = {
                        k: usage.get(k, 0) + usage2.get(k, 0)
                        for k in set(usage) | set(usage2)
                    }
                    verdict = parse_verdict(text)
            out.verdicts[cluster_id] = verdict
            input_p = usage.get("prompt", 0)
            output_p = usage.get("completion", 0)
            with result_file.open("a", encoding="utf-8") as f:
                f.write(
                    "============================================================\n"
                    "LLM RAW OUTPUT\n"
                    "============================================================\n\n"
                    f"{text}\n\n"
                    "============================================================\n"
                    "PARSED VERDICT\n"
                    "============================================================\n\n"
                    f"Verdict      : {verdict.verdict}\n"
                    f"Confidence   : {verdict.confidence:.4f}\n"
                    f"Behaviors    : {verdict.behaviors}\n"
                    f"Description  : "
                    f"{getattr(verdict, 'description', '(none)')}\n"
                    f"Usage (in|out): {input_p} | {output_p}\n"
                )
            total_in += usage.get("prompt", 0)
            total_out += usage.get("completion", 0)
            logger.info(
                f"Prompt SYSTEM_CONTEXTUAL_CONGRUENCE | "
                f"cluster {cluster_id}: "
                f"{verdict.verdict} "
                f"({verdict.confidence:.2f})"
            )
        except Exception as exc:
            logger.error(
                f"Prompt SYSTEM_CONTEXTUAL_CONGRUENCE | "
                f"cluster {cluster_id} failed: {exc}"
            )
            out.errors[cluster_id] = str(exc)
    out.usage = {
        "prompt_tokens": total_in,
        "completion_tokens": total_out
    }
    out.stats = {
        "clusters_analyzed": len(out.verdicts),
        "clusters_failed": len(out.errors),
        "malicious": sum(
            1 for v in out.verdicts.values()
            if v.verdict == "malicious"
        ),
        "suspicious": sum(
            1 for v in out.verdicts.values()
            if v.verdict == "suspicious"
        ),
        "benign": sum(
            1 for v in out.verdicts.values()
            if v.verdict == "benign"
        )
    }
    logger.info(
        f"Stage4 done for System Prompt SYSTEM_CONTEXTUAL_CONGRUENCE: "
        f"{out.stats} usage={out.usage}"
    )
    return out


# def analyze_clusters_sys(s1: Stage1Result, s2: Stage2Result, s3: Stage3Result, cfg: Config):
#     setup_logging(cfg.logging.level,cfg.logging.androguard_level,cfg.paths.log_file)

#     client = LLMClient(cfg)
#     # client = OpenAIClient(cfg)
#     app_context_data = s1.apk.app_role

#     OUT_LIST = []
#     CLUSTERS_TO_ANALYZE = 20
#     targets = list(s3.clusters)[:CLUSTERS_TO_ANALYZE]

#     packed_clusters = []

#     for cl in targets:
#         import time
#         time_1 = time.time()
#         packed, cluster_class_size = pack_cluster_class_blocks_with_graph(cl,s1,s2,s3,char_budget=cl.est_tokens * 4,cfg=cfg)
#         cluster_size = len(packed)

#         if cluster_size > 200:
#             packed_clusters.append((cl, packed))
#             time_2 = time.time()
#             logger.info(f"CLUSTER {cl.cluster_id} TOOK {time_2 - time_1:.2f} seconds to run with CodeBERT...")
#         else:
#             logger.info(f"CLUSTER {cl.cluster_id} with size {cluster_size} contains no important details --> Skipping")

    
#     from droidlens.llm.prompts import (SYSTEM_STRICT_EVIDENCE,SYSTEM_CONTEXTUAL_CONGRUENCE,SYSTEM_BALANCED,SYSTEM_SECURITY_FOCUS)
#     # system_prompts = [SYSTEM_STRICT_EVIDENCE, SYSTEM_CONTEXTUAL_CONGRUENCE, SYSTEM_BALANCED, SYSTEM_SECURITY_FOCUS]
#     system_prompts = [SYSTEM_CONTEXTUAL_CONGRUENCE]

#     for SYS_Prompt_Id, SYS in enumerate(system_prompts, 1):
#         total_in = 0
#         total_out = 0
#         out = Stage4Result(apk_sha256=s1.apk.sha256,model=cfg.llm.model)
#         logger.info(
#             f"{SYS_Prompt_Id} - Running System Prompt: "
#             f"{SYS_Prompt_Id} --------------------------"
#         )
#         for cl, packed in packed_clusters:
#             cluster_id = cl.cluster_id
#             print(f"----------------------------Prompt {SYS_Prompt_Id} | Cluster {cluster_id}---------------------------------")

#             user = USER_TEMPLATE.format(
#                 package=s1.apk.package_name,
#                 app_context=app_context_data,
#                 cluster_id=cluster_id,
#                 n_classes=len(cl.class_names),
#                 packed=packed
#             )
#             result_dir = (Path(f"Stage4Results-System_{SYS_Prompt_Id}") / s1.apk.sha256)
#             result_dir.mkdir(parents=True, exist_ok=True)
#             result_file = (result_dir / f"cluster_{cluster_id}_llmAnalysis.txt")

#             result_file.write_text(
#                 "============================================================\n"
#                 "LLM INPUT\n"
#                 "============================================================\n\n"
#                 + user
#                 + "\n\n",
#                 encoding="utf-8"
#             )

#             try:
#                 text, usage = client.complete(SYS, user)
#                 try:
#                     verdict = parse_verdict(text)
#                 except Exception:
#                     print("----> Parsing to fallback.........")
#                     try:
#                         verdict = parse_verdict_fallback(text)
#                     except Exception as e:
#                         verdict = None
#                         logger.info(f"Verdict fallback failed due to: {e}")
#                     print(f"FALLBACKED: {verdict}")
#                     if verdict is None:
#                         logger.warning(f"cluster {cluster_id}: bad JSON, retrying")
#                         text, usage2 = client.complete(SYS,user + _RETRY_SUFFIX)
#                         usage = {
#                             k: usage.get(k, 0) + usage2.get(k, 0)
#                             for k in set(usage) | set(usage2)
#                         }
#                         verdict = parse_verdict(text)
#                 out.verdicts[cluster_id] = verdict
#                 with result_file.open("a", encoding="utf-8") as f:
#                     f.write(
#                         "============================================================\n"
#                         "LLM RAW OUTPUT\n"
#                         "============================================================\n\n"
#                         f"{text}\n\n"
#                         "============================================================\n"
#                         "PARSED VERDICT\n"
#                         "============================================================\n\n"
#                         f"Verdict      : {verdict.verdict}\n"
#                         f"Confidence   : {verdict.confidence:.4f}\n"
#                         f"Behaviors    : {verdict.behaviors}\n"
#                         f"Description  : "
#                         f"{getattr(verdict, 'description', '(none)')}\n"
#                     )

#                 total_in += usage.get("prompt", 0)
#                 total_out += usage.get("completion", 0)
#                 logger.info(
#                     f"Prompt {SYS_Prompt_Id} | "
#                     f"cluster {cluster_id}: "
#                     f"{verdict.verdict} "
#                     f"({verdict.confidence:.2f})"
#                 )

#             except Exception as exc:
#                 logger.error(
#                     f"Prompt {SYS_Prompt_Id} | "
#                     f"cluster {cluster_id} failed: {exc}"
#                 )
#                 out.errors[cluster_id] = str(exc)

#         out.usage = {
#             "prompt_tokens": total_in,
#             "completion_tokens": total_out
#         }

#         out.stats = {
#             "clusters_analyzed": len(out.verdicts),
#             "clusters_failed": len(out.errors),
#             "malicious": sum(
#                 1 for v in out.verdicts.values()
#                 if v.verdict == "malicious"
#             ),
#             "suspicious": sum(
#                 1 for v in out.verdicts.values()
#                 if v.verdict == "suspicious"
#             ),
#             "benign": sum(
#                 1 for v in out.verdicts.values()
#                 if v.verdict == "benign"
#             )
#         }
#         logger.info(
#             f"Stage4 done for System Prompt {SYS_Prompt_Id}: "
#             f"{out.stats} usage={out.usage}"
#         )
#         OUT_LIST.append(out)

#     return OUT_LIST

# from droidlens.summarization.summ_prompts import CLUSTER_PROFILE_SYSTEM, CLUSTER_PROFILE_USER

# def summarize_clusters(s1: Stage1Result, s2: Stage2Result, s3: Stage3Result, cfg: Config):
#     setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
#     client = LLMClient(cfg)
#     # out = Stage4Result(apk_sha256=s1.apk.sha256, model=cfg.llm.model)
#     summaries: dict[int, str] = {}
#     prompt_tokens = 0
#     completion_tokens = 0

#     # Here we do not analyse all the 10 clusters: if importance is lower than the threshold
#     targets = [c for c in s3.clusters if c.importance >= cfg.llm.min_cluster_importance][:cfg.llm.max_clusters]

#     total_in = total_out = 0
#     for cl in targets:
#         packed = pack_cluster_with_graph(cl, s1, s2, s3, char_budget=cl.est_tokens * 4, cfg=cfg) # Packing or Truncation: Do we miss cluster classes? est_tokens = bytecode token per cluster
#         user = CLUSTER_PROFILE_USER.format(cluster_id=cl.cluster_id, package_name=s1.apk.package_name, class_names=cl.class_names, all_sources=packed)

#         # Save Stage 4 LLM input/output for this cluster
#         result_dir = Path("Stage4Results-ClusterSummary_TEST5_12Clusters") / s1.apk.sha256
#         result_dir.mkdir(parents=True, exist_ok=True)
#         result_file = result_dir / f"cluster_{cl.cluster_id}_llmAnalysis.txt"
#         result_file.write_text("============================================================\n"
#                                 "LLM INPUT\n"
#                                 "============================================================\n\n"
#                                 + user
#                                 + "\n\n",
#                                 encoding="utf-8")
#         try:
#             text, usage = client.complete(CLUSTER_PROFILE_SYSTEM, user)
#             summaries[cl.cluster_id]=text
#             prompt_tokens += usage.get("prompt")
#             completion_tokens += usage.get("completion")
            
#             with result_file.open("a", encoding="utf-8") as f:
#                 f.write(
#                     "============================================================\n"
#                     "LLM RAW OUTPUT\n"
#                     "============================================================\n\n"
#                     f"{text}\n\n"
#                     "============================================================\n\n"
#                     f"Packed Length: {len(packed)}\n"
#                     f"Estimated Tokens: {len(packed)/4}\n"
#                     f"LLM Usage: {usage}\n")
#         except Exception as exec:
#             logger.error(f"LLM Client Chat Completion Error: {exec}")
#         total_usage = {"prompt": prompt_tokens,"completion": completion_tokens,}
        
#     return summaries, total_usage