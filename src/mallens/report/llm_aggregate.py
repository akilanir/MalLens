"""Stage 5: LLM-based APK-level aggregation.

Consumes stage-4 cluster analyses (verdicts, typed behaviors, quoted
evidence) -- never raw source -- and produces a final APK verdict.
Deterministic guardrails: schema validation, verbatim-quote verification
against the cluster reports, one retry with error feedback, hard
fallback to the legacy rule engine.
"""
from __future__ import annotations

import dataclasses
import json
import re
from typing import Any

from loguru import logger
from mallens.utils.logsetup import setup_logging

from mallens.core.datatypes import LLMAggregateVerdict
from mallens.llm.client import LLMClient
from mallens.llm.openai_client import OpenAIClient
from mallens.llm.prompts import AGG_SYSTEM, AGG_USER_TEMPLATE, FINAL_APK_SYSTEM, FINAL_APK_USER

_ALLOWED_VERDICTS = {"malicious", "suspicious", "benign"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _to_dict(obj: Any) -> dict:
    """Best-effort conversion of a stage-4 cluster analysis to a dict."""
    if isinstance(obj, dict):
        return obj
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    raise TypeError(f"cannot serialize cluster analysis of type {type(obj)}")


def _cluster_report_block(cid: int, analysis: Any) -> tuple[int, str]:
    d = _to_dict(analysis)
    # verdicts: dict[int, ClusterVerdict] = field(default_factory=dict)
    keep = {
        k: d[k]
        for k in (
            "verdict",
            "confidence",
            "behaviors",
            "evidence",
            "network_indicators",
            "family_hint",
            "summary",
            "benign_explanation_considered",
            "why_benign_explanation_rejected",
        )
        if k in d and d[k] not in (None, "", [])
    }
    body = json.dumps(keep, indent=1, ensure_ascii=False, default=str)
    return f"--- Cluster #{cid} ---\n{body}"


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _extract_json(text: str) -> dict:
    """Parse the model reply; tolerate code fences and leading prose."""
    # logger.info("------------------- Enter extract json")
    text = text.strip()
    # logger.info("------------------- Enter Stripped json")
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    # logger.info("------------------- Enter M json")
    if m:
        text = m.group(1)
    start = text.find("{")
    # logger.info("------------------- Got START")
    if start < 0:
        raise ValueError("no JSON object in reply")
    depth = 0
    # logger.info("------------------- Getting depth")
    for i, ch in enumerate(text[start:], start):
        depth += ch == "{"
        depth -= ch == "}"
        if depth == 0:
            try:
                # logger.info("------------------- Inside TRY")
                return json.loads(text[start:i + 1])
            except json.JSONDecodeError as e:
                logger.info("BIG ERROR HERE-------------")
                logger.info(e)
                logger.info(text[start:i + 1][e.pos-80:e.pos+80])
                raise
            # return json.loads(text[start:i + 1])
    raise ValueError("unbalanced JSON in reply")


def _validate(out: dict, valid_ids: set[int], corpus_norm: str) -> list[str]:
    problems: list[str] = []
    if out.get("verdict") not in _ALLOWED_VERDICTS:
        problems.append(
            f"verdict must be one of {sorted(_ALLOWED_VERDICTS)}, "
            f"got {out.get('verdict')!r}")
    try:
        c = float(out.get("confidence"))
        if not 0.0 <= c <= 1.0:
            problems.append("confidence out of [0,1]")
    except (TypeError, ValueError):
        problems.append("confidence is not a number")

    pcs = out.get("payload_clusters") or []
    if not isinstance(pcs, list):
        problems.append("payload_clusters must be a list")
    else:
        bad = [p for p in pcs if not (isinstance(p, int) and p in valid_ids)]
        if bad:
            problems.append(
                f"payload_clusters contains unknown cluster ids {bad}; "
                f"valid ids: {sorted(valid_ids)}")
    if out.get("verdict") == "malicious" and not pcs:
        problems.append("verdict is malicious but payload_clusters is empty")

    quotes = out.get("key_evidence") or []
    if out.get("verdict") == "malicious" and not quotes:
        problems.append("verdict is malicious but key_evidence is empty")
    for q in quotes:
        if not isinstance(q, str) or len(q) < 8:
            problems.append(f"key_evidence entry too short: {q!r}")
        # elif _norm(q) not in corpus_norm:
        #     problems.append(
        #         f"key_evidence not found verbatim in cluster reports: "
        #         f"{q[:80]!r}")
    return problems



# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------
def llm_aggregate(s1, s2, s3, s4, cfg) -> LLMAggregateVerdict:
    # ---- collect cluster reports ----------------------------------------
    client = LLMClient(cfg)
    # client = OpenAIClient(cfg)
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    # ADAPT: s4.analyses -> however stage 4 stores per-cluster results
    # print("Starting LLM AGGREGATION")
    # print(f"S4: {s4}")
    # analyses = list(s4.verdicts.items())
    # print(f"Analysis from Stage 4: {analyses}")
    # print("="* 70)
    blocks, valid_ids = [], set()

    no_clusters = 0
    no_benign = 0
    for cid, analysis in s4.verdicts.items():
        no_clusters += 1
        report_str = _cluster_report_block(cid, analysis)

        valid_ids.add(cid)
        blocks.append(report_str)

        json_body = report_str.split("\n", 1)[1]
        data = json.loads(json_body)

        verdict = data.get("verdict")
        confidence = data.get("confidence")
        if verdict == "benign" or verdict == "BENIGN":
            no_benign += 1
        if (verdict == "suspicious" or verdict == "SUSPICIOUS") and confidence <= 0.7:
            no_benign += 1
        if (verdict == "inconclusive" or verdict == "INCONCLUSIVE") and confidence <= 0.5:
            no_benign += 1
        print(f"------------------- Cluster {cid} is {verdict} with confidence: {confidence}")

    if no_benign == no_clusters:
        print("ALL THE CLUSTERs ARE BENIGN...................")

        # Uncomment if you are using with Bert..
        # print(f"-----------------------------!!!!!!!!! We are stopping the ollama model: {cfg.llm.model}")
        # client.unload_model()

        return LLMAggregateVerdict(
                verdict="benign",
                confidence=1.0,
                payload_clusters=[],
                payload_description=None,
                benign_rationale=None,
                key_evidence=[],
                family_hint=None,
                malicious_classes=["UNKNWN"],
                rules_fired=["UNKWN"],
                source="rule",
                raw=None,
            )

    # for cid, analysis in s4.verdicts.items():
    #     block = _cluster_report_block(cid, analysis)
    #     # print(f"Cluster {cid} report extracted: {block}")
    #     valid_ids.add(cid)
    #     blocks.append(block)
    if not blocks:
        raise RuntimeError("stage 4 produced no cluster analyses")

    cluster_reports = "\n\n".join(blocks)
    corpus_norm = _norm(cluster_reports)

    # ---- static facts -----------------------------------------------------
    apk_metadata = s1.apk
    package = getattr(apk_metadata, "package_name", "unknown")
    permissions = ", ".join(getattr(apk_metadata, "permissions", [])) or "none"
    n_app = len(getattr(s2, "records", {})) # Total classes in the app
    covered = len({m for c in s3.clusters for m in c.class_names}) # Classes covered
    n_suspect = sum(1 for r in s2.records.values() if r.suspicion_naive >= 0.5)

    extra = ""
    if n_suspect:
        names = [ k for k, r in s2.records.items() if r.suspicion_naive > 0.5][:10]
        extra = ("- suspicious classes (sample): " + ", ".join(names) + "\n")
    
    # print("Lets Check the facts ---------------------------------------------")
    # print(f"##### ---- Package: {package}")
    # print(f"##### ---- Permissions: {permissions}")
    # print(f"##### ---- n_app: {n_app}")
    # print(f"##### ---- Covered: {covered}")
    # print(f"##### ---- n_suspect: {n_suspect}")
    # print(f"##### ---- Extra: {extra}")

    user = AGG_USER_TEMPLATE.format(
        package=package, permissions=permissions,
        n_app=n_app, n_covered=covered, n_suspect=n_suspect,
        extra_facts=extra, n_reports=len(blocks),
        cluster_reports=cluster_reports,
    )

    # user = AGG_USER_TEMPLATE.format(n_reports=len(blocks),
    #         cluster_reports=cluster_reports,
    #     )
    # logger.info("USER PROMPT: ---------------------------------------")
    # logger.info(user)

    # ---- call, validate, retry once ---------------------------------------
    reply = client.complete(AGG_SYSTEM, user)

    print(f"VERDICT RESPONSE: \n {reply}")
    logger.info(f"VERDICT RESPONSE: \n {reply}")

    out, problems = None, ["unparsed"]
    for attempt in (1, 2):
        try:
            out = _extract_json(reply[0])
            # print(f"VERDICT RESPONSE: {out}")
            problems = _validate(out, valid_ids, corpus_norm)
        except (ValueError, json.JSONDecodeError) as e:
            # Uncomment if you are using with Bert..
            # client.unload_model()
            out, problems = None, [f"JSON parse error: {e}"]
        if not problems:
            break
        if attempt == 1:
            logger.info(f"VERDICT RESPONSE: \n {reply}")
            logger.warning(f"aggregator reply invalid, retrying: {problems}")
            user_prompt = (
                f"{user}\n\n"
                f"Your previous reply was had issues:\n"
                f"{chr(10).join(f'- {p}' for p in problems)}\n\n"
                f"Return a corrected JSON object only."
            )
            # user_prompt = ( f"{user}\n\n" f"Your previous reply was rejected:\n" f"{'- ' + '\n- '.join(problems)}\n\n" f"Return a corrected JSON object only.")
            reply = client.complete(AGG_SYSTEM, user_prompt)
            logger.info("Second Stage llm response: -------------------------------")
            logger.info(reply)
            out = _extract_json(reply[0])

    # if problems:
    #     raise RuntimeError(f"aggregator failed after retry: {problems}")
    
    # ---- map payload clusters -> class names -------------------------------
    by_id = {int(c.cluster_id): c for c in s3.clusters}   # ADAPT: .cluster_id
    mal_classes = sorted({
        m for pc in out.get("payload_clusters", [])
        for m in by_id[pc].class_names})

    # Uncomment if you are using with Bert..
    # print(f"-----------------------------!!!!!!!!! We are stopping the ollama model: {cfg.llm.model}")
    # client.unload_model()

    return LLMAggregateVerdict(
        verdict=out["verdict"],
        confidence=round(float(out["confidence"]), 3),
        payload_clusters=[int(p) for p in out.get("payload_clusters", [])],
        payload_description=out.get("payload_description") or None,
        benign_rationale=out.get("benign_rationale") or None,
        key_evidence=list(out.get("key_evidence") or []),
        family_hint=out.get("family_hint") or None,
        malicious_classes=mal_classes,
        rules_fired=["llm_aggregator"],
        source="llm",
        raw=out,
    )



def llm_aggregate_cluster_summary(s1, s2, s3, s4, cfg) -> LLMAggregateVerdict:
    # ---- collect cluster reports ----------------------------------------
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    # blocks, valid_ids = [], set()
    data = "## LLM Responses: ----->"

    for cid, analysis in s4.items():
        # logger.info(f"Cluster: {cid} LLM Summary:\n{analysis}")
        data = data + f"### CLUSTER ID: {cid}\n"
        data = data + f"### CLUSTER EXTRACT: {analysis}\n"
        data = data + f"-----------------------------------------------------\n"
               
    user = FINAL_APK_USER.format(cluster_profiles=data,)

    # ---- call, validate, retry once ---------------------------------------
    client = LLMClient(cfg)
    # client = OpenAIClient(cfg)
    reply = client.complete(FINAL_APK_SYSTEM, user)
    # logger.info(f"USER PROMPT-------------\n{user}")

    out, problems = None, ["unparsed"]
    for attempt in (1, 2):
        try:
            out = _extract_json(reply[0])
        except (ValueError, json.JSONDecodeError) as e:
            out, problems = None, [f"JSON parse error: {e}"]
        if not problems:
            break
        if attempt == 1:
            logger.info(f"VERDICT RESPONSE: \n {reply}")
            logger.warning(f"aggregator reply invalid, retrying: {problems}")
            user_prompt = (
                f"{user}\n\n"
                f"Your previous reply was had issues:\n"
                f"{chr(10).join(f'- {p}' for p in problems)}\n\n"
                f"Return a corrected JSON object only."
            )
            # user_prompt = ( f"{user}\n\n" f"Your previous reply was rejected:\n" f"{'- ' + '\n- '.join(problems)}\n\n" f"Return a corrected JSON object only.")
            reply = client.complete(FINAL_APK_SYSTEM, user_prompt)
            logger.info("Second Stage llm response: -------------------------------")
            logger.info(reply)
            out = _extract_json(reply[0])

    
    # ---- map payload clusters -> class names -------------------------------
    by_id = {int(c.cluster_id): c for c in s3.clusters}   # ADAPT: .cluster_id
    mal_classes = sorted({
        m for pc in out.get("payload_clusters", [])
        for m in by_id[pc].class_names})

    return LLMAggregateVerdict(
        verdict=out["verdict"],
        confidence=round(float(out["confidence"]), 3),
        payload_clusters=[int(p) for p in out.get("payload_clusters", [])],
        payload_description=out.get("payload_description") or None,
        benign_rationale=out.get("benign_rationale") or None,
        key_evidence=list(out.get("key_evidence") or []),
        family_hint=out.get("family_hint") or None,
        malicious_classes=mal_classes,
        rules_fired=["llm_aggregator"],
        source="llm",
        raw=out,
    )