"""Stage 2 orchestrator: Stage1Result -> Stage2Result."""
from __future__ import annotations

import math
from pathlib import Path

from loguru import logger
from mallens.utils.logsetup import setup_logging

from mallens.config import Config
from mallens.core.datatypes import (ClassFeatureRecord, FeatureVector,
                                      Stage1Result, Stage2Result)
from mallens.features.api_taxonomy import ApiTaxonomy
from mallens.features.decompile import run_jadx
from mallens.features.manifest import extract_components
from mallens.features.strings import analyze_strings
from mallens.features.attack_suspicion import compute_attack_suspicion

_STRUCT = ["method_count", "native_method_count", "bytecode_size", "loc",
           "in_degree", "out_degree", "weighted_in", "weighted_out",
           "lib_call_count"]
_FLAGS = ["spoofed_framework", "is_component", "is_exported",
          "intent_filter_count", "jadx_ok"]
_API = ["api_total", "api_declared_perm", "api_undeclared_perm"]
_STR = ["str_count", "str_high_entropy", "str_max_entropy", "str_urls",
        "str_ips", "str_base64", "str_shell", "str_exec_files",
        "str_shortcodes", "str_impair_defenses"]


def extract_features(s1: Stage1Result, apk_path: str | Path, cfg: Config) -> Stage2Result:
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    tax = ApiTaxonomy.load(cfg.features.sensitive_api_csv)
    feature_names = (_STRUCT + _FLAGS + _API +
                     [f"{c}" for c in tax.categories] + _STR)

    components = extract_components(apk_path)
    jadx = run_jadx(apk_path, s1.apk.sha256, cfg)
    declared_perms = set(s1.apk.permissions)
    # print(f"DECLARED PERMISSIONS: {declared_perms}")
    g = s1.graph

    records: dict[str, ClassFeatureRecord] = {}
    jadx_hits = 0
    analysed_class_no = 0
    for cname, raw_cls_rec in s1.class_records.items():
        analysed_class_no += 1
        f: dict[str, float] = {}
        # ---- structural ------------------------------------------------
        loc = jadx.loc_for(cname) # mapping smali path with java Lcom/foo/Bar$Inner;' -> sources/com/foo/Bar.java
        if loc is not None:
            jadx_hits += 1
        f["method_count"] = raw_cls_rec.method_count
        f["native_method_count"] = raw_cls_rec.native_method_count
        f["bytecode_size"] = raw_cls_rec.bytecode_size
        f["loc"] = float(loc if loc is not None else 0)
        f["in_degree"] = g.in_degree(cname) if g.has_node(cname) else 0
        f["out_degree"] = g.out_degree(cname) if g.has_node(cname) else 0
        f["weighted_in"] = g.in_degree(cname, weight="weight") if g.has_node(cname) else 0
        f["weighted_out"] = g.out_degree(cname, weight="weight") if g.has_node(cname) else 0
        f["lib_call_count"] = raw_cls_rec.lib_call_count

        # ---- flags -----------------------------------------------------
        comp = components.get(cname)
        f["spoofed_framework"] = float(getattr(raw_cls_rec, "spoofed_framework_name", False))
        f["is_component"] = float(comp is not None)
        f["is_exported"] = float(comp.exported if comp else False)
        f["intent_filter_count"] = float(comp.intent_filter_count if comp else 0)
        f["jadx_ok"] = float(loc is not None)

        # ---- sensitive APIs ---------------------------------------------
        cat_counts: dict[str, int] = {}
        declared = undeclared = total = 0
        suspicion = 0.0
        per_cat_w: dict[str, float] = {}
        # logger.info("LETS PRINT SOME API SIGNATURES FROM APK:")
        for sig, cnt in raw_cls_rec.api_calls.items():
            # print("IT IS HERE THAT WE STOPPED......")
            # print(sig)
            rule = tax.match(sig)
            if rule is None:
                continue
            # logger.info(f"FROM RAW_CLS_RECORD: {sig}")
            # logger.info(f"FOM MATCHED RULES: {rule}")
            total += cnt
            cat_counts[rule.category] = cat_counts.get(rule.category, 0) + cnt
            per_cat_w[rule.category] = max(per_cat_w.get(rule.category, 0.0), rule.weight)
            if rule.permission:
                # logger.info(f"Detected API RULE: {rule}")
                if rule.permission in declared_perms: # Checking any permission related APIs missing permisions in Manifest
                    # logger.info(f"This RULE is declared: {rule}")
                    declared += cnt
                else:
                    # logger.info(f"This RULE is UNDECLARED!!!!!: {rule} -- signal: {sig}")
                    undeclared += cnt
        f["api_total"] = float(total) # in one class
        f["api_declared_perm"] = float(declared)
        f["api_undeclared_perm"] = float(undeclared)
        for c in tax.categories:
            f[f"{c}"] = float(cat_counts.get(c, 0)) #category-wise count
            # f[f"cat_{c}"] = float(cat_counts.get(c, 0)) #category-wise count
        # THIS IS WHERE WE CALCULATED CLASS NAIVE SUSPICION: based on perm_api count
        # naive suspicion: weight * log-damped count, summed over categories
        # for c, n in cat_counts.items():
        #     suspicion += per_cat_w[c] * math.log1p(n) # In the current setup we have same per_cat_w = 1.0
        # if f["spoofed_framework"]:
        #     suspicion += cfg.features.spoof_bonus # = 10.0

        # details = {
        #         "score": round(suspicion, 3),
        #     }

        # ---- strings -----------------------------------------------------
        f.update(analyze_strings(raw_cls_rec.string_constants,
                                 cfg.features.entropy_threshold,
                                 cfg.features.min_string_len_for_entropy))

        # print("attack sus..")
        suspicion, details = compute_attack_suspicion(f)

        jp = jadx.java_path_for(cname) # mapping smali path with java Lcom/foo/Bar$Inner;' -> sources/com/foo/Bar.java
        records[cname] = ClassFeatureRecord(
            vector=FeatureVector(class_name=cname, feature_names=feature_names,
                                 values=[float(f[k]) for k in feature_names]),
            jadx_ok=loc is not None,
            java_path=str(jp) if jp else None,
            api_categories=cat_counts,
            suspicion_naive=round(suspicion, 3),
        )

    stats = {
        "classes": len(records),
        "jadx_coverage": round(jadx_hits / max(1, len(records)), 3),
        "components_mapped": sum(1 for c in components if c in s1.class_records),
        "components_in_manifest": len(components),
        "classes_with_sensitive_api": sum(
            1 for r in records.values() if r.api_categories),
        "undeclared_perm_classes": sum(
            1 for r in records.values()
            if r.vector.values[feature_names.index("api_undeclared_perm")] > 0),
    }
    stats.update(details)
    logger.info(f"!! stage2 done: {stats} | Analysed {analysed_class_no} Classes...")
    return Stage2Result(apk_sha256=s1.apk.sha256, feature_names=feature_names,
                        records=records, jadx_stats={"ok": jadx.ok}, stats=stats)



#####------- Debug method can comment later
import csv
from pathlib import Path

def save_fired_tactics(s1, apk_path, cname, details):
    from mallens.features.attack_suspicion import ATTACK_MAPPINGS
    attack_csv = Path("results/malware_attack_rules.csv")

    attack_csv.parent.mkdir(parents=True, exist_ok=True)
    file_exists = attack_csv.exists()
    with attack_csv.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)

        if not file_exists:
            writer.writerow([
                "apk_sha256",
                "apk_name",
                "class_name",
                "suspicion_score",
                "technique_id",
                "tactic",
            ])

        # One row for every ATT&CK technique fired by this class
        for technique_id in details["techniques"]:
            # Find the corresponding tactic from your mapping
            tactic = next((rule.tactic for rule in ATTACK_MAPPINGS if rule.technique_id == technique_id),"unknown")

            writer.writerow([
                s1.apk.sha256,
                Path(apk_path).name,
                cname,
                details["score"],
                technique_id,
                tactic,
            ])