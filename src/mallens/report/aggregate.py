# """Cluster verdicts -> APK verdict, with an auditable rule trace."""
# from __future__ import annotations

# from dataclasses import dataclass, field

# from loguru import logger

# from mallens.config import Config
# from mallens.core.datatypes import Stage2Result, Stage3Result
# from mallens.llm.analyze import Stage4Result


# @dataclass
# class ApkVerdict:
#     verdict: str                      # malicious|suspicious|benign|inconclusive
#     confidence: float
#     rules_fired: list[str] = field(default_factory=list)
#     behaviors: list[str] = field(default_factory=list)
#     network_indicators: list[str] = field(default_factory=list)
#     family_hints: list[str] = field(default_factory=list)
#     malicious_classes: list[str] = field(default_factory=list)  # localization output
#     unanalyzed_important: list[str] = field(default_factory=list)


# def _norm_indicator(ind: str) -> str:
#     """Crude host extraction so http://x.com/a and x.com:22 corroborate."""
#     ind = ind.lower().strip()
#     for pre in ("https://", "http://", "ftp://", "ssh://"):
#         ind = ind.removeprefix(pre)
#     return ind.split("/")[0].split(":")[0]


# def aggregate(s2: Stage2Result, s3: Stage3Result, s4: Stage4Result,
#               cfg: Config) -> ApkVerdict:
#     r = cfg.report
#     fired: list[str] = []
#     clusters = {c.cluster_id: c for c in s3.clusters}

#     flagged = {cid: v for cid, v in s4.verdicts.items()
#                if v.verdict in ("malicious", "suspicious")}
#     hard_mal = [cid for cid, v in flagged.items()
#                 if v.verdict == "malicious" and v.confidence >= r.t_malicious_conf]
#     soft = [cid for cid, v in flagged.items()
#             if v.confidence >= r.t_suspicious_conf]

#     # --- corroboration among soft hits ------------------------------------
#     corroborated = False
#     if len(soft) >= 2:
#         host_owners: dict[str, set[int]] = {}
#         for cid in soft:
#             for ind in s4.verdicts[cid].network_indicators:
#                 host_owners.setdefault(_norm_indicator(ind), set()).add(cid)
#         shared = {h: o for h, o in host_owners.items() if len(o) >= 2}
#         if shared:
#             corroborated = True
#             fired.append(f"corroboration: clusters share network hosts {sorted(shared)}")
#         names = s2.feature_names
#         spoof_idx = names.index("spoofed_framework")
#         spoofed_clusters = [
#             cid for cid in soft if any(
#                 s2.records[m].vector.values[spoof_idx] > 0
#                 for m in clusters[cid].class_names if m in s2.records)]
#         if len(spoofed_clusters) >= 2:
#             corroborated = True
#             fired.append(f"corroboration: {len(spoofed_clusters)} flagged clusters "
#                          "contain spoofed-framework classes")

#     # --- honesty guard ------------------------------------------------------
#     unseen = [c for c in s3.clusters
#               if c.cluster_id not in s4.verdicts
#               and c.cluster_id not in s4.errors
#               and c.importance >= r.t_unseen_importance]
#     unseen_names = [c.seed_class for c in unseen]

#     # --- decide -------------------------------------------------------------
#     if hard_mal:
#         verdict = "malicious"
#         fired.append(f"rule: cluster(s) {hard_mal} malicious with conf >= "
#                      f"{r.t_malicious_conf}")
#         confidence = max(s4.verdicts[c].confidence for c in hard_mal)
#     elif corroborated:
#         verdict = "malicious"
#         confidence = min(0.9, max(s4.verdicts[c].confidence for c in soft))
#     elif flagged:
#         verdict = "suspicious"
#         fired.append(f"rule: flagged clusters {sorted(flagged)} below "
#                      "malicious threshold / uncorroborated")
#         confidence = max(v.confidence for v in flagged.values())
#     elif s4.errors or unseen:
#         verdict = "inconclusive"
#         if s4.errors:
#             fired.append(f"rule: {len(s4.errors)} cluster analyses failed")
#         if unseen:
#             fired.append(f"rule: high-importance clusters not analyzed: "
#                          f"{unseen_names}")
#         confidence = 0.0
#     else:
#         verdict = "benign"
#         fired.append("rule: all analyzed clusters benign/inconclusive, "
#                      "no important cluster unanalyzed")
#         confidence = min((v.confidence for v in s4.verdicts.values()
#                           if v.verdict == "benign"), default=0.5)

#     mal_classes = sorted({m for cid in flagged
#                           for m in clusters[cid].class_names})
#     out = ApkVerdict(
#         verdict=verdict, confidence=round(confidence, 2), rules_fired=fired,
#         behaviors=sorted({b for v in flagged.values() for b in v.behaviors}),
#         network_indicators=sorted({i for v in flagged.values()
#                                    for i in v.network_indicators}),
#         family_hints=sorted({v.family_hint for v in flagged.values()
#                              if v.family_hint}),
#         malicious_classes=mal_classes,
#         unanalyzed_important=unseen_names,
#     )
#     logger.info(f"stage5: {verdict} ({confidence:.2f}), "
#                 f"{len(mal_classes)} classes localized, rules={fired}")
#     return out

"""Cluster verdicts -> APK verdict, with an auditable rule trace."""
from __future__ import annotations

import re                                                    # CHANGE: new import
from dataclasses import dataclass, field

from loguru import logger

from mallens.config import Config
from mallens.core.datatypes import Stage2Result, Stage3Result
from mallens.llm.analyze import Stage4Result

# CHANGE: action-evidence gate (module-level; move patterns to config later)
# ACTION_PAT = re.compile(
#     r"sms|premium|exfil|c2|command.and.control|dynamic.*(load|dex|code)|"
#     r"dexclassloader|shell|su\b|root(ing|.detect)?|keylog|overlay|"
#     r"accessibility|record|screenshot|clipboard|"
#     r"boot.*(receiver|persist|start)|hide.*icon|abort.*broadcast|"
#     r"install.*(apk|package)|device.admin|encrypt.*(file|storage)|ransom|"
#     r"proxy.*(permission|context|bypass)|permission.bypass", re.I)

ACTION_PAT = re.compile(
    r"sms|premium|exfil|c2|command.and.control|dynamic.*(load|dex|code)|"
    r"dexclassloader|shell|su\b|root(ing|.detect)?|keylog|overlay|"
    r"accessibility|record|screenshot|clipboard|"
    r"download.*(apk|dex|payload|execut)|execut.*(apk|payload|download)|"
    r"install.*(apk|package)|drops?.*(apk|payload)|"
    r"socks|tunnel|port.forward|proxy.*(implement|tunnel|permission|context|bypass)|"
    r"boot.*(receiver|persist|start)|hide.*icon|abort.*broadcast|"
    r"device.admin|encrypt.*(file|storage)|ransom|permission.bypass", re.I)

# Deny-list backstop: targets the ONE diagnosed failure mode (naming-echo).
# Deliberately narrow; do not grow this into a signature engine.
NAMING_PAT = re.compile(r"framework.style|masquerad|spoof|class.nam", re.I)

def _actions(v) -> list:
    return [b for b in v.behaviors
            if b.kind == "action" and not NAMING_PAT.search(b.description)]


SDK_HOSTS = ("startapp", "appodeal", "revmob", "firebase", "play.goo",
             "unity3d", "applovin", "mopub", "admob", "crashlytics",
             "flurry", "adjust", "appsflyer", "vungle", "chartboost")


# def _has_action(v) -> bool:                                  # CHANGE: new
#     return any(ACTION_PAT.search(b) for b in v.behaviors)


def _evidence_classes(v) -> int:                             # CHANGE: new
    return len({e.class_name for e in v.evidence})


def _passes_gate(v, r) -> bool:
    sig = [b for b in v.behaviors
           if b.kind in ("action", "capability")
           and not NAMING_PAT.search(b.description)]
    if not sig or len(v.evidence) < 2:
        return False
    if v.verdict == "malicious":
        return bool(_actions(v))          # malicious needs a real action
    return _evidence_classes(v) >= r.min_evidence_classes

# def _passes_gate(v, r) -> bool:
#     if not _has_action(v):
#         return False
#     if len(v.evidence) < 2:                      # always need &gt;=2 quotes
#         return False
#     if v.verdict == "malicious":
#         return True                              # god-class allowed
#     return _evidence_classes(v) >= r.min_evidence_classes  # suspicious needs spread


@dataclass
class ApkVerdict:
    verdict: str
    confidence: float
    rules_fired: list[str] = field(default_factory=list)
    behaviors: list[str] = field(default_factory=list)
    network_indicators: list[str] = field(default_factory=list)
    family_hints: list[str] = field(default_factory=list)
    malicious_classes: list[str] = field(default_factory=list)
    unanalyzed_important: list[str] = field(default_factory=list)
    gated_out: list[int] = field(default_factory=list)       # CHANGE: audit field


def _norm_indicator(ind: str) -> str:
    ind = ind.lower().strip()
    for pre in ("https://", "http://", "ftp://", "ssh://"):
        ind = ind.removeprefix(pre)
    return ind.split("/")[0].split(":")[0]


def aggregate(s2: Stage2Result, s3: Stage3Result, s4: Stage4Result,
              cfg: Config) -> ApkVerdict:
    r = cfg.report
    fired: list[str] = []
    clusters = {c.cluster_id: c for c in s3.clusters}

    flagged = {cid: v for cid, v in s4.verdicts.items()
               if v.verdict in ("malicious", "suspicious")}

    # CHANGE: evidence gate — naming-only or thin-evidence clusters cannot vote
    # gated = {cid: v for cid, v in flagged.items() if _has_action(v) and _evidence_classes(v) >= r.min_evidence_classes}
    gated = {cid: v for cid, v in flagged.items() if _passes_gate(v, r)}

    gated_out = sorted(set(flagged) - set(gated))
    if gated_out:
        fired.append(f"gate: clusters {gated_out} flagged but excluded "
                     f"(no action-evidence or evidence in "
                     f"< {r.min_evidence_classes} classes)")

    # CHANGE: hard_mal / soft now drawn from `gated`, not `flagged`
    hard_mal = [cid for cid, v in gated.items()
                if v.verdict == "malicious" and v.confidence >= r.t_malicious_conf]
    soft = [cid for cid, v in gated.items()
            if v.confidence >= r.t_suspicious_conf]

    # --- corroboration among soft hits ------------------------------------
    corroborated = False
    if len(soft) >= 2:
        host_owners: dict[str, set[int]] = {}
        for cid in soft:
            for ind in s4.verdicts[cid].network_indicators:
                h = _norm_indicator(ind)
                # CHANGE: SDK/ad-network hosts don't corroborate
                if not h or any(s in h for s in SDK_HOSTS):
                    continue
                host_owners.setdefault(h, set()).add(cid)
        shared = {h: o for h, o in host_owners.items() if len(o) >= 2}
        if shared:
            corroborated = True
            fired.append(f"corroboration: clusters share non-SDK hosts "
                         f"{sorted(shared)}")

        # CHANGE: spoofed-framework corroboration rule DELETED entirely
        # (the whole spoof_idx / spoofed_clusters block is gone)

    # --- honesty guard (unchanged) -----------------------------------------
    unseen = [c for c in s3.clusters
              if c.cluster_id not in s4.verdicts
              and c.cluster_id not in s4.errors
              and c.importance >= r.t_unseen_importance]
    unseen_names = [c.seed_class for c in unseen]

    # --- decide (structure unchanged; inputs are now gated) -----------------
    if hard_mal:
        verdict = "malicious"
        fired.append(f"rule: cluster(s) {hard_mal} malicious with action "
                     f"evidence, conf >= {r.t_malicious_conf}")
        confidence = max(s4.verdicts[c].confidence for c in hard_mal)
    elif corroborated:
        verdict = "malicious"
        confidence = min(0.9, max(s4.verdicts[c].confidence for c in soft))
    elif gated:                                              # CHANGE: was `flagged`
        verdict = "suspicious"
        fired.append(f"rule: gated clusters {sorted(gated)} below "
                     "malicious threshold / uncorroborated")
        confidence = max(v.confidence for v in gated.values())
    elif s4.errors or unseen:
        verdict = "inconclusive"
        if s4.errors:
            fired.append(f"rule: {len(s4.errors)} cluster analyses failed")
        if unseen:
            fired.append(f"rule: high-importance clusters not analyzed: "
                         f"{unseen_names}")
        confidence = 0.0
    else:
        verdict = "benign"
        fired.append("rule: no cluster passed the action-evidence gate, "
                     "no important cluster unanalyzed")
        confidence = min((v.confidence for v in s4.verdicts.values()
                          if v.verdict == "benign"), default=0.5)

    # CHANGE: localization/behaviors/IOCs from `gated` only — otherwise a
    # naming-only cluster still pollutes malicious_classes and your
    # localization-precision metric
    mal_classes = sorted({m for cid in gated
                          for m in clusters[cid].class_names})
    out = ApkVerdict(
        verdict=verdict, confidence=round(confidence, 2), rules_fired=fired,
        # behaviors=sorted({b for v in gated.values() for b in v.behaviors}),
        # Changed to this
        behaviors = sorted({f"[{b.kind}] {b.description}" for v in gated.values() for b in v.behaviors}),
        network_indicators=sorted({i for v in gated.values()
                                   for i in v.network_indicators}),
        family_hints=sorted({v.family_hint for v in gated.values()
                             if v.family_hint}),
        malicious_classes=mal_classes,
        unanalyzed_important=unseen_names,
        gated_out=gated_out,
    )
    logger.info(f"stage5: {verdict} ({confidence:.2f}), "
                f"{len(mal_classes)} classes localized, "
                f"{len(gated_out)} clusters gated out, rules={fired}")
    return out
