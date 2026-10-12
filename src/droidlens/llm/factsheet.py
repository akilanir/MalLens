import json, re
from loguru import logger
from droidlens.core.datatypes import ClassFactSheet, FactEntry
from droidlens.llm.fscache import FactSheetCache, src_hash

FS_PROMPT_VERSION = "fs_v1"   # keep in sync with cfg; asserted in orchestrator

# Here we hard code the sources,sinks,transformers,and triggers : is this valid???
SOURCES = ["DEVICE_ID", "LOCATION", "CONTACTS", "SMS_CONTENT", "CALL_LOG",
           "ACCOUNTS", "INSTALLED_APPS", "CAMERA_MIC", "CLIPBOARD",
           "FILE_READ", "USER_INPUT", "OTHER"]
SINKS = ["NETWORK_SEND", "SMS_SEND", "FILE_WRITE", "DEX_LOAD", "SHELL_EXEC",
         "REFLECTION_CALL", "CONTENT_PROVIDER_WRITE", "IPC_SEND", "OTHER"]
TRANSFORMS = ["ENCRYPT", "DECRYPT", "BASE64", "COMPRESS", "STRING_ASSEMBLY", "HASH", "OTHER"]
TRIGGERS = ["EXPORTED_COMPONENT", "BOOT", "SMS_RECEIVED", "ALARM", "PUSH",
            "UI", "OTHER", "NONE"]

FACTSHEET_SYSTEM = f"""You are a static-code documentation tool. You receive ONE
Java class decompiled from an Android app. Extract facts. Do NOT judge whether
the code is malicious or benign; that is not your task and no such field exists.

Rules:
- Every entry in sources/sinks/transforms/triggers MUST include "quote": a
  fragment copied character-for-character from the provided source. Output is
  machine-verified; entries whose quote is not found verbatim are discarded.
- "type" MUST be exactly one value from the allowed list for that field.
  If a behavior fits no listed value, put it in "unresolved" instead.
- Allowed sources: {", ".join(SOURCES)}
- Allowed sinks: {", ".join(SINKS)}
- Allowed transforms: {", ".join(TRANSFORMS)}
- Allowed triggers: {", ".join(TRIGGERS)}
- "endpoint" (sinks only): the literal URL/number/path if it appears in the
  code; otherwise a short description of the expression that produces it;
  otherwise "unresolved".
- "unresolved": list reflection targets, native method calls, and dynamically
  loaded code whose behavior cannot be determined from this source.
- If a field has no entries, output an empty list [].

Respond with ONLY this JSON object, no markdown, no extra text:
{{
  "functional_summary": "1-2 sentences, purely descriptive",
  "sources":    [{{"type": "", "quote": "", "method": ""}}],
  "sinks":      [{{"type": "", "quote": "", "method": "", "endpoint": ""}}],
  "transforms": [{{"type": "", "quote": ""}}],
  "triggers":   [{{"type": "", "quote": ""}}],
  "notable_strings": [],
  "unresolved": []
}}"""

USER_TEMPLATE = "Class: {cname}\n\n```java\n{source}\n```"

_ENUMS = {"sources": set(SOURCES), "sinks": set(SINKS),
          "transforms": set(TRANSFORMS), "triggers": set(TRIGGERS)}

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()

# stage-2 cross-check: LLM claim -> stage-2 feature that must be nonzero.
# Align keys with your sensitive_apis.csv categories. Only categories present
# here are enforced; direction is one-way (we drop LLM claims stage-2 denies,
# we never add claims stage-2 makes).
XCHECK = {
    "SMS_SEND":  ["cat_SMS"],
    "DEX_LOAD":  ["cat_DYNAMIC_LOADING"],
    "SHELL_EXEC": ["cat_PROCESS", "str_shell"],
    "LOCATION":  ["cat_LOCATION"],
    "CONTACTS":  ["cat_CONTACTS"],
    "DEVICE_ID": ["cat_TELEPHONY", "cat_DEVICE_ID"],
}


def feats_dict(record) -> dict[str, float] | None:
    """Flatten a ClassFeatureRecord into the lookup dict XCHECK uses."""
    if record is None:
        return None
    d = dict(zip(record.vector.feature_names, record.vector.values))
    # api_categories under a stable prefix so XCHECK keys are unambiguous
    for cat, count in record.api_categories.items():
        d[f"cat_{cat}"] = float(count)
    return d


def verify_sheet(fs: ClassFactSheet, source: str,
                 feats: dict | None, min_quote: int) -> ClassFactSheet:
    hay = _norm(source)
    for field_name, allowed in _ENUMS.items():
        kept = []
        for e in getattr(fs, field_name):
            if e.type not in allowed:
                fs.dropped.append(f"{field_name}:{e.type}:bad-enum"); continue
            if len(e.quote) < min_quote or _norm(e.quote) not in hay:
                fs.dropped.append(f"{field_name}:{e.type}:quote-not-found"); continue
            req = XCHECK.get(e.type)
            if req and feats is not None and not any(feats.get(k, 0) > 0 for k in req):
                fs.dropped.append(f"{field_name}:{e.type}:stage2-denies"); continue
            # endpoint literal must actually appear in source
            if e.endpoint and e.endpoint.startswith(("http", "www")) \
                    and e.endpoint.lower() not in hay:
                e.endpoint = "unresolved"
                fs.dropped.append(f"sinks:{e.type}:endpoint-not-in-source")
            kept.append(e)
        setattr(fs, field_name, kept)
    fs.notable_strings = [s for s in fs.notable_strings if s.lower() in hay]
    return fs

def _chunks(source: str, budget: int) -> list[str]:
    if len(source) <= budget:
        return [source]
    # split at method-ish boundaries; fall back to hard cut
    parts, cur = [], []
    for line in source.splitlines(keepends=True):
        cur.append(line)
        if sum(map(len, cur)) >= budget and re.match(r"^\s{4}(public|private|protected|static|})", line):
            parts.append("".join(cur)); cur = []
    if cur:
        parts.append("".join(cur))
    return parts

def _merge(sheets: list[ClassFactSheet]) -> ClassFactSheet:
    base = sheets[0]
    for s in sheets[1:]:
        for f in ("sources", "sinks", "transforms", "triggers"):
            seen = {(e.type, _norm(e.quote)) for e in getattr(base, f)}
            getattr(base, f).extend(e for e in getattr(s, f)
                                    if (e.type, _norm(e.quote)) not in seen)
        base.notable_strings = list(dict.fromkeys(base.notable_strings + s.notable_strings))
        base.unresolved = list(dict.fromkeys(base.unresolved + s.unresolved))
        base.dropped += s.dropped
    return base

def build_factsheet(cname: str, source: str, feats: dict | None,
                    client, fscache: FactSheetCache, cfg) -> ClassFactSheet:
    h = src_hash(source)
    cached = fscache.get(h)
    if cached:
        cached.class_name = cname          # local name may differ; bytes don't
        return cached

    sheets = []
    for chunk in _chunks(source, cfg.factsheet.char_budget):
        user = USER_TEMPLATE.format(cname=cname, source=chunk)
        try:
            text, _ = client.complete(FACTSHEET_SYSTEM, user)
            d = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
            
        except Exception as exc:
            logger.warning(f"factsheet {cname}: {exc}")
            sheets.append(ClassFactSheet(cname, h, FS_PROMPT_VERSION,
                                         status="llm_error"))
            continue
        fs = ClassFactSheet(
            class_name=cname, src_hash=h, prompt_version=FS_PROMPT_VERSION,
            functional_summary=str(d.get("functional_summary", ""))[:300],
            sources=[FactEntry(**{k: e.get(k, "") for k in ("type", "quote", "method")})
                     for e in d.get("sources", []) if isinstance(e, dict)],
            sinks=[FactEntry(**{k: e.get(k, "") for k in ("type", "quote", "method", "endpoint")})
                   for e in d.get("sinks", []) if isinstance(e, dict)],
            transforms=[FactEntry(type=e.get("type", ""), quote=e.get("quote", ""))
                        for e in d.get("transforms", []) if isinstance(e, dict)],
            triggers=[FactEntry(type=e.get("type", ""), quote=e.get("quote", ""))
                      for e in d.get("triggers", []) if isinstance(e, dict)],
            notable_strings=[str(s) for s in d.get("notable_strings", [])][:20],
            unresolved=[str(s) for s in d.get("unresolved", [])][:20],
        )
        sheets.append(verify_sheet(fs, chunk, feats, cfg.factsheet.min_quote_len))

    merged = _merge(sheets)
    if merged.status == "ok":
        fscache.put(merged)
    return merged
