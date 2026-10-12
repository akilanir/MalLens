import json, re
from droidlens.core.datatypes import CandidatePath, PathVerdict, ClassFactSheet

ADJ_SYSTEM = """You are an expert Android code reviewer. You receive ONE data-flow
path found by static analysis in a decompiled app: a chain of classes where
data from a SOURCE reaches a SINK, possibly transformed along the way. Every
fact shown was verified against the source code; the call edges exist.

Your only task: decide whether THIS flow is consistent with a legitimate
purpose (advertising SDK, analytics, crash reporting, push notifications,
backup/sync, plugin framework, etc.) or exceeds any legitimate purpose.

Rules:
- Judge only this path. Do not speculate about code you were not shown.
- Fingerprinting/telemetry flows to advertising or analytics endpoints are
  legitimate by default. A flow exceeds legitimate purpose only if the shown
  facts demonstrate it: e.g. SMS content leaving the device, premium SMS
  sending, executing downloaded code, shell commands on user data, data sent
  to endpoints hidden by string assembly or encryption without SDK context.
- If the sink endpoint is "unresolved" or a hop depends on unresolved
  reflection/native code, you may still judge the flow, but say so in
  "reading" and lower confidence.
- exceeds_legitimate_purpose=true REQUIRES a non-empty "why" citing the
  specific facts (by class and type) that no legitimate SDK would exhibit.

Respond with ONLY this JSON object, no markdown:
{
  "reading": "2-3 sentences: what this flow does, mechanically",
  "legitimate_explanation": "most plausible legitimate purpose for this flow",
  "exceeds_legitimate_purpose": true|false,
  "why": "REQUIRED if true: which facts exceed the legitimate purpose. Empty string otherwise.",
  "confidence": 0.0-1.0
}"""

def render_path(path: CandidatePath, sheets: dict[str, ClassFactSheet],
                perm_lines: str, alias: bool) -> str:
    amap = {n: (f"C{i+1}" if alias else n) for i, n in enumerate(path.nodes)}
    blocks = []
    for n in path.nodes:
        fs, a = sheets[n], amap[n]
        b = [f"{a}: {fs.functional_summary}"]
        for lbl, entries in (("source", fs.sources), ("sink", fs.sinks),
                             ("transform", fs.transforms), ("trigger", fs.triggers)):
            for e in entries:
                ep = f", endpoint={e.endpoint}" if getattr(e, "endpoint", "") else ""
                b.append(f'  {lbl}: {e.type}{ep} -- "{e.quote[:160]}"')
        if fs.unresolved:
            b.append(f"  unresolved: {'; '.join(fs.unresolved[:5])}")
        blocks.append("\n".join(b))
    chain = " -> ".join(f"{amap[a]}--({w} calls)->{amap[b]}"
                        for a, b, w in path.edges) or f"{amap[path.nodes[0]]} (single class)"
    return (f"FLOW: {path.source_type} -> "
            f"{'transform -> ' if path.has_transform else ''}{path.sink_type}"
            f" (trigger: {path.trigger_type})\n\nCALL CHAIN: {chain}\n\n"
            f"CLASS FACTS:\n" + "\n\n".join(blocks)
            + f"\n\nRELEVANT PERMISSIONS:\n{perm_lines}")

def adjudicate_path(path, sheets, perm_lines, client, cfg) -> PathVerdict:
    user = render_path(path, sheets, perm_lines, cfg.factpaths.alias_names)
    text, _ = client.complete(ADJ_SYSTEM, user)
    try:
        d = json.loads(re.search(r"\{.*\}", text, re.S).group(0))
    except Exception:
        return PathVerdict(path_id=path.path_id, verified=False,
                           reading="PARSE_ERROR")
    v = PathVerdict(
        path_id=path.path_id,
        reading=str(d.get("reading", ""))[:500],
        legitimate_explanation=str(d.get("legitimate_explanation", ""))[:300],
        exceeds_legitimate_purpose=bool(d.get("exceeds_legitimate_purpose", False)),
        why=str(d.get("why", ""))[:500],
        confidence=float(d.get("confidence", 0.0)),
    )
    # verifier: hostile requires substantive why; facts were pre-verified in 4a,
    # edges in 4b, so the only thing left to check is the justification.
    v.verified = (not v.exceeds_legitimate_purpose) or len(v.why.strip()) >= 20
    if not v.verified:
        v.exceeds_legitimate_purpose = False   # downgrade, never upgrade
    return v
