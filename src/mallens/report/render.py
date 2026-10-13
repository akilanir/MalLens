from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path


from mallens.core.datatypes import Stage1Result, Stage3Result
from mallens.llm.analyze import Stage4Result
from mallens.report.aggregate import ApkVerdict


def render(s1: Stage1Result, s3: Stage3Result, s4: Stage4Result,
           apk_verdict: ApkVerdict, out_dir: str) -> tuple[Path, Path]:
    out = Path(out_dir) / s1.apk.sha256[:16]
    out.mkdir(parents=True, exist_ok=True)

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "apk": {"sha256": s1.apk.sha256, "package": s1.apk.package_name},
        "pipeline": {"scorer": s3.scorer_name, "model": s4.model,
                     "llm_usage": s4.usage},
        "verdict": asdict(apk_verdict),
        "clusters": [
            {"cluster_id": c.cluster_id, "seed": c.seed_class,
             "importance": c.importance, "classes": c.class_names,
             "llm": (s4.verdicts[c.cluster_id].model_dump()
                     if c.cluster_id in s4.verdicts else None),
             "error": s4.errors.get(c.cluster_id)}
            for c in s3.clusters],
    }
    json_path = out / "report.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    md = [f"# DroidLens report — `{s1.apk.package_name}`",
          f"`{s1.apk.sha256}`", "",
          f"## Verdict: **{apk_verdict.verdict.upper()}** "
          f"(confidence {apk_verdict.confidence})", ""]
    md += [f"- {r}" for r in apk_verdict.rules_fired]
    if apk_verdict.behaviors:
        md += ["", "**Behaviors:** " + ", ".join(apk_verdict.behaviors)]
        # md += [f"- **{b.kind}**: {b.description}" for b in v.behaviors]
    if apk_verdict.family_hints:
        md += ["**Family hints:** " + ", ".join(apk_verdict.family_hints)]
    if apk_verdict.network_indicators:
        md += ["", "## Network indicators (IOCs)"]
        md += [f"- `{i}`" for i in apk_verdict.network_indicators]
    if apk_verdict.malicious_classes:
        md += ["", f"## Localized classes ({len(apk_verdict.malicious_classes)})"]
        md += [f"- `{c}`" for c in apk_verdict.malicious_classes]
    if apk_verdict.gated_out:
        md += ["", f"*Clusters flagged by LLM but gated out " f"(no action evidence): {apk_verdict.gated_out}*"]

    md += ["", "## Cluster detail"]
    for c in s3.clusters:
        v = s4.verdicts.get(c.cluster_id)
        if v is None:
            continue
        md += [f"", f"### Cluster {c.cluster_id} — {v.verdict} "
               f"({v.confidence:.2f}) — seed `{c.seed_class}`",
               v.summary]
        # in the "## Cluster detail" loop, after the summary line: (NEW LINE)
        if v.verdict == "malicious" and getattr(v, "benign_explanation_considered", ""):
            md += [f"> Benign explanation considered: " f"{v.benign_explanation_considered}", f"> Rejected because: {v.why_benign_explanation_rejected}"]
        for e in v.evidence:
            md += [f"- `{e.class_name}`: \"{e.quote}\" — {e.reason}"]
    md_path = out / "report.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    return json_path, md_path
