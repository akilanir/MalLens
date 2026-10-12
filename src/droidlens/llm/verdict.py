from __future__ import annotations

import json
import re
from typing import Literal

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    class_name: str
    quote: str = Field(description="verbatim code or string from the source")
    reason: str

class Behavior(BaseModel):
    kind: Literal["action", "capability", "observation"]
    description: str

class ClusterVerdict(BaseModel):
    benign_explanation_considered: str   # most plausible legit explanation
    why_benign_explanation_rejected: str # "" if verdict is benign
    verdict: Literal["malicious", "suspicious", "benign", "inconclusive"]
    confidence: float = Field(ge=0.0, le=1.0)
    behaviors: list[Behavior]
    evidence: list[Evidence] = Field(default_factory=list)
    network_indicators: list[str] = Field(default_factory=list)
    family_hint: str | None = None
    summary: str = ""

# Removed
# behaviors: list[str] = Field(default_factory=list,description="e.g. 'sms_exfiltration', 'c2_beacon'")
# Added
# behaviors: list[Behavior]

#We included this two responses to reduce teh FP
# "benign_explanation_considered: str   # most plausible legit explanation
# "why_benign_explanation_rejected: str # "" if verdict is benign"

def parse_verdict(text: str) -> ClusterVerdict:
    """Tolerant: extracts the first JSON object from markdown fences or prose."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object in LLM output")
    return ClusterVerdict.model_validate(json.loads(m.group(0)))


def parse_verdict_fallback(text: str) -> ClusterVerdict:
    text = text.strip()
    # 1. Try the entire response directly
    try:
        return ClusterVerdict.model_validate_json(text)
    except Exception:
        pass

    # 2. Remove markdown code fences if present
    cleaned = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE)
    cleaned = cleaned.replace("```", "").strip()

    try:
        return ClusterVerdict.model_validate_json(cleaned)
    except Exception:
        pass

    # 3. Find the first balanced JSON object
    start = cleaned.find("{")
    if start == -1:
        raise ValueError("No JSON object found in LLM output")

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(cleaned)):
        ch = cleaned[i]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1

            if depth == 0:
                candidate = cleaned[start:i + 1]

                try:
                    obj = json.loads(candidate)
                    return ClusterVerdict.model_validate(obj)
                except (json.JSONDecodeError, Exception):
                    break
    # 4. Last fallback: try extracting JSON with a greedy regex
    m = re.search(r"\{.*\}", cleaned, re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            return ClusterVerdict.model_validate(obj)
        except Exception:
            pass

    raise ValueError("Could not parse JSON from LLM output")