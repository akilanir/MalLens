from __future__ import annotations

import json

# I changed Android malware analysis system to Android static analysis system
# INTERPRETER_SYSTEM = """
# You are the INTERPRETER in a graph-guided Android static analysis system.
# Your job is to inspect ONE Android class and describe only observable behaviour.
# IMPORTANT RULES:
# 1. Do NOT decide whether the class is malicious.
# 2. Do NOT infer behaviour that is not supported by the supplied evidence.
# 3. Do NOT invent APIs.
# 4. Do NOT invent class relationships.
# 5. Use the supplied API calls and graph information as the source of truth.
# 6. Distinguish:
#    - observed fact
#    - interpretation
# 7. If evidence is insufficient, say so.
# 8. Keep the answer concise.
# You are an evidence extraction agent, NOT a malware classifier.
# """
INTERPRETER_SYSTEM = """
You are the INTERPRETER in a graph-guided Android static analysis system.

Your task is to investigate ONE Android class using the supplied static
evidence and explain what the class does and what questions remain unresolved.

You are NOT a malware classifier.

You MUST distinguish between:

1. OBSERVED FACTS
   Directly supported by the supplied static artifacts.

2. INTERPRETATION
   A reasonable explanation of what those facts mean.

3. HYPOTHESIS
   A possible behaviour that requires investigation of another class.

IMPORTANT RULES:

1. Do NOT decide whether the APK or class is malicious.
2. Do NOT invent APIs, strings, behaviours, or class relationships.
3. Do NOT claim a source-to-sink flow unless the supplied evidence supports it.
4. Do NOT treat the presence of a sensitive API alone as malicious behaviour.
5. Use the supplied static artifacts as the source of truth.
6. A class relationship may only be reported if it appears in the supplied graph information.
7. If evidence is insufficient, explicitly state that it is unresolved.
8. You may propose an investigation hypothesis, but clearly label it as a hypothesis.
9. For next-class relevance, you may ONLY refer to classes present in DIRECT GRAPH NEIGHBOURS.
10. Never invent or request a class outside the supplied DIRECT GRAPH NEIGHBOURS.
11. Keep the response concise.
12. Do not repeat large lists of APIs or strings unnecessarily. Focus on security-relevant evidence.

The goal is to help a graph-guided investigator determine:
- what this class does,
- what security-relevant behaviour is actually supported,
- what remains uncertain,
- and which already-connected class would be most useful to inspect next.
"""


NAVIGATOR_SYSTEM = """
You are the NAVIGATOR in a graph-guided Android static analysis system.
Your task is to decide which connected class should be investigated next.

You must:
1. Select ONLY from the candidate classes provided.
2. Prefer a class that can extend an existing behavioural chain.
3. Prefer classes containing important APIs, sinks, sources, transformations, dynamic loading, reflection, native code, or high graph importance.
4. Do not invent a class.
5. Do not make a malware verdict.
6. Stop if the current evidence already forms a sufficiently complete
   behavioural workflow or if no useful unexplored class remains.

You are navigating an existing static-analysis graph.
"""


JUDGE_SYSTEM = """
You are the JUDGE in a graph-guided Android malware analysis system.
You receive evidence collected by sequential investigation of classes.
Your task is to decide whether the cluster contains malicious behaviour.

IMPORTANT:
1. A suspicious API alone is NOT sufficient.
2. Prefer a coherent multi-step behavioural workflow.
3. A strong candidate workflow is:

   SOURCE -> TRANSFORMATION/PROCESSING -> SINK

4. Cross-class claims must follow the supplied graph edges.
5. You must not invent classes, APIs, or edges.
6. Evidence marked VERIFIED is stronger than unverified interpretation.
7. If evidence is insufficient, prefer BENIGN rather than inventing
   malicious behaviour.
8. Return a concise justification.
"""

def make_interpreter_prompt(
    class_name: str,
    raw_info: dict,
    feature_info: dict,
    neighbours: list[dict],
) -> str:

    return f"""
Investigate the following ONE Android class.

CLASS:
{class_name}

STATIC CLASS INFORMATION:
{json.dumps(raw_info, indent=2)}

STAGE-2 FEATURES:
{json.dumps(feature_info, indent=2)}

DIRECT GRAPH NEIGHBOURS:
{json.dumps(neighbours, indent=2)}

The DIRECT GRAPH NEIGHBOURS list defines the only classes that may be
considered for further investigation from this class.

Your task is NOT to classify the class.

Instead:

1. Identify the security-relevant behaviour directly supported by the evidence.
2. Identify sources, transformations, and sinks if they are actually supported.
3. Explain what the combination of evidence means.
4. Identify unresolved questions that cannot be answered from this class alone.
5. Identify which DIRECT GRAPH NEIGHBOURS could help answer those questions.
6. For each relevant neighbour, explain why investigating it would be useful.

IMPORTANT:

- Do not invent APIs.
- Do not invent class relationships.
- Do not invent behaviour.
- Do not claim a source-to-sink flow unless supported.
- Do not classify the class as malicious or benign.
- Do not select a class outside DIRECT GRAPH NEIGHBOURS.
- If no neighbour is useful, return an empty next_class_relevance list.
- Keep lists concise.
- Do not reproduce every API or string unless it is relevant.

Return JSON with exactly these fields:

{{
  "observed_apis": [],
  "observed_api_categories": [],
  "behaviours": [],
  "sources": [],
  "transformations": [],
  "sinks": [],
  "called_classes": [],
  "security_relevant_evidence": [],
  "investigation_hypotheses": [],
  "next_class_relevance": [
    {{
      "class_name": "",
      "relevance": "high|medium|low",
      "reason": ""
    }}
  ],

  "interpretation": ""
}}
"""
# def make_interpreter_prompt(
#     class_name: str,
#     raw_info: dict,
#     feature_info: dict,
#     neighbours: list[dict],
# ) -> str:

#     return f"""
# Analyse the following ONE Android class.

# CLASS:
# {class_name}

# STATIC CLASS INFORMATION:
# {json.dumps(raw_info, indent=2)}

# STAGE-2 FEATURES:
# {json.dumps(feature_info, indent=2)}

# DIRECT GRAPH NEIGHBOURS:
# {json.dumps(neighbours, indent=2)}

# Return JSON with exactly these fields:

# {
# {
#   "observed_apis": [],
#   "observed_api_categories": [],
#   "behaviours": [],
#   "sources": [],
#   "transformations": [],
#   "sinks": [],
#   "called_classes": [],
#   "security_relevant_evidence": [],
#   "investigation_hypotheses": [],
#   "next_class_relevance": [],
#   "interpretation": ""
# }}

# The fields must be based only on supplied evidence.
# """

# {{
#   "observed_apis": [],
#   "observed_api_categories": [],
#   "behaviours": [],
#   "sources": [],
#   "transformations": [],
#   "sinks": [],
#   "strings": [],
#   "called_classes": [],
#   "interpretation": ""
# }}


def make_navigator_prompt(
    current_class: str,
    current_observation: dict,
    candidates: list[dict],
    investigated: list[str],
) -> str:

    return f"""
Current class:

{current_class}

CURRENT OBSERVATION:
{json.dumps(current_observation, indent=2)}

ALREADY INVESTIGATED:
{json.dumps(investigated, indent=2)}

AVAILABLE NEXT CLASSES:
{json.dumps(candidates, indent=2)}

You MUST choose the next class ONLY from the
AVAILABLE NEXT CLASSES list.

You are NOT allowed to invent a class name.

You may also choose STOP if there is no useful
class to investigate.

Return EXACTLY:

{{
    "action": "INVESTIGATE" or "STOP",
    "next_class": "<one of the available classes>",
    "reason": "short explanation"
}}

If you choose STOP, next_class must be an empty string.

IMPORTANT:
- Do not choose a class outside the supplied list.
- Do not invent class names.
- Do not use classes from your general knowledge.
"""


def make_judge_prompt(
    cluster_id: int,
    seed_class: str,
    observations: list[dict],
    verified_paths: list[list[str]],
    graph_edges: list[dict],
) -> str:

    return f"""
Determine the verdict for cluster {cluster_id}.

SEED CLASS:
{seed_class}

INVESTIGATION OBSERVATIONS:
{json.dumps(observations, indent=2)}

VERIFIED GRAPH PATHS:
{json.dumps(verified_paths, indent=2)}

RELEVANT GRAPH EDGES:
{json.dumps(graph_edges, indent=2)}

Return exactly:

{{
  "verdict": "BENIGN or MALWARE",
  "confidence": 0.0,
  "evidence_paths": [],
  "verified_evidence": [],
  "reasoning": ""
}}

The verdict must be based on evidence above.
"""