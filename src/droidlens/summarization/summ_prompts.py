# SYSTEM_PROMPT = (
#     "You are a malware analyst assistant. Your job is to summarise suspicious behaviour "
#     "found in a single Java class. You MUST respond with ONLY a JSON object containing:\n"
#     "- \"summary\": one concise sentence describing what the class does (e.g., \"Sends SMS to "
#     "premium numbers, hides icon, and downloads a payload\").\n"
#     "- \"evidence\": an array of EXACT copy-pasted code snippets that support the summary. "
#     "Each snippet must be a substring taken VERBATIM from the provided code. Do NOT alter, "
#     "abbreviate, or rewrite the snippets. Include as many snippets as needed to cover each "
#     "suspicious behaviour.\n\n"
#     "Do NOT add any text outside the JSON. The output must be parseable by json.loads()."
# )

import json
# def build_user_prompt(class_name: str, source: str, static_facts: dict, max_source_chars: int = 4000) -> str:
#     # static_facts is a dict of facts about the class from s2.records (if any)
#     facts_text = json.dumps(static_facts, indent=2) if static_facts else "No precomputed facts available."
#     src_snippet = source[:max_source_chars]  # truncate for small model
#     return f"""Class: {class_name}
#     Precomputed static analysis facts:
#     {facts_text}

#     Source code (first {max_source_chars} characters): java {src_snippet}
#     Carefully examine the code. Identify suspicious behaviours such as accessing sensitive APIs, reflection, dynamic code loading, crypto misuse, hiding icons, sending SMS, etc. Only base your claims on code that is actually present. IMPORTANT: If the behavior is not suspicious or seems like legitimate Android Library class just reply with the summary and for evidence add "library"
#     Respond with the JSON as specified."""


SYSTEM_PROMPT = """
You are an Android code analysis assistant. You have given a one Class from a cluster of classes

Analyze this ONE Java class and produce a concise, factual summary of the behaviour implemented in that class.

Your task is NOT to determine whether the class is malicious or benign. Do not label behaviour as suspicious or malicious. Simply describe what the code actually does and how it will flow important data/erquests to other classes.

Rules:
1. Summarize the important observable behaviour of the class in a few concise sentences.
2. Every behaviour mentioned in the summary MUST be directly supported by the provided source code.
3. For each important behaviour, provide one or more EXACT line/s copied verbatim from the source code that demonstrate it.
4. Evidence must be an exact substring of the provided source. Do not rewrite, paraphrase, shorten, modify, aor add any fillups to code.
5. Do not infer behaviour that is not demonstrated by the provided code.
6. Reflection, encryption, networking, device identifiers, dynamic loading, obfuscation, and SDK functionality should be described factually without assuming malicious intent.
7. If the behaviour flows from the analysis class to outside mention that as well. It will help overall analysis when everything togehter.
8. If the class contains no meaningful behaviour that can be established from the provided source, return an "no_summary" as summary and "no_evidence" as evidence.

IMPORTANT: 
- Each EVIDENCE must be separated by a line containing exactly:
---
- Do not write anything before SUMMARY or after the EVIDENCE.

RETURN ONLY:
SUMMARY:
Write concise sentences describing the important behaviour of the class.

EVIDENCE:
Provide exact verbatim code line/s copied directly from the source code that support the summary.
"""


# {
#   "summary": "Concise factual description of what this class does.",
#   "evidence": [
#     "EXACT verbatim source code line as exactly as input code.",
#     "EXACT verbatim source code line as exactly as input code."
#   ]
# }
# Return ONLY valid JSON:


def build_user_prompt(
    class_name: str,
    source: str,
    static_facts: dict,
    max_source_chars: int = 6000
) -> str:

    facts_text = (
        json.dumps(static_facts, indent=2)
        if static_facts
        else "No precomputed facts available."
    )

    src = source[:max_source_chars]

    return f"""Class: {class_name} 
    Static analysis facts: {facts_text}
    Source code:
    ```java
    {src}"""


##### ----------------------------------------------------------- CLUSTER SUMMARY PROMPTS
CLUSTER_PROFILE_SYSTEM = """
You are a reverse-engineering assistant. Given the complete source code of a cluster
of related classes and their call graph, extract ONLY objective, factual information.
DO NOT classify as malicious, suspicious, or benign.
DO NOT invent any code, APIs, or behaviours.

Your output must be a single JSON object with the following keys:

{
  "cluster_id": "<any identifier you receive>",
  "classes": ["list of class names"],
  "api_flows": [
    {
      "description": "what happens (e.g., ClassLoader loads a dex and then sends HTTP)",
      "steps": ["call sequence, e.g., A.onCreate() → A.loadDex() → B.invoke() → C.sendRequest()"],
      "sensitive_apis": ["apis involved"],
      "data_involved": ["data items, e.g., device IMEI, URL"]
    }
  ],
  "data_flows": [
    {
      "source": "where the data comes from (e.g., getDeviceId())",
      "destination": "where it goes (e.g., HTTP request to )",
      "path": ["classes and methods the data passes through"],
      "quoted_code": "exact code excerpt showing the data handling (max 5 lines, properly escaped)"
    }
  ],
  "code_snippets": [
    {
      "class_name": "full class name",
      "lines": "exact code excerpt (max 10 lines), escape newlines as \\n and double quotes as \\\"",
      "reason": "why this snippet is interesting (e.g., dynamic loading, reflection, network call)",
      "kind": "suspicious | exculpatory | neutral"
    }
  ],
  "network_indicators": ["list of URLs, IPs, domains found"],
  "permissions_used": ["permissions actually used in code"],
  "services_receivers": ["exported components found"],
  "reflection_usage": [
    {
      "target": "what is accessed/modified via reflection",
      "code": "exact code lines",
      "risk": "low/medium/high if used for bypassing security"
    }
  ],
  "dynamic_loading": [
    {
      "mechanism": "DexClassLoader / PathClassLoader / other",
      "loaded_code_origin": "file path, URL, or unknown",
      "actions_after_load": "what methods are called on the loaded class, if visible",
      "exculpatory_code": "any code that restricts loading (e.g., only loads known classes, checks signatures)"
    }
  ],
  "native_code": [
    {
      "library_name": "name of .so file",
      "purpose_hint": "from code comments or usage",
      "function_called": "JNI function signatures"
    }
  ],
  "benign_pattern_matches": [
    {
      "pattern": "e.g., OneSignal, Firebase, AdMob, multidex, etc.",
      "confidence": 0.0-1.0,
      "evidence_lines": "quote key lines that match the pattern"
    }
  ],
  "unusual_behaviors": [
    {
      "description": "behaviour that does NOT fit common benign SDK patterns",
      "exact_code": "quote the code",
      "why_unusual": "explain why a legitimate app would not do this"
    }
  ],
  "notes": "any additional objective observations"
}

Important rules:
- All code quotes must be taken VERBATIM from the provided source code.
- To ensure valid JSON, escape every newline as \\n, every double quote as \\\", and every backslash as \\\\\.
- If you are unsure about an observation, do not include it.
- Use empty arrays for missing categories.
- The analysis must be based ONLY on the source code provided; never add assumptions.
"""


CLUSTER_PROFILE_USER = """
Cluster ID: {cluster_id}
Package Name: {package_name}
Class names: {class_names}

## Graph connection, and source codes of the cluster ---->
{all_sources}

Extract the evidence profile as JSON.
"""
