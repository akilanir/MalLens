import json
import re
from pathlib import Path
from droidlens.utils.pre_processing import preprocess_java_code
from droidlens.summarization.summ_prompts import build_user_prompt, SYSTEM_PROMPT


# def verify_evidence(evidence: list, source_text: str):
#     """
#     Returns (correct_count, total, list of incorrect_snippets).
#     A snippet is correct if it appears as a substring in source_text after stripping trailing/leading whitespace.
#     """
#     incorrect = []
#     correct = 0
#     source_clean = re.sub(r'\s+', ' ', source_text)
#     for snippet in evidence:
#         # Normalise whitespace (collapse multiple spaces, but keep newlines if needed)
#         snippet_clean = re.sub(r'\s+', ' ', snippet).strip()
        
#         print(f"SNIPPET:\n{snippet}")
#         if snippet_clean in source_clean:
#             correct += 1
#         else:
#             incorrect.append(snippet)
#     return correct, len(evidence), incorrect


import re


def tokenize_for_evidence(text: str):
    """
    Tokenize Java code while ignoring formatting and obvious
    placeholder/syntax noise.
    """
    tokens = re.findall(
        r'[A-Za-z_$][\w$]*'
        r'|"(?:\\.|[^"\\])*"'
        r"|'(?:\\.|[^'\\])*'"
        r'|\d+(?:\.\d+)?',
        text
    )
    return tokens


def lcs_length(a, b):
    """
    Longest Common Subsequence length.
    """
    if not a or not b:
        return 0
    # Keep memory small.
    if len(a) < len(b):
        a, b = b, a
    prev = [0] * (len(b) + 1)
    for x in a:
        curr = [0]
        for j, y in enumerate(b, start=1):
            if x == y:
                curr.append(prev[j - 1] + 1)
            else:
                curr.append(max(prev[j], curr[-1]))
        prev = curr
    return prev[-1]


def verify_evidence(evidence: list,source_text: str,threshold: float = 0.80):
    """
    Evidence verification using:
      1. exact normalized substring match
      2. ordered token coverage using LCS

    Returns:
      correct_count,
      total,
      incorrect_snippets
    """
    incorrect = []
    correct = 0
    source_clean = re.sub(r'\s+', ' ', source_text).strip()
    source_tokens = tokenize_for_evidence(source_text)

    for snippet in evidence:
        snippet_clean = re.sub(r'\s+', ' ', snippet).strip()
        # ------------------------------------------
        # Stage 1: exact normalized substring
        # ------------------------------------------
        if snippet_clean in source_clean:
            correct += 1
            continue
        # ------------------------------------------
        # Stage 2: ordered token similarity
        # ------------------------------------------
        snippet_tokens = tokenize_for_evidence(snippet)
        if not snippet_tokens:
            incorrect.append(snippet)
            continue
        matched = lcs_length(snippet_tokens, source_tokens)
        coverage = matched / len(snippet_tokens)
        print(f"Evidence coverage: " f"{matched}/{len(snippet_tokens)} = {coverage:.3f}")
        if coverage >= threshold:
            correct += 1
        else:
            incorrect.append(snippet)
    return correct, len(evidence), incorrect


# def parse_tiny_response(text: str):
#     need_verify = True
#     text = text.strip()
#     # Remove markdown fences if the model adds them
#     if text.startswith("```"):
#         lines = text.splitlines()
#         if lines and lines[0].startswith("```"):
#             lines = lines[1:]
#         if lines and lines[-1].strip() == "```":
#             lines = lines[:-1]
#         text = "\n".join(lines).strip()
#     summary_marker_1 = "SUMMARY:"
#     summary_marker_2 = "SUMMARY"
#     evidence_marker_1 = "EVIDENCE:"
#     evidence_marker_2 = "EVIDENCE"
    
#     if summary_marker_1 in text:
#         summary_part = text.split(summary_marker_1, 1)[1]
#     elif summary_marker_2 in text:
#         summary_part = text.split(summary_marker_2, 1)[1]
#     else:
#         summary = "Could not separate summary and evidence refer full llm agent response: {text}"
#         evidence = "refer to full code"
#         need_verify = False
#         return summary, evidence, need_verify

#     if evidence_marker_1 in text:
#         summary, evidence_part = summary_part.split(evidence_marker_1,1)
#     if evidence_marker_2 in text:
#         summary, evidence_part = summary_part.split(evidence_marker_2,1)
    
#     summary = summary.strip()
#     evidence = [x.strip() for x in evidence_part.split("\n---\n") if x.strip()]
#     return summary, evidence, need_verify

def parse_tiny_response(text: str):
    need_verify = True
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    if "SUMMARY:" in text:
        summary_part = text.split("SUMMARY:", 1)[1]
    elif "SUMMARY" in text:
        summary_part = text.split("SUMMARY", 1)[1]
    else:
        summary = (
            f"Could not separate summary and evidence. "
            f"Refer to full LLM response: {text}"
        )
        return summary, [], False
    if "EVIDENCE:" in summary_part:
        summary, evidence_part = summary_part.split(
            "EVIDENCE:", 1
        )
    elif "EVIDENCE" in summary_part:
        summary, evidence_part = summary_part.split(
            "EVIDENCE", 1
        )
    else:
        summary = (
            f"Could not separate summary and evidence. "
            f"Refer to full LLM response: {text}"
        )
        return summary, [], False
    summary = summary.strip()
    evidence = [
        x.strip()
        for x in evidence_part.split("\n---\n")
        if x.strip()
    ]
    if not summary or not evidence:
        return summary, evidence, False
    return summary, evidence, need_verify

def get_verified_summary(class_name: str, raw_source_path: str, static_facts: dict,
                         client, max_iterations: int = 3) -> dict:
    """
    Returns a dict with keys:
        'summary': str,
        'evidence': list (verified),
        'iterations': int,
        'success': bool (80% or more correct)
    If after max_iterations the rate is still below 80%, we still return the best attempt
    but mark success=False. The caller can decide to fallback to raw source or a warning.
    """
    # Preprocess the source code exactly as you do in pack_cluster
    src_raw = Path(raw_source_path).read_text(encoding="utf-8", errors="replace")
    src_clean = preprocess_java_code(src_raw)  # from your preprocessing module

    # We'll pass the clean source to the model, but verification also uses src_clean
    user_base = build_user_prompt(class_name, src_clean, static_facts, max_source_chars=4000)

    print("="*30 + f"\nNEW CLASS: {class_name} ")

    current_user = user_base
    best_output = None
    best_score = 0.0
    best_evidence = []
    # tiny_model = "llama3.2:latest"
    # tiny_model = "qwen3-coder:latest"
    tiny_model="llama3.2:3b-instruct-q8_0"

    for i in range(max_iterations):
        text, usage = client.complete_tiny(SYSTEM_PROMPT, current_user, tiny_model)
        print(f"Tiny llm response: {text} \n {usage}")

        # Attempt to parse JSON
        try:
            summary, evidence, need_verify = parse_tiny_response(text)
            # Some models might put the JSON inside a markdown code block; extract it
            # json_match = re.search(r'\{.*\}', text, re.DOTALL)
            # if json_match:
            #     text_clean = json_match.group(0)
            # else:
            #     text_clean = text
            # parsed = json.loads(text_clean)
            # summary = parsed.get("summary", "")
            # evidence = parsed.get("evidence", [])
            print(f"This is parsed: SUMMARY: {summary}\nEVIDENCE: {evidence}")
        except Exception as exc:
            # Parse error – treat as zero correct evidence
            print(f"        LLM RESPONSE PARSER ERROR!!!!!: {exc}")
            summary = f"Could not separate summary and evidence refer full llm agent response: {text}"
            evidence = []

        # Verify evidence against src_clean
        if need_verify:
            print("VERIFYING THE EVIDENCES ==============================================================")
            correct, total, incorrect = verify_evidence(evidence, src_clean)
        else:
            print("Sending raw response---------------------------------- ***********************")
            correct, total, incorrect = 1, 1, 0
        if total == 0:
            rate = 0.0
        else:
            rate = correct / total

        # Track best attempt by rate
        if rate > best_score:
            best_score = rate
            best_output = {"summary": summary, "evidence": evidence}
            best_evidence = evidence
        else:
            # Keep the best evidence so far, but we can still try to improve
            pass

        # If rate >= 0.8, we are done
        print(f"Fact Verification Rate for {class_name} is {rate}")
        if rate >= 0.8:
            return {
                "summary": summary,
                "evidence": evidence,
                "iterations": i + 1,
                "success": True,
                "usage": usage
            }

        # Otherwise, prepare error feedback
        if i < max_iterations - 1:
            # Build a new user prompt that includes the error
            error_msg = (
                f"Your previous answer contained {len(incorrect)} evidence snippet(s) that are "
                f"NOT verbatim substrings of the source code:\n"
            )
            for idx, bad in enumerate(incorrect, 1):
                error_msg += f"{idx}. {bad[:200]}...\n"
            error_msg += (
                "\nPlease revise the summary and ensure ALL evidence snippets are EXACT, copiable substrings "
                "from the original code. Do not alter or paraphrase them. Respond with ONLY the corrected JSON."
            )
            # Append feedback to the conversation; we can just concatenate the entire interaction
            current_user = f"{user_base}\n\n---\nPrevious answer:\n{text}\n\nError:\n{error_msg}"
            # Note: This creates a longer prompt; the model should handle it.

    # If we exit the loop, return the best we had
    return {
        "summary": best_output["summary"],
        "evidence": best_evidence,
        "iterations": max_iterations,
        "success": False,
        "usage": None
    }

#### ------------------------ Cluster summary verification ------------------
def verify_code_snippet(class_name: str, snippet: str, source_map: dict) -> bool:
    """
    Check if the snippet appears in the given class source.
    We normalize whitespace and remove indentation variability.
    """
    if class_name not in source_map:
        return False
    src = source_map[class_name]
    # Normalise: collapse multiple spaces, strip leading/trailing whitespace per line
    def normalize(s):
        lines = [l.strip() for l in s.strip().splitlines() if l.strip() != '']
        return '\n'.join(lines)

    norm_snippet = normalize(snippet)
    norm_src = normalize(src)
    return norm_snippet in norm_src
