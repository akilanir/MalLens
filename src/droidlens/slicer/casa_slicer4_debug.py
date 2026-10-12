#!/usr/bin/env python3
"""
Smart Code Slicing for LLM-based Malware Detection - Debug/Corrected Version

Pipeline:
1. Build benign CodeBERT prototypes offline.
2. Compute contrastive token saliency online.
3. Select anomalous anchors.
4. Expand backward/forward lexical dependencies.
5. Preserve enclosing control/brace structure.
6. Propagate importance over a lightweight line graph.
7. Select lines by an explicit token-retention target plus hard max_tokens.
8. Print detailed diagnostics so pruning behavior can be verified.

Important:
- keep_ratio is now a DIRECT source-token retention target, not cumulative saliency mass.
- max_tokens is a HARD final budget target.
- Missing benign prototypes are treated as an error by default to avoid accidental non-contrastive experiments.
"""

import os
import re
import math
import warnings
from typing import List, Dict, Set, Tuple, Optional

import numpy as np
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel
from sklearn.cluster import MiniBatchKMeans
from tqdm import tqdm

warnings.filterwarnings("ignore")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_NAME = "microsoft/codebert-base"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE)
model.eval()

SENSITIVE_APIS = [
    "Runtime.exec", "ProcessBuilder", "getDeviceId", "getSubscriberId",
    "getSimSerialNumber", "getLine1Number", "sendTextMessage",
    "startService", "createWifiLock", "newWakeLock",
    "DexClassLoader", "PathClassLoader", "loadClass", "loadLibrary",
    "getInstalledPackages", "setComponentEnabledSetting",
    "Class.forName", "getMethod", "invoke", "getDeclaredMethod",
    "HttpURLConnection", "execute", "SecretKeySpec", "Cipher",
]

KEYWORDS = {
    "if", "for", "while", "switch", "try", "catch", "finally", "return",
    "new", "instanceof", "class", "public", "private", "protected", "static",
    "final", "void", "int", "long", "double", "float", "boolean", "byte",
    "short", "char", "this", "super", "null", "true", "false", "import",
    "package", "throws", "throw", "extends", "implements", "interface",
    "enum", "synchronized", "volatile", "transient", "native", "abstract",
    "default", "assert", "break", "continue", "do", "else", "case",
}

IDENT_RE = re.compile(r"\b([a-zA-Z_$][\w$]*)\b")
ASSIGN_RE = re.compile(r"(?<![=!<>])(?:\+=|-=|\*=|/=|%=|=(?!=))")

def dbg(debug: bool, msg: str) -> None:
    if debug:
        print(f"[SMART-SLICE] {msg}")

def token_count(text: str) -> int:
    return len(tokenizer(text, add_special_tokens=False, truncation=False)["input_ids"])

def build_benign_prototypes_from_folder(
    folder_path: str,
    output_path: str,
    n_clusters: int = 256,
    max_windows: int = 200000,
    batch_size: int = 32,
    max_len: int = 512,
    stride: int = 256,
    debug: bool = True,
) -> None:
    java_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            if f.endswith(".java"):
                java_files.append(os.path.join(root, f))
    print(f"Found {len(java_files)} Java files.")
    all_windows = []
    for file_path in tqdm(java_files, desc="Tokenizing files"):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
        except Exception:
            continue
        if not source.strip():
            continue
        enc = tokenizer(source, return_offsets_mapping=False, add_special_tokens=False, truncation=False)
        input_ids = enc["input_ids"]
        for start in range(0, len(input_ids), stride):
            end = min(start + max_len - 2, len(input_ids))
            if end <= start:
                break
            all_windows.append([tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id])
            if len(all_windows) >= max_windows:
                break
        if len(all_windows) >= max_windows:
            break
    print(f"Collected {len(all_windows)} windows.")
    if not all_windows:
        raise RuntimeError("No benign windows were collected.")
    embeddings_list = []
    with torch.no_grad():
        for batch_start in tqdm(range(0, len(all_windows), batch_size), desc="Extracting CLS embeddings"):
            batch = all_windows[batch_start:batch_start + batch_size]
            batch_max_len = max(len(w) for w in batch)
            input_ids = torch.full((len(batch), batch_max_len), tokenizer.pad_token_id, dtype=torch.long, device=DEVICE)
            attention_mask = torch.zeros((len(batch), batch_max_len), dtype=torch.long, device=DEVICE)
            for i, w in enumerate(batch):
                input_ids[i, :len(w)] = torch.tensor(w, dtype=torch.long, device=DEVICE)
                attention_mask[i, :len(w)] = 1
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            cls = F.normalize(outputs.last_hidden_state[:, 0, :].float(), dim=-1).cpu().numpy()
            embeddings_list.append(cls)
    X = np.concatenate(embeddings_list, axis=0)
    print(f"Total benign embedding matrix: {X.shape}")
    actual_k = min(n_clusters, len(X))
    if actual_k < n_clusters:
        print(f"Reducing n_clusters from {n_clusters} to {actual_k} because only {len(X)} windows exist.")
    kmeans = MiniBatchKMeans(
        n_clusters=actual_k,
        random_state=42,
        batch_size=min(1024, max(32, len(X))),
        max_iter=100,
        n_init=3,
    )
    kmeans.fit(X)
    centroids = F.normalize(torch.tensor(kmeans.cluster_centers_, dtype=torch.float32), dim=-1).numpy()
    np.savez_compressed(output_path, centroids=centroids)
    print(f"Saved {len(centroids)} benign centroids to {output_path}")

def load_benign_prototypes(proto_path: str, strict: bool = True) -> torch.Tensor:
    if not os.path.exists(proto_path):
        msg = f"Prototype file not found: {proto_path}"
        if strict:
            raise FileNotFoundError(msg)
        print(f"Warning: {msg}; anomaly weighting disabled.")
        return torch.zeros(1, model.config.hidden_size, dtype=torch.float32, device=DEVICE)
    data = np.load(proto_path)
    centroids = np.asarray(data["centroids"], dtype=np.float32)
    norms = np.linalg.norm(centroids, axis=1, keepdims=True)
    centroids = centroids / np.clip(norms, 1e-12, None)
    if centroids.ndim != 2 or centroids.shape[1] != model.config.hidden_size:
        raise ValueError(f"Invalid prototype shape: {centroids.shape}")
    return torch.tensor(centroids, dtype=torch.float32, device=DEVICE)

def char_to_line(char_pos: int, line_ends: np.ndarray) -> int:
    if len(line_ends) == 0:
        return 0
    return min(np.searchsorted(line_ends, char_pos, side="right"), len(line_ends) - 1)

def get_saliency_line_scores_contrastive(
    java_codes: List[str],
    benign_protos: torch.Tensor,
    use_attention_fusion: bool = True,
    batch_size: int = 16,
    max_len: int = 512,
    stride: int = 256,
    debug: bool = True,
) -> List[Tuple[np.ndarray, List[str]]]:
    if not java_codes:
        return []
    all_windows = []
    window_meta = []
    class_data = []
    for cls_idx, code in enumerate(java_codes):
        enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False, truncation=False)
        input_ids = enc["input_ids"]
        offset_map = enc["offset_mapping"]
        lines = code.splitlines(keepends=True)
        line_ends = np.cumsum([len(l) for l in lines], dtype=np.int64)
        for start in range(0, len(input_ids), stride):
            end = min(start + max_len - 2, len(input_ids))
            if end <= start:
                break
            all_windows.append([tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id])
            window_meta.append((cls_idx, start, end))
        class_data.append((offset_map, line_ends, len(input_ids), lines))
    dbg(debug, f"Classes={len(java_codes)} | lines={len(class_data[0][3]) if class_data else 0} | windows={len(all_windows)}")
    token_score_sum = [np.zeros(data[2], dtype=np.float32) for data in class_data]
    token_score_cnt = [np.zeros(data[2], dtype=np.int32) for data in class_data]
    anomaly_values = []
    benign_protos = F.normalize(benign_protos.float(), dim=-1)
    for batch_start in range(0, len(all_windows), batch_size):
        batch_windows = all_windows[batch_start:batch_start + batch_size]
        batch_meta = window_meta[batch_start:batch_start + batch_size]
        batch_max_len = max(len(w) for w in batch_windows)
        input_ids = torch.full((len(batch_windows), batch_max_len), tokenizer.pad_token_id, dtype=torch.long, device=DEVICE)
        attention_mask = torch.zeros((len(batch_windows), batch_max_len), dtype=torch.long, device=DEVICE)
        for i, w in enumerate(batch_windows):
            input_ids[i, :len(w)] = torch.tensor(w, dtype=torch.long, device=DEVICE)
            attention_mask[i, :len(w)] = 1
        embeddings = model.get_input_embeddings()(input_ids)
        embeddings.retain_grad()
        model.zero_grad(set_to_none=True)
        outputs = model(inputs_embeds=embeddings, attention_mask=attention_mask, output_attentions=use_attention_fusion)
        cls_emb = outputs.last_hidden_state[:, 0, :].float()
        cls_normed = F.normalize(cls_emb, dim=-1)
        cos_sim = cls_normed @ benign_protos.T
        max_sim = cos_sim.max(dim=1).values
        anomaly = 1.0 - max_sim
        anomaly = torch.clamp(anomaly, 0.0, 2.0)
        loss = anomaly.mean()
        loss.backward()
        grad = embeddings.grad.float()
        saliency = (embeddings.detach().float() * grad).norm(dim=-1)
        if use_attention_fusion and outputs.attentions is not None:
            layer_indices = [i for i in (6, 7, 8, 9) if i < len(outputs.attentions)]
            if layer_indices:
                attn_weights = torch.zeros(embeddings.size(0), embeddings.size(1), device=DEVICE)
                for l_idx in layer_indices:
                    layer_attn = outputs.attentions[l_idx].float().mean(dim=1)
                    attn_weights += layer_attn[:, 0, :]
                attn_weights /= len(layer_indices)
                saliency = saliency * attn_weights
        token_scores = saliency * anomaly.detach().unsqueeze(1)
        token_scores = token_scores.detach().cpu().numpy()
        anomaly_values.extend(anomaly.detach().cpu().numpy().tolist())
        for batch_idx, (cls_idx, start, end) in enumerate(batch_meta):
            content_len = end - start
            scores = token_scores[batch_idx, 1:content_len + 1]
            token_score_sum[cls_idx][start:end] += scores
            token_score_cnt[cls_idx][start:end] += 1
        del input_ids, attention_mask, embeddings, outputs, grad, loss, cls_emb
        if DEVICE.type == "cuda":
            torch.cuda.empty_cache()
    results = []
    for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
        scores = token_score_sum[cls_idx]
        cnts = token_score_cnt[cls_idx]
        mask = cnts > 0
        final_token_scores = np.zeros(total_tok, dtype=np.float32)
        final_token_scores[mask] = scores[mask] / cnts[mask]
        line_scores = np.zeros(len(lines), dtype=np.float32)
        for token_idx, (start_char, end_char) in enumerate(offset_map):
            if start_char == 0 and end_char == 0:
                continue
            line_idx = char_to_line(start_char, line_ends)
            line_scores[line_idx] += final_token_scores[token_idx]
        results.append((line_scores, lines))
    if anomaly_values:
        arr = np.asarray(anomaly_values, dtype=np.float32)
        dbg(debug, f"Anomaly stats: min={arr.min():.4f} mean={arr.mean():.4f} max={arr.max():.4f}")
    return results

def build_line_graph(lines: List[str]) -> np.ndarray:
    n = len(lines)
    adj = np.zeros((n, n), dtype=np.float32)
    for i in range(n):
        if i + 1 < n:
            adj[i, i + 1] = 1.0
        s = lines[i].strip()
        if s.endswith("{") and re.search(r"\b(if|for|while|switch|try|catch|else)\b", s):
            adj[i, i] = 1.0
    row_sums = adj.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1.0
    return adj / row_sums

def select_automatic_anchors(
    line_scores: np.ndarray,
    top_k_ratio: float = 0.05,
    min_score: float = 1e-8,
) -> Set[int]:
    n = len(line_scores)
    if n == 0:
        return set()
    k = max(1, int(math.ceil(n * top_k_ratio)))
    k = min(k, n)
    order = np.argsort(line_scores)[::-1]
    selected = {int(i) for i in order[:k] if line_scores[i] >= min_score}
    return selected

def extract_variables_used(line: str) -> Set[str]:
    return {m.group(1) for m in IDENT_RE.finditer(line) if m.group(1) not in KEYWORDS}

def extract_assignment_lhs_vars(line: str) -> Set[str]:
    match = ASSIGN_RE.search(line)
    if not match:
        return set()
    lhs = line[:match.start()].strip()
    ids = extract_variables_used(lhs)
    if "." in lhs:
        tail = lhs.split(".")[-1]
        ids = {tail.split("[", 1)[0].strip()} & ids | ({tail.split("[", 1)[0].strip()} if tail.split("[", 1)[0].strip() else set())
    if "=" in line and "(" in lhs and ")" in lhs:
        return set()
    return {v for v in ids if v not in KEYWORDS}

def extract_assignment_rhs_vars(line: str) -> Set[str]:
    match = ASSIGN_RE.search(line)
    if not match:
        return set()
    return extract_variables_used(line[match.end():])

def backward_lexical_def_use(
    lines: List[str],
    anchor_idx: int,
    depth: int = 3,
    max_scan: int = 80,
) -> Set[int]:
    keep = {anchor_idx} if 0 <= anchor_idx < len(lines) else set()
    watch_vars = extract_variables_used(lines[anchor_idx]) if keep else set()
    resolved = set()
    for level in range(depth + 1):
        if not watch_vars:
            break
        found_any = False
        scan_start = anchor_idx - 1
        for i in range(scan_start, max(-1, anchor_idx - max_scan) , -1):
            assigned = extract_assignment_lhs_vars(lines[i])
            hit = assigned.intersection(watch_vars - resolved)
            if hit:
                keep.add(i)
                found_any = True
                resolved.update(hit)
                watch_vars.update(extract_assignment_rhs_vars(lines[i]))
                break
        if not found_any:
            break
    return keep

def forward_lexical_use(lines: List[str], anchor_idx: int, max_scan: int = 80) -> Set[int]:
    keep = set()
    assigned_vars = extract_assignment_lhs_vars(lines[anchor_idx]) if 0 <= anchor_idx < len(lines) else set()
    watch_vars = set(assigned_vars)
    if not watch_vars:
        return keep
    for i in range(anchor_idx + 1, min(anchor_idx + max_scan + 1, len(lines))):
        used_vars = extract_variables_used(lines[i])
        if watch_vars.intersection(used_vars):
            keep.add(i)
            new_vars = extract_assignment_lhs_vars(lines[i])
            watch_vars.update(new_vars)
    return keep

def enclosing_control_lines(lines: List[str], anchor_idx: int) -> Set[int]:
    keep = set()
    for i in range(anchor_idx - 1, -1, -1):
        s = lines[i].strip()
        if s.endswith("{") and re.search(r"\b(if|for|while|switch|try|catch|else)\b", s):
            keep.add(i)
        if re.search(r"\b(class|interface|enum)\b", s) and "{" in s:
            keep.add(i)
            break
        if "(" in s and s.endswith("{") and re.search(r"\b(public|private|protected|static)\b", s):
            keep.add(i)
            break
    return keep

def build_brace_pairs(lines: List[str]) -> Tuple[Dict[int, int], Dict[int, int], List[List[int]]]:
    open_to_close = {}
    close_to_open = {}
    stack = []
    stack_before = []
    in_block_comment = False
    for i, line in enumerate(lines):
        stack_before.append(list(stack))
        j = 0
        in_string = None
        escaped = False
        while j < len(line):
            ch = line[j]
            nxt = line[j + 1] if j + 1 < len(line) else ""
            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == in_string:
                    in_string = None
                j += 1
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                j += 2
                continue
            if ch == "/" and nxt == "/":
                break
            if ch in ('"', "'"):
                in_string = ch
            elif ch == "{":
                stack.append(i)
            elif ch == "}" and stack:
                open_idx = stack.pop()
                open_to_close[open_idx] = i
                close_to_open[i] = open_idx
            j += 1
    return open_to_close, close_to_open, stack_before

def structural_context_for_indices(
    selected: Set[int],
    open_to_close: Dict[int, int],
    close_to_open: Dict[int, int],
    stack_before: List[List[int]],
) -> Set[int]:
    keep = set()
    for idx in selected:
        if idx in close_to_open:
            keep.add(close_to_open[idx])
        for open_idx in stack_before[idx]:
            keep.add(open_idx)
            if open_idx in open_to_close:
                keep.add(open_to_close[open_idx])
    return keep

def mandatory_lines_to_keep(lines: List[str]) -> Set[int]:
    keep = set()
    if not lines:
        return keep
    keep.update({0, len(lines) - 1})
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(("package ", "import ")):
            keep.add(i)
        if re.search(r"\b(class|interface|enum)\b", s) and "{" in s:
            keep.add(i)
        if re.search(r"\b(public|private|protected)\b", s) and "(" in s and s.endswith("{"):
            keep.add(i)
    return keep

def pagerank_propagation(
    line_scores: np.ndarray,
    anchor_bonus: np.ndarray,
    adj: np.ndarray,
    alpha: float = 0.85,
    iterations: int = 20,
) -> np.ndarray:
    n = len(line_scores)
    if n == 0:
        return line_scores
    init = line_scores.astype(np.float32).copy()
    if anchor_bonus.sum() > 0:
        init += anchor_bonus.astype(np.float32)
    if init.sum() <= 0:
        init[:] = 1.0 / n
    else:
        init /= init.sum()
    p = init.copy()
    for _ in range(iterations):
        p = alpha * (adj.T @ p) + (1.0 - alpha) * init
        p /= (p.sum() + 1e-12)
    return p

def add_reason(reasons: Dict[int, Set[str]], indices: Set[int], reason: str) -> None:
    for idx in indices:
        reasons.setdefault(int(idx), set()).add(reason)

def select_lines_with_budget(
    lines: List[str],
    propagated: np.ndarray,
    initial_keep: Set[int],
    reasons: Dict[int, Set[str]],
    keep_ratio: float,
    max_tokens: int,
    debug: bool = True,
) -> Set[int]:
    original_tokens = token_count("".join(lines))
    target_tokens = min(max_tokens, max(1, int(math.ceil(original_tokens * keep_ratio))))
    line_costs = np.asarray([max(1, token_count(line)) for line in lines], dtype=np.int32)
    keep = set(initial_keep)
    used_tokens = int(line_costs[list(keep)].sum()) if keep else 0
    dbg(debug, f"Original tokens={original_tokens} | keep_ratio={keep_ratio:.3f} | target={target_tokens} | initial kept tokens={used_tokens}")
    if used_tokens > target_tokens:
        dbg(debug, f"Initial mandatory/closure structure already exceeds target by {used_tokens - target_tokens} tokens; these lines are retained for context.")
    candidates = [i for i in np.argsort(propagated)[::-1] if int(i) not in keep]
    candidates.sort(key=lambda i: float(propagated[i]) / max(1, line_costs[i]), reverse=True)
    for idx in candidates:
        if used_tokens >= target_tokens:
            break
        cost = int(line_costs[idx])
        if used_tokens + cost > max_tokens:
            continue
        if used_tokens + cost > target_tokens and used_tokens < target_tokens:
            continue
        keep.add(int(idx))
        used_tokens += cost
        reasons.setdefault(int(idx), set()).add("score")
    dbg(debug, f"Final selected lines={len(keep)}/{len(lines)} | selected tokens≈{used_tokens} | target={target_tokens} | max={max_tokens}")
    return keep

def render_pruned_source(lines: List[str], keep_indices: Set[int]) -> str:
    if not lines:
        return ""
    result = []
    last_kept = -2
    for i in sorted(keep_indices):
        if i > last_kept + 1:
            result.append("// ... pruned ...\n")
        result.append(lines[i])
        last_kept = i
    return "".join(result)

def print_debug_summary(
    lines: List[str],
    line_scores: np.ndarray,
    propagated: np.ndarray,
    anchors: Set[int],
    keep: Set[int],
    reasons: Dict[int, Set[str]],
    debug: bool = True,
) -> None:
    if not debug:
        return
    dbg(True, f"Score stats: min={line_scores.min():.6g} mean={line_scores.mean():.6g} max={line_scores.max():.6g} nonzero={np.count_nonzero(line_scores)}/{len(lines)}")
    top = np.argsort(line_scores)[::-1][:min(10, len(lines))]
    print("[SMART-SLICE] Top anomaly/saliency lines:")
    for i in top:
        print(f"  L{i+1:04d} score={line_scores[i]:.6g} prop={propagated[i]:.6g} anchor={'Y' if i in anchors else 'N'} | {lines[i].strip()[:140]}")
    dbg(True, f"Anchors={len(anchors)} -> {[i + 1 for i in sorted(anchors)]}")
    reason_counts = {}
    for idx in keep:
        for r in reasons.get(idx, {"unknown"}):
            reason_counts[r] = reason_counts.get(r, 0) + 1
    dbg(True, f"Keep reasons={reason_counts}")
    print("[SMART-SLICE] Dropped lines:")
    dropped = [i for i in range(len(lines)) if i not in keep]
    for i in dropped[:20]:
        print(f"  DROP L{i+1:04d} score={line_scores[i]:.6g} prop={propagated[i]:.6g} | {lines[i].strip()[:140]}")
    if len(dropped) > 20:
        print(f"  ... {len(dropped) - 20} more dropped lines ...")

def smart_slice_class(
    class_source: str,
    benign_protos_path: str,
    use_attention_fusion: bool = True,
    batch_size: int = 8,
    keep_ratio: float = 0.7,
    max_tokens: int = 1024,
    top_k_ratio: float = 0.05,
    sensitive_apis: Optional[List[str]] = None,
    debug: bool = True,
    strict_prototypes: bool = True,
) -> str:
    if not class_source.strip():
        return ""
    if not 0.0 < keep_ratio <= 1.0:
        raise ValueError("keep_ratio must be in (0, 1].")
    benign_protos = load_benign_prototypes(benign_protos_path, strict=strict_prototypes)
    lines = class_source.splitlines(keepends=True)
    original_tokens = token_count(class_source)
    dbg(debug, f"Input chars={len(class_source)} | lines={len(lines)} | tokens={original_tokens}")
    results = get_saliency_line_scores_contrastive(
        [class_source],
        benign_protos=benign_protos,
        use_attention_fusion=use_attention_fusion,
        batch_size=batch_size,
        debug=debug,
    )
    if not results:
        return class_source
    line_scores, lines = results[0]
    if not np.any(line_scores > 0):
        dbg(debug, "All line scores are zero; falling back to structural/context selection.")
    if sensitive_apis is not None:
        anchors = {i for i, line in enumerate(lines) if any(api in line for api in sensitive_apis)}
        dbg(debug, f"Explicit API anchors selected: {len(anchors)}")
    else:
        anchors = select_automatic_anchors(line_scores, top_k_ratio=top_k_ratio)
    if not anchors:
        anchors = {int(np.argmax(line_scores))}
        dbg(debug, f"No anchors above threshold; fallback anchor=L{next(iter(anchors)) + 1}")
    anchor_bonus = np.zeros(len(lines), dtype=np.float32)
    for idx in anchors:
        anchor_bonus[idx] = 1.0 / max(1, len(anchors))
    normalized_scores = line_scores.copy()
    if normalized_scores.sum() > 0:
        normalized_scores /= normalized_scores.sum()
    propagated = pagerank_propagation(normalized_scores, anchor_bonus, build_line_graph(lines))
    closure_keep = set()
    reasons: Dict[int, Set[str]] = {}
    add_reason(reasons, anchors, "anchor")
    for aidx in anchors:
        b = backward_lexical_def_use(lines, aidx, depth=3, max_scan=80)
        f = forward_lexical_use(lines, aidx, max_scan=80)
        c = enclosing_control_lines(lines, aidx)
        closure_keep.update(b)
        closure_keep.update(f)
        closure_keep.update(c)
        add_reason(reasons, b, "backward")
        add_reason(reasons, f, "forward")
        add_reason(reasons, c, "control")
    mandatory = mandatory_lines_to_keep(lines)
    closure_keep.update(mandatory)
    add_reason(reasons, mandatory, "mandatory")
    brace_open, brace_close, stack_before = build_brace_pairs(lines)
    structural = structural_context_for_indices(closure_keep | anchors, brace_open, brace_close, stack_before)
    closure_keep.update(structural)
    add_reason(reasons, structural, "brace")
    dbg(debug, f"Closure={len(closure_keep)} | mandatory={len(mandatory)} | structural={len(structural)}")
    keep = select_lines_with_budget(
        lines=lines,
        propagated=propagated,
        initial_keep=closure_keep,
        reasons=reasons,
        keep_ratio=keep_ratio,
        max_tokens=max_tokens,
        debug=debug,
    )
    print_debug_summary(lines, line_scores, propagated, anchors, keep, reasons, debug=debug)
    pruned = render_pruned_source(lines, keep)
    pruned_tokens = token_count(pruned)
    reduction = 100.0 * (1.0 - (pruned_tokens / max(1, original_tokens)))
    dbg(debug, f"Final tokens={pruned_tokens} | reduction={reduction:.2f}% | output lines={len(keep)}")
    return pruned

if __name__ == "__main__":
    print("Use smart_slice_class(...) from another script.")
    class_code = """
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

        """
    pruned = smart_slice_class(class_source = class_code, benign_protos_path = "benign_prototypes.npz", use_attention_fusion = True, keep_ratio=0.8, max_tokens=2048)
    print(pruned)
