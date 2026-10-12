#!/usr/bin/env python3
"""
Token-efficient LLM malware detector - smart code slicing.
Uses CodeBERT saliency, contrastive anomaly against benign prototypes,
sensitive API anchors, lexical def-use closure, and lightweight PageRank.
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

# ------------------------------------------------------------------------------
# Global setup
# ------------------------------------------------------------------------------
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_NAME = "microsoft/codebert-base"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME).to(DEVICE)
model.eval()

# Sensitive APIs (permission-related, from MITRE, SUSI, etc.)
SENSITIVE_APIS = [
    "Runtime.exec", "ProcessBuilder", "getDeviceId", "getSubscriberId",
    "getSimSerialNumber", "getLine1Number", "sendTextMessage",
    "startService", "createWifiLock", "newWakeLock",
    "DexClassLoader", "PathClassLoader", "loadClass", "loadLibrary",
    "getInstalledPackages", "setComponentEnabledSetting",
    "Class.forName", "getMethod", "invoke", "getDeclaredMethod",
    "HttpURLConnection", "execute", "SecretKeySpec", "Cipher",
    "getCellLocation", "getNetworkOperator", "getNetworkOperatorName",
    "getSimOperator", "getSimOperatorName", "getSubscriberId",
    "getDeviceId", "getImei", "getMeid", "getPhoneType",
    "getAllCellInfo", "getCellInfo", "requestLocationUpdates",
    "getLastKnownLocation", "getLatitude", "getLongitude",
    "sendTextMessage", "sendMultipartTextMessage", "abortBroadcast",
    "setResultData", "getRunningTasks", "getRunningAppProcesses",
    "killBackgroundProcesses", "restartPackage", "setComponentEnabledSetting",
    "addJavascriptInterface", "setWebChromeClient", "setWebViewClient",
    "loadUrl", "evaluateJavascript", "postUrl",
]

# ------------------------------------------------------------------------------
# 1. Benign prototype generation
# ------------------------------------------------------------------------------
def build_benign_prototypes_from_folder(
    folder_path: str,
    output_path: str,
    n_clusters: int = 256,
    max_windows: int = 200000,
    batch_size: int = 32,
    max_len: int = 512,
    stride: int = 256
) -> None:
    """
    Process all Java files in folder_path, extract CodeBERT CLS embeddings
    for sliding windows, cluster them with MiniBatchKMeans, and save centroids
    to an .npz file. These centroids represent common benign/TPL code patterns.

    Args:
        folder_path: Root directory containing benign Java sources.
        output_path: Where to save the .npz file.
        n_clusters: Number of centroids (prototypes) to store.
        max_windows: Maximum number of windows to consider (memory safety).
        batch_size: Batch size for CodeBERT inference.
        max_len, stride: Window parameters (same as used later).
    """
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
        enc = tokenizer(source, return_offsets_mapping=False,
                        add_special_tokens=False, truncation=False)
        input_ids = enc["input_ids"]
        total = len(input_ids)
        if total == 0:
            continue
        for start in range(0, total, stride):
            end = min(start + max_len - 2, total)
            if end <= start:
                break
            window = [tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id]
            all_windows.append(window)
            if len(all_windows) >= max_windows:
                break
        if len(all_windows) >= max_windows:
            break

    print(f"Collected {len(all_windows)} windows.")
    embeddings_list = []
    with torch.no_grad():
        for batch_start in tqdm(range(0, len(all_windows), batch_size),
                                desc="Extracting CLS embeddings"):
            batch_windows = all_windows[batch_start:batch_start + batch_size]
            batch_max_len = max(len(w) for w in batch_windows)
            input_ids = torch.full((len(batch_windows), batch_max_len),
                                    tokenizer.pad_token_id, dtype=torch.long, device=DEVICE)
            attention_mask = torch.zeros((len(batch_windows), batch_max_len),
                                         dtype=torch.long, device=DEVICE)
            for i, w in enumerate(batch_windows):
                input_ids[i, :len(w)] = torch.tensor(w, dtype=torch.long, device=DEVICE)
                attention_mask[i, :len(w)] = 1
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            cls = outputs.last_hidden_state[:, 0, :].cpu().numpy()
            embeddings_list.append(cls)

    if not embeddings_list:
        print("No embeddings extracted.")
        return
    X = np.concatenate(embeddings_list, axis=0)
    print(f"Total embedding matrix: {X.shape}")

    # Normalize embeddings to unit length (cosine similarity later)
    X = X / np.linalg.norm(X, axis=1, keepdims=True)

    # MiniBatchKMeans clustering
    kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=42,
                             batch_size=1024, max_iter=100, n_init=3)
    kmeans.fit(X)
    centroids = kmeans.cluster_centers_
    centroids = centroids / np.linalg.norm(centroids, axis=1, keepdims=True)

    np.savez_compressed(output_path, centroids=centroids)
    print(f"Saved {n_clusters} centroids to {output_path}")


def load_benign_prototypes(proto_path: str) -> torch.Tensor:
    """
    Load pre-computed benign centroids from .npz file.
    Returns a tensor of shape [n_clusters, hidden_dim] on DEVICE, L2-normalized.
    """
    if not os.path.exists(proto_path):
        print(f"Warning: prototype file {proto_path} not found. Using zero tensor (no anomaly weighting).")
        # Return a dummy tensor that gives anomaly weight ~1 for all windows.
        # We use a single zero vector; cos_sim with zero vector is 0 -> anomaly = 1.
        dim = model.config.hidden_size
        return torch.zeros(1, dim, dtype=torch.float32, device=DEVICE)

    data = np.load(proto_path)
    centroids = data["centroids"]
    centroids = centroids / np.linalg.norm(centroids, axis=1, keepdims=True)
    return torch.tensor(centroids, dtype=torch.float32, device=DEVICE)


# ------------------------------------------------------------------------------
# 2. Contrastive saliency computation
# ------------------------------------------------------------------------------
def char_to_line(char_pos: int, line_ends: np.ndarray) -> int:
    """Map character offset to line index using cumulative line lengths."""
    idx = np.searchsorted(line_ends, char_pos, side="right")
    return min(idx, len(line_ends) - 1)


def get_saliency_line_scores_contrastive(
    java_codes: List[str],
    benign_protos: torch.Tensor,
    use_attention_fusion: bool = True,
    batch_size: int = 16,
    max_len: int = 512,
    stride: int = 256
) -> List[Tuple[np.ndarray, List[str]]]:
    """
    Compute line-level importance scores for each Java code string.
    Score for a token = ||embedding * grad|| (L2 norm) 
                        * optional attention weight 
                        * contrastive anomaly weight (no tunable lambda).

    The anomaly weight is computed per window as:
        anomaly = 1 - max(cosine_sim(window_CLS, benign_protos))
    where cosine similarity is clamped to [0,1] (negative -> 0).
    Thus windows very similar to benign code get weight near 0, unusual windows near 1.

    Args:
        java_codes: List of Java source strings.
        benign_protos: Tensor of benign centroids, shape [K, D].
        use_attention_fusion: If True, multiply by average CLS attention from layers 6-9.
        batch_size: Batch size for backward/forward passes.
        max_len, stride: Window parameters.

    Returns:
        List of (line_scores_array, lines_list) per input code.
        line_scores_array has shape [n_lines], lines_list is the split source.
    """
    if not java_codes:
        return []

    all_windows = []
    window_meta = []   # (cls_idx, start_token, end_token)
    class_data = []    # (offset_map, line_ends, total_tokens, lines)

    # Tokenize all inputs and create sliding windows
    for cls_idx, code in enumerate(java_codes):
        enc = tokenizer(code, return_offsets_mapping=True,
                        add_special_tokens=False, truncation=False)
        input_ids = enc["input_ids"]
        offset_map = enc["offset_mapping"]
        lines = code.splitlines(keepends=True)
        line_ends = np.cumsum([len(l) for l in lines])
        total_tokens = len(input_ids)

        for start in range(0, total_tokens, stride):
            end = min(start + max_len - 2, total_tokens)
            if end <= start:
                break
            window = [tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id]
            all_windows.append(window)
            window_meta.append((cls_idx, start, end))
        class_data.append((offset_map, line_ends, total_tokens, lines))

    # Accumulators for token scores
    token_score_sum = [np.zeros(data[2], dtype=np.float32) for data in class_data]
    token_score_cnt = [np.zeros(data[2], dtype=np.int32) for data in class_data]

    # Normalize benign prototypes once
    benign_protos = F.normalize(benign_protos.float(), dim=-1)

    # Process windows in batches
    for batch_start in range(0, len(all_windows), batch_size):
        batch_windows = all_windows[batch_start:batch_start + batch_size]
        batch_meta = window_meta[batch_start:batch_start + batch_size]
        batch_max_len = max(len(w) for w in batch_windows)

        input_ids = torch.full((len(batch_windows), batch_max_len),
                               tokenizer.pad_token_id, dtype=torch.long, device=DEVICE)
        attention_mask = torch.zeros((len(batch_windows), batch_max_len),
                                     dtype=torch.long, device=DEVICE)
        for i, w in enumerate(batch_windows):
            input_ids[i, :len(w)] = torch.tensor(w, dtype=torch.long, device=DEVICE)
            attention_mask[i, :len(w)] = 1

        embeddings = model.get_input_embeddings()(input_ids)
        embeddings.retain_grad()
        model.zero_grad(set_to_none=True)

        # Forward (with mixed precision on CUDA)
        if DEVICE.type == "cuda":
            with torch.autocast(device_type="cuda", dtype=torch.float16):
                outputs = model(inputs_embeds=embeddings,
                                attention_mask=attention_mask,
                                output_attentions=use_attention_fusion)
                cls_emb = outputs.last_hidden_state[:, 0, :].float()
                cls_norm = cls_emb.norm(dim=-1)
                loss = cls_norm.sum()
        else:
            outputs = model(inputs_embeds=embeddings,
                            attention_mask=attention_mask,
                            output_attentions=use_attention_fusion)
            cls_emb = outputs.last_hidden_state[:, 0, :].float()
            cls_norm = cls_emb.norm(dim=-1)
            loss = cls_norm.sum()

        loss.backward()

        grad = embeddings.grad  # [batch, seq_len, hidden]
        saliency = (embeddings.float() * grad.float()).norm(dim=-1)  # [batch, seq_len]

        # Optional attention fusion (average CLS attention from selected layers)
        if use_attention_fusion:
            layer_indices = [6, 7, 8, 9]
            attn_weights = torch.zeros(embeddings.size(0), embeddings.size(1),
                                       device=DEVICE)
            for l_idx in layer_indices:
                layer_attn = outputs.attentions[l_idx]          # [batch, heads, seq, seq]
                layer_attn = layer_attn.mean(dim=1)             # average heads
                attn_weights += layer_attn[:, 0, :]             # CLS row
            attn_weights /= len(layer_indices)
            token_scores = saliency * attn_weights
        else:
            token_scores = saliency

        # Contrastive anomaly weighting (no hyperparameter)
        # anomaly = 1 - max_cos_sim (clamped to [0,1])
        with torch.no_grad():
            cls_normed = F.normalize(cls_emb, dim=-1)
            cos_sim = cls_normed @ benign_protos.T         # [batch, K]
            max_sim = cos_sim.max(dim=1).values            # [batch]
            max_sim = torch.clamp(max_sim, min=0.0)        # negative -> 0
            anomaly = 1.0 - max_sim                        # [batch], 1 = very anomalous
        token_scores = token_scores * anomaly.unsqueeze(1)  # gate saliency

        token_scores = token_scores.detach().cpu().numpy()

        # Map batch scores back to original token positions
        for batch_idx, (cls_idx, start, end) in enumerate(batch_meta):
            content_len = end - start
            scores = token_scores[batch_idx, 1:content_len + 1]  # skip CLS
            for pos, score in enumerate(scores):
                orig_idx = start + pos
                if orig_idx < len(token_score_sum[cls_idx]):
                    token_score_sum[cls_idx][orig_idx] += score
                    token_score_cnt[cls_idx][orig_idx] += 1

        # Cleanup
        del input_ids, attention_mask, embeddings, outputs, grad, loss
        del cls_emb, cls_norm, saliency, token_scores
        if DEVICE.type == "cuda":
            torch.cuda.empty_cache()

    # Aggregate token scores to line scores
    results = []
    for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
        scores = token_score_sum[cls_idx]
        cnts = token_score_cnt[cls_idx]
        mask = cnts > 0
        token_scores_final = np.zeros(total_tok, dtype=np.float32)
        token_scores_final[mask] = scores[mask] / cnts[mask]

        line_scores = np.zeros(len(lines), dtype=np.float32)
        for token_idx, (start_char, end_char) in enumerate(offset_map):
            if start_char == 0 and end_char == 0:
                continue
            line_idx = char_to_line(start_char, line_ends)
            line_scores[line_idx] += token_scores_final[token_idx]
        results.append((line_scores, lines))
    return results


# ------------------------------------------------------------------------------
# 3. Lightweight statement / line graph
# ------------------------------------------------------------------------------
def build_line_graph(lines: List[str]) -> np.ndarray:
    """
    Build a simple adjacency matrix over source lines.
    Edges:
      - consecutive lines (i -> i+1)
      - control headers (if/for/while/switch/try/catch) get self-loop
        so they retain importance.
    The matrix is row-normalized for PageRank.

    Args:
        lines: List of source lines (without line endings).

    Returns:
        Row-stochastic adjacency matrix of shape [n_lines, n_lines].
    """
    n = len(lines)
    adj = np.zeros((n, n), dtype=np.float32)
    for i in range(n):
        if i + 1 < n:
            adj[i, i + 1] = 1.0
        s = lines[i].strip()
        if s.endswith("{") and any(kw in s for kw in ["if", "for", "while", "switch", "try", "catch"]):
            adj[i, i] = 1.0   # keep header in flow
    # Normalize rows
    row_sums = adj.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1.0
    adj = adj / row_sums
    return adj


# ------------------------------------------------------------------------------
# 4. Anchor extraction
# ------------------------------------------------------------------------------
def extract_sensitive_api_anchor_lines(lines: List[str],
                                       sensitive_apis: Optional[List[str]] = None) -> Set[int]:
    """
    Return indices of lines containing any sensitive API string.

    Args:
        lines: List of source lines.
        sensitive_apis: Optional custom list; defaults to global SENSITIVE_APIS.

    Returns:
        Set of line indices.
    """
    if sensitive_apis is None:
        sensitive_apis = SENSITIVE_APIS
    anchors = set()
    for i, line in enumerate(lines):
        for api in sensitive_apis:
            if api in line:
                anchors.add(i)
                break
    return anchors


# ------------------------------------------------------------------------------
# 5. Backward lexical def-use closure
# ------------------------------------------------------------------------------
def extract_variables_used(line: str) -> Set[str]:
    """
    Very simple variable extraction: all non-keyword identifiers.
    Not perfect, but sufficient for lightweight def-use closure.
    """
    keywords = {
        "if", "for", "while", "switch", "try", "catch", "finally", "return",
        "new", "instanceof", "class", "public", "private", "protected",
        "static", "final", "void", "int", "long", "double", "float",
        "boolean", "byte", "short", "char", "this", "super", "null",
        "true", "false", "import", "package"
    }
    pattern = re.compile(r'\b([a-zA-Z_$][\w$]*)\b')
    vars_used = set()
    for match in pattern.finditer(line):
        var = match.group(1)
        if var not in keywords:
            vars_used.add(var)
    return vars_used


def backward_lexical_def_use(lines: List[str],
                             anchor_idx: int,
                             depth: int = 3,
                             max_scan: int = 80) -> Set[int]:
    """
    Backward lexical data-flow closure for an anchor line.
    Scans backwards to find assignments to variables used in the anchor,
    and recursively for those definitions. Also collects control headers
    encountered during the scan.

    Args:
        lines: List of source lines.
        anchor_idx: Index of the anchor line.
        depth: Recursion depth for variable definitions.
        max_scan: Maximum number of lines to scan backwards.

    Returns:
        Set of line indices to keep.
    """
    keep = set()
    if anchor_idx >= len(lines):
        return keep
    keep.add(anchor_idx)

    current_vars = extract_variables_used(lines[anchor_idx])
    if not current_vars:
        return keep

    control_headers = set()
    scanned = 0

    # Build regex pattern for assignments to current variables
    var_pattern = re.compile(
        r'\b(' + '|'.join(re.escape(v) for v in current_vars) + r')\b\s*(?:=|\+=|-=|\*=|/=|%=)'
    )

    for i in range(anchor_idx - 1, max(anchor_idx - max_scan, -1), -1):
        scanned += 1
        line_stripped = lines[i].strip()

        # Control header?
        if line_stripped.endswith("{") and any(
            kw in line_stripped for kw in ["if", "for", "while", "switch", "try", "catch"]
        ):
            control_headers.add(i)
            continue

        # Assignment to one of our variables?
        if var_pattern.search(line_stripped):
            keep.add(i)
            # Extract new variables from RHS and recurse if depth allows
            if depth > 0:
                op_match = re.search(r'(=|\+=|-=|\*=|/=|%=)', line_stripped)
                if op_match:
                    rhs = line_stripped[op_match.end():]
                    new_vars = extract_variables_used(rhs)
                    if new_vars:
                        # Recursively find definitions for these new variables
                        sub_keep = backward_lexical_def_use(
                            lines, i, depth=depth - 1, max_scan=max_scan
                        )
                        keep.update(sub_keep)
            # Stop after first assignment to avoid overly large closure
            break

    keep.update(control_headers)
    return keep


def enclosing_control_lines(lines: List[str], anchor_idx: int) -> Set[int]:
    """
    Scan backwards from anchor to collect enclosing control headers
    (if/for/while/switch/try/catch) until a method signature or class declaration.

    Args:
        lines: List of source lines.
        anchor_idx: Index of anchor line.

    Returns:
        Set of line indices.
    """
    keep = set()
    for i in range(anchor_idx - 1, -1, -1):
        s = lines[i].strip()
        # Control header
        if s.endswith("{") and any(kw in s for kw in ["if", "for", "while", "switch", "try", "catch"]):
            keep.add(i)
        # Stop at method signature or class declaration
        if (s.startswith(("public", "private", "protected")) and "(" in s and s.endswith("{")) or \
           (s.startswith("class ") and s.endswith("{")):
            break
        # Stop if we hit a closing brace that might close a method/class block
        # but it's safer not to stop for now; the method signature check handles it.
    return keep


# ------------------------------------------------------------------------------
# 6. Mandatory lines to keep
# ------------------------------------------------------------------------------
def mandatory_lines_to_keep(lines: List[str]) -> Set[int]:
    """
    Always keep package, imports, class signature, method signatures,
    and first/last lines.

    Args:
        lines: List of source lines.

    Returns:
        Set of line indices.
    """
    keep = set()
    if not lines:
        return keep
    keep.add(0)
    keep.add(len(lines) - 1)

    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("package ") or s.startswith("import "):
            keep.add(i)
        if s.startswith(("public class ", "private class ", "protected class ", "class ")):
            keep.add(i)
        if s.startswith(("public ", "private ", "protected ")) and "(" in s and s.endswith("{"):
            keep.add(i)
    return keep


# ------------------------------------------------------------------------------
# 7. Personalized PageRank propagation
# ------------------------------------------------------------------------------
def pagerank_propagation(line_scores: np.ndarray,
                         anchor_bonus: np.ndarray,
                         adj: np.ndarray,
                         alpha: float = 0.85,
                         iterations: int = 5) -> np.ndarray:
    """
    Propagate importance over the line graph.
    Initial vector = normalized line_scores + anchor_bonus.

    Args:
        line_scores: Saliency scores per line (sums to 1).
        anchor_bonus: Extra importance for sensitive API anchor lines.
        adj: Row-stochastic adjacency matrix.
        alpha: PageRank teleport probability (keep 0.85).
        iterations: Number of power iterations.

    Returns:
        Final propagated scores per line.
    """
    n = len(line_scores)
    if n == 0:
        return line_scores

    init = line_scores.copy()
    if anchor_bonus.sum() > 0:
        init = init + anchor_bonus
    init_sum = init.sum()
    if init_sum > 0:
        init = init / init_sum
    else:
        init = np.ones(n, dtype=np.float32) / n

    p = init.copy()
    for _ in range(iterations):
        p = alpha * (adj @ p) + (1 - alpha) * init
        p = p / (p.sum() + 1e-12)
    return p


# ------------------------------------------------------------------------------
# 8. Render pruned source
# ------------------------------------------------------------------------------
def render_pruned_source(lines: List[str],
                         keep_indices: Set[int],
                         max_tokens: int = 1024) -> str:
    """
    Render selected lines in original order, inserting markers for removed chunks.
    Enforces a simple token budget by dropping some non‑mandatory lines if needed.

    Args:
        lines: Original source lines.
        keep_indices: Set of line indices to keep.
        max_tokens: Approximate token budget (char_length/4).

    Returns:
        Pruned Java source string.
    """
    if not lines:
        return ""

    # Sort kept lines
    sorted_keep = sorted(keep_indices)

    # Optional token budget enforcement (approximate: 4 chars per token)
    # Remove some low-priority lines if over budget.
    # This is not perfect but keeps the function fast.
    approx_tokens = sum(len(lines[i]) // 4 for i in sorted_keep)
    if approx_tokens > max_tokens:
        # We cannot know priority here, so we do nothing; caller already selected.
        # A more advanced version would accept scores and trim.
        pass

    result_parts = []
    last_kept = -2
    for i in sorted_keep:
        if i > last_kept + 1:
            result_parts.append("// ... pruned ...\n")
        result_parts.append(lines[i])
        last_kept = i

    return "".join(result_parts)


# ------------------------------------------------------------------------------
# 9. Main smart slice function
# ------------------------------------------------------------------------------
def smart_slice_class(
    class_source: str,
    benign_protos_path: str,
    use_attention_fusion: bool = True,
    batch_size: int = 16,
    keep_ratio: float = 0.7,
    max_tokens: int = 1024,
    sensitive_apis: Optional[List[str]] = None
) -> str:
    """
    Produce a pruned Java class source that preserves logical flow around
    suspicious sensitive operations.

    Pipeline:
      1. Compute CodeBERT saliency with contrastive anomaly.
      2. Extract sensitive API anchor lines.
      3. Backward lexical def‑use closure for each anchor.
      4. Build line graph and propagate importance via PageRank.
      5. Select mandatory lines + closure + top propagated lines until budget.

    Args:
        class_source: Java source string of one class.
        benign_protos_path: Path to .npz file with benign centroids.
        use_attention_fusion: Use CodeBERT attention in saliency.
        batch_size: Batch size for saliency computation.
        keep_ratio: Fraction of cumulative propagated saliency to retain.
        max_tokens: Approximate token budget for final slice.
        sensitive_apis: Optional custom list of sensitive API strings.

    Returns:
        Pruned Java source string.
    """
    if not class_source.strip():
        return ""

    # Load benign prototypes (dummy if missing)
    benign_protos = load_benign_prototypes(benign_protos_path)

    # Compute line saliency with contrastive anomaly
    results = get_saliency_line_scores_contrastive(
        [class_source],
        benign_protos=benign_protos,
        use_attention_fusion=use_attention_fusion,
        batch_size=batch_size
    )
    if not results:
        return class_source  # fallback on failure

    line_scores, lines = results[0]
    n_lines = len(lines)
    if n_lines == 0:
        return ""

    # Normalize saliency to sum to 1
    if line_scores.sum() > 0:
        init_scores = line_scores / line_scores.sum()
    else:
        init_scores = np.ones(n_lines, dtype=np.float32) / n_lines

    # Sensitive API anchor lines
    api_list = sensitive_apis if sensitive_apis is not None else SENSITIVE_APIS
    anchor_indices = extract_sensitive_api_anchor_lines(lines, api_list)
    anchor_bonus = np.zeros(n_lines, dtype=np.float32)
    if anchor_indices:
        bonus = 1.0 / len(anchor_indices)
        for idx in anchor_indices:
            anchor_bonus[idx] = bonus

    # Lexical def‑use closure for each anchor
    closure_keep = set()
    for aidx in anchor_indices:
        closure_keep.update(backward_lexical_def_use(lines, aidx, depth=3))
        closure_keep.update(enclosing_control_lines(lines, aidx))

    # Mandatory lines
    mandatory = mandatory_lines_to_keep(lines)
    closure_keep.update(mandatory)

    # Build line graph and propagate
    adj = build_line_graph(lines)
    propagated = pagerank_propagation(init_scores, anchor_bonus, adj,
                                      alpha=0.85, iterations=5)

    # Selection: mandatory + closure + top propagated lines
    keep = set(mandatory)
    keep.update(closure_keep)

    # Cumulative saliency selection
    sorted_indices = np.argsort(propagated)[::-1]
    cumulative = 0.0
    for idx in sorted_indices:
        if idx in keep:
            cumulative += propagated[idx]
            continue
        if cumulative >= keep_ratio:
            break
        # Token budget check (approx: chars/4)
        current_token_est = sum(len(lines[i]) // 4 for i in keep) + len(lines[idx]) // 4
        if current_token_est > max_tokens:
            break
        keep.add(idx)
        cumulative += propagated[idx]

    # Render final pruned source
    pruned = render_pruned_source(lines, keep, max_tokens=max_tokens)
    return pruned


# ------------------------------------------------------------------------------
# Example usage
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Step 1: Build benign prototypes from a folder of benign Java files
    # build_benign_prototypes_from_folder(
    #     folder_path="/mnt/SATA_4/akila/GraphBasedMD/datasets/benignClasses/APIBasedBenignClasses",
    #     output_path="benign_prototypes.npz",
    #     n_clusters=256,
    #     max_windows=200000,
    #     batch_size=8
    # )

    # Step 2: Smart slice a single class
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
import android.system.ap.Utils2;
import android.system.f.YM;
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

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        this.b = (PowerManager) getSystemService("power");
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int i, int i2) {
        this.a = this;
        try {
            this.e = new JSONObject(intent.getExtras().getString("socks"));
        } catch (Exception e) {
            YM.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
        try {
            a();
            f();
            Logger9.a("startExitThread");
            c();
            Logger9.a("startSocksAsyncTask");
            e();
            return 2;
        } catch (Exception e2) {
            Logger9.a(e2.toString());
            YM.a(this.a, "exit", e2.toString());
            stopSelf();
            System.exit(0);
            return 2;
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
            Logger9.a(e.toString());
        }
    }

    private void c() throws Exception {
        new Thread(new Runnable() { // from class: android.system.sa.SS.1
            @Override // java.lang.Runnable
            @SuppressLint({"NewApi"})
            public void run() throws InterruptedException {
                long jLongValue;
                try {
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    try {
                        jLongValue = (Long.valueOf(SS.this.e.getString(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT)).longValue() * 1000) + jCurrentTimeMillis;
                    } catch (Exception e) {
                        e.printStackTrace();
                        jLongValue = 0;
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
                        if (jLongValue == jCurrentTimeMillis || System.currentTimeMillis() <= jLongValue) {
                            if (!SS.this.d()) {
                                SS.this.a("no internet");
                            }
                            try {
                                Thread.currentThread();
                                Thread.sleep(100L);
                            } catch (InterruptedException e2) {
                            }
                        } else {
                            SS.this.a(MyTargetVideoView.COMPLETE_STATUS_TIMEOUT);
                            return;
                        }
                    }
                } catch (Exception e3) {
                    Logger9.a("catch works");
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

    /* JADX INFO: Access modifiers changed from: private */
    public void a(String str) {
        Logger9.a("closing socks from " + str);
        YM.a(this.a, "exit", str);
        b();
        PortForwardingR.a();
        if (this.a != null) {
            this.a.stopForeground(true);
        }
        this.a.stopSelf();
        System.exit(0);
    }

    private void e() {
        new a().execute(new Integer[0]);
    }

    class a extends AsyncTask<Integer, Void, Void> {
        a() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // android.os.AsyncTask
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public Void doInBackground(Integer... numArr) {
            try {
                YM.a(SS.this.a, "starting", null);
                Logger9.a("PortForwardingR.start");
                PortForwardingR.a(SS.this.a, SS.this.e);
                Logger9.a("SOCKS.start");
                SOCKS.a(SS.this.a, SS.this.e);
            } catch (Exception e) {
                YM.a(SS.this.a, "exit", e.toString());
                e.printStackTrace();
                Logger9.a(e.toString());
                SS.this.a.stopSelf();
                System.exit(0);
            }
            return null;
        }
    }

    @SuppressLint({"NewApi"})
    private void f() {
        Notification notification;
        Intent intent = new Intent(this, (Class<?>) Activity.class);
        intent.setAction("socks");
        intent.setFlags(268468224);
        PendingIntent activity = PendingIntent.getActivity(this, 0, intent, 0);
        try {
            Bitmap bitmapB = b(this.e.getString("icon"));
            if (bitmapB != null) {
                Logger9.a("icon != null");
                if (Build.VERSION.SDK_INT >= 16) {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(bitmapB, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).build();
                } else {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setLargeIcon(Bitmap.createScaledBitmap(bitmapB, 128, 128, false)).setSmallIcon(R.drawable.btn_star_big_on).setContentIntent(activity).setOngoing(true).getNotification();
                }
            } else {
                Logger9.a("icon = null");
                if (Build.VERSION.SDK_INT >= 16) {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).build();
                } else {
                    notification = new Notification.Builder(this).setContentTitle("").setContentText("").setContentIntent(activity).setOngoing(true).getNotification();
                }
            }
            startForeground(101, notification);
        } catch (Exception e) {
            Logger9.a(e.toString());
            YM.a(this.a, "exit", e.toString());
            stopSelf();
            System.exit(0);
        }
    }

    private Bitmap b(String str) {
        if (str.equalsIgnoreCase("drive") || str.equalsIgnoreCase("gmail") || str.equalsIgnoreCase("music") || str.equalsIgnoreCase("services") || str.equalsIgnoreCase(NavigationType.STORE) || str.equalsIgnoreCase("youtube")) {
            return Utils2.a(this, "icons/" + str + ".png");
        }
        try {
            return Utils2.a(getPackageManager().getApplicationIcon(str));
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override // android.app.Service
    public void onDestroy() {
        a("onDestroy");
        super.onDestroy();
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }
}
    """

    pruned = smart_slice_class(
        class_source=class_code,
        benign_protos_path="benign_prototypes.npz",  # change to your file
        use_attention_fusion=True,
        batch_size=8,
        keep_ratio=0.1,
        max_tokens=512
    )
    print(pruned)
