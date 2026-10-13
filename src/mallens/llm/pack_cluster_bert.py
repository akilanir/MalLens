from __future__ import annotations

from pathlib import Path

from mallens.core.datatypes import Cluster, Stage1Result, Stage2Result, Stage3Result
from mallens.utils.pre_processing import preprocess_java_code, parse_java_blocks
from mallens.config import Config

import torch
import numpy as np
from collections import defaultdict
from transformers import AutoTokenizer, AutoModel

# MODEL_NAME = "microsoft/codebert-base"

# # Assume tokenizer and model are already loaded globally:
# tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
# model = AutoModel.from_pretrained(MODEL_NAME, output_attentions=True)

# device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
# print(f"LOADING: {MODEL_NAME} to DEVICE: {device}")
# model = model.to(device)
# model.eval()   # set to inference mode (disables dropout, etc.)


def char_to_line(char_idx, line_ends):
    """Given char index and array of cumulative line ends, return 0‑based line index."""
    for i, end in enumerate(line_ends):
        if char_idx < end:
            return i
    return len(line_ends) - 1


def get_line_scores_batched(java_codes: list[str], batch_max: int = 16):
    if not java_codes:
        return []

    # ---- 1. Tokenize all codes and collect windows -----------------
    all_windows = []          # list of token-ID lists (CPU)
    window_meta = []          # (class_idx, start_orig, end_orig)
    class_data = []           # per class: (offset_mapping, line_ends, total_tokens, lines)

    for cls_idx, code in enumerate(java_codes):
        enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False)
        input_ids = enc["input_ids"] # - id-token, id-token so the code is tokenised and each token has a id
        offset_mapping = enc["offset_mapping"]
        tokens = tokenizer.convert_ids_to_tokens(input_ids)

        lines = code.splitlines(keepends=True)
        line_ends = np.cumsum([len(line) for line in lines])

        total_tokens = len(input_ids) # number of token ids
        max_len = 512
        stride = 256

        for start in range(0, total_tokens, stride):
            end = min(start + max_len - 2, total_tokens)
            if end - start < 1:
                break
            window_ids = [tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id]
            all_windows.append(window_ids)
            window_meta.append((cls_idx, start, end))

        class_data.append((offset_mapping, line_ends, total_tokens, lines))

    # ---- 2. Prepare accumulators -----------------------------------
    num_classes = len(java_codes)
    token_score_sum = [np.zeros(data[2]) for data in class_data]
    token_score_cnt = [np.zeros(data[2], dtype=int) for data in class_data]

    # ---- 3. Process windows in mini‑batches ------------------------
    num_windows = len(all_windows)
    device = next(model.parameters()).device

    for chunk_start in range(0, num_windows, batch_max):
        chunk_end = min(chunk_start + batch_max, num_windows)
        chunk_windows = all_windows[chunk_start:chunk_end]
        chunk_meta = window_meta[chunk_start:chunk_end]

        # Pad inside this chunk
        max_wlen = max(len(w) for w in chunk_windows)
        batch_ids = torch.zeros((len(chunk_windows), max_wlen), dtype=torch.long, device=device)
        batch_masks = torch.zeros((len(chunk_windows), max_wlen), dtype=torch.long, device=device)
        for i, w in enumerate(chunk_windows):
            batch_ids[i, :len(w)] = torch.tensor(w, device=device)
            batch_masks[i, :len(w)] = 1

        # Forward pass
        with torch.no_grad():
            outputs = model(input_ids=batch_ids, attention_mask=batch_masks)
        avg_attn = outputs.attentions[-1].mean(dim=1)  # (chunk_size, seq_len, seq_len)

        # Accumulate per‑token scores
        for i_rel, (cls_idx, start, end) in enumerate(chunk_meta):
            attn_matrix = avg_attn[i_rel]
            content_len = end - start
            for pos_in_window in range(1, content_len + 1):
                orig_idx = start + pos_in_window - 1
                score = attn_matrix[:, pos_in_window].sum().item()
                token_score_sum[cls_idx][orig_idx] += score
                token_score_cnt[cls_idx][orig_idx] += 1

        # Free GPU tensors for this chunk
        del batch_ids, batch_masks, avg_attn, outputs
        torch.cuda.empty_cache()

    # ---- 4. Average and map to lines -------------------------------
    results = []
    for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
        scores = token_score_sum[cls_idx]
        cnts = token_score_cnt[cls_idx]
        mask = cnts > 0
        token_scores = np.zeros(total_tok)
        token_scores[mask] = scores[mask] / cnts[mask]

        line_scores = np.zeros(len(lines))
        for token_idx, (start_char, end_char) in enumerate(offset_map):
            if start_char == end_char == 0:
                continue
            line_idx = char_to_line(start_char, line_ends)
            line_scores[line_idx] += token_scores[token_idx]

        results.append((line_scores, lines))

    return results


def attention_slice_batched(java_codes: list[str], keep_ratio=0.7) -> list[str]:
    """
    For each code, keeps lines whose cumulative attention score reaches keep_ratio.
    Returns list of sliced source strings (one per input code).
    """
    batch_results = get_line_scores_batched(java_codes)
    sliced = []
    for line_scores, lines in batch_results:
        total_score = line_scores.sum()
        if total_score == 0 or len(lines) == 0:
            # fallback: keep first keep_ratio of lines
            keep_n = max(1, int(len(lines) * keep_ratio))
            kept = list(range(len(lines)))[:keep_n]
        else:
            sorted_indices = np.argsort(line_scores)[::-1]
            running = 0
            kept = []
            for idx in sorted_indices:
                running += line_scores[idx]
                kept.append(idx)
                if running / total_score >= keep_ratio:
                    break
        kept.sort()
        sliced.append("".join(lines[i] for i in kept))
    return sliced


def pack_cluster_with_graph(cluster: Cluster, s1: "Stage1Result", s2: Stage2Result, s3: Stage3Result, char_budget: int, cfg: Config):
    debug = False
    parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
    # ------------------------------------------------------------
    # 1. Graph overview (unchanged)
    # ------------------------------------------------------------
    cluster_graph = s1.graph.subgraph(cluster.class_names)
    edges_str = []
    for caller in cluster.class_names:
        if caller in cluster_graph:
            callees = list(cluster_graph.successors(caller))
            callees_in = [dst for dst in callees if dst in cluster.class_names]
            if callees_in:
                edges_str.append(f"- {caller} → {', '.join(callees_in)}")
    parts.append("\n## GRAPH OVERVIEW")
    if edges_str:
        parts.extend(edges_str)
    else:
        parts.append("Single Class Cluster")

    # if debug:
    #     print("Requested:", len(cluster.class_names))
    #     print("Subgraph:", cluster_graph.number_of_nodes())
    #     print("Nodes:", list(cluster_graph.nodes()))
    #     cluster_id = getattr(cluster, 'cluster_id', 'unknown')
    #     _save_cluster_subgraph(cluster_graph, str(cluster_id), Path("/mnt/SATA_3/akila/AK_PHD3/droidlens3/cluster_graphs"))

    weights = [max(0.05, s3.scores.get(c, 0.0)) for c in cluster.class_names]
    total_w = sum(weights)

    # We'll process only classes that have a readable .java file.
    # Keep indices to map back.
    class_sources = []           # list of raw source strings
    class_indices = []           # position in the original cluster.class_names
    class_recs = []              # record for each source‑available class
    class_weights = []           # corresponding weight for budget calculation

    for i, c in enumerate(cluster.class_names):
        rec = s2.records.get(c)
        if rec is None or not rec.java_path:
            # We'll still output a placeholder later, but skip batched slicing
            continue
        try:
            raw_src = Path(rec.java_path).read_text(encoding="utf-8", errors="replace")
            src_clean = preprocess_java_code(raw_src)
            class_sources.append(src_clean)
            class_indices.append(i)
            class_recs.append(rec)
            class_weights.append(weights[i])
        except OSError:
            # Source unreadable – handle in the final loop
            pass

    # ---- Run batched attention slicing on all valid classes ----
    if class_sources:
        sliced_sources = attention_slice_batched(class_sources, keep_ratio=0.7)  # adjust keep_ratio as needed
    else:
        sliced_sources = []

    # ------------------------------------------------------------
    # 3. Assemble the output, distributing sliced sources back
    # ------------------------------------------------------------
    parts.append("\n## DECOMPILED ATTENTION BASED IMPORTANT SOURCES:")

    # We need to map from class_indices back to the original cluster.class_names order
    sliced_map = dict(zip(class_indices, sliced_sources))

    for i, c in enumerate(cluster.class_names):
        rec = s2.records.get(c)
        share = int(char_budget * weights[i] / total_w)
        parts.append(f"\n### Class: {c}")

        if rec is None or not rec.java_path:
            parts.append("(no decompiled source available)")
            continue

        # Use the batched sliced source if available, otherwise fallback
        sliced_code = sliced_map.get(i)
        if sliced_code is None:
            try:
                raw_src = Path(rec.java_path).read_text(encoding="utf-8", errors="replace")
                raw_src = preprocess_java_code(raw_src)
                # fallback single‑class for unbatched cases (should not happen)
                raw_src = attention_slice(raw_src)
                sliced_code = raw_src
            except OSError:
                parts.append("(source unreadable)")
                continue

        src = sliced_code
        if len(src) > share:
            src = src[:share] + f"\n// [truncated {len(src) - share} chars]"
        parts.append("```java\n" + src + "\n```")

        # Graph connections
        block = "## GRAPH CONNECTIONS: \n"
        if c in cluster_graph:
            callees = list(cluster_graph.successors(c))
            callees_in_cluster = [dst for dst in callees if dst in cluster.class_names]
            if callees_in_cluster:
                block += f"\nCalls: {', '.join(callees_in_cluster)}"
        parts.append(block)

    torch.cuda.empty_cache()
    return "\n".join(parts)


#--------------------------------------------------
def pack_cluster_class_blocks_with_graph(cluster: Cluster, s1: "Stage1Result", s2: Stage2Result, s3: Stage3Result, char_budget: int, cfg: Config):
    debug = False
    # parts = []
    parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
    # ------------------------------------------------------------
    # 1. Graph overview (unchanged)
    # ------------------------------------------------------------
    cluster_graph = s1.graph.subgraph(cluster.class_names)
    edges_str = []
    for caller in cluster.class_names:
        if caller in cluster_graph:
            callees = list(cluster_graph.successors(caller))
            callees_in = [dst for dst in callees if dst in cluster.class_names]
            if callees_in:
                edges_str.append(f"- {caller} → {', '.join(callees_in)}")
    parts.append("\n## GRAPH OVERVIEW")
    if edges_str:
        parts.extend(edges_str)
    else:
        parts.append("Single Class Cluster")

    weights = [max(0.05, s3.scores.get(c, 0.0)) for c in cluster.class_names]
    total_w = sum(weights)

    # We'll process only classes that have a readable .java file.
    # Keep indices to map back.
    class_sources = []           # list of raw source strings
    class_indices = []           # position in the original cluster.class_names
    class_recs = []              # record for each source‑available class
    class_weights = []           # corresponding weight for budget calculation

    parts.append("\n## DECOMPILED ATTENTION BASED IMPORTANT SOURCES:")

    for i, c in enumerate(cluster.class_names):
        rec = s2.records.get(c)
        share = int(char_budget * weights[i] / total_w)
        parts.append(f"\n### Class: {c}")
        if rec is None or not rec.java_path:
            # We'll still output a placeholder later, but skip batched slicing
            continue
        try:
            raw_src = Path(rec.java_path).read_text(encoding="utf-8", errors="replace")
            src_clean = preprocess_java_code(raw_src)
            # print("PARSING TO JAVA BLOCKS...")
            blocks = parse_java_blocks(src_clean) # We have blocks here list[] -> we divide each class into HEADER, METHOD_1, METHOD_2...
            src_blocks: list[str] = [b["text"] for b in blocks if b["type"] == "METHOD" and b["text"]]
            # print(f"jAVA BLOCKS PARSED WITH: {len(src_blocks)} blocks")
            # Now we get the important lines of each block
            sliced_blocks = attention_slice_batched(src_blocks, keep_ratio=0.7)
            class_code_attention = "\n".join(sliced_blocks)

            original_l = len(src_clean)
            attent_l = len(class_code_attention)
            # print(f"We reduced from {original_l} --> {attent_l}")

            if len(class_code_attention) > share:
                class_code_attention = class_code_attention[:share] + f"\n// [truncated {len(class_code_attention) - share} chars]"
            parts.append("```java\n" + class_code_attention + "\n```")

        except OSError:
            # Source unreadable – handle in the final loop
            pass

        # Graph connections
        block = "## GRAPH CONNECTIONS: \n"
        if c in cluster_graph:
            callees = list(cluster_graph.successors(c))
            callees_in_cluster = [dst for dst in callees if dst in cluster.class_names]
            if callees_in_cluster:
                block += f"Calls: {', '.join(callees_in_cluster)}"
        parts.append(block)

    torch.cuda.empty_cache()
    return "\n".join(parts)



#### FALLBACK ---------
def get_line_scores(java_code):
    # 1. Tokenize with offsets
    enc = tokenizer(java_code, return_offsets_mapping=True, add_special_tokens=False)
    input_ids = enc["input_ids"]
    offset_mapping = enc["offset_mapping"]  # list of (start, end) char positions
    tokens = tokenizer.convert_ids_to_tokens(input_ids)

    # 2. Build char->line mapping
    lines = java_code.splitlines(keepends=True)  # keep line breaks for exact offset matching
    # Compute cumulative char positions of line ends
    line_ends = np.cumsum([len(line) for line in lines])
    def char_to_line(char_idx):
        # returns 0-based line index for a character position
        for i, end in enumerate(line_ends):
            if char_idx < end:
                return i
        return len(lines) - 1

    # 3. Sliding window parameters
    max_len = 512
    stride = 256
    total_tokens = len(input_ids)
    # Initialize accumulation of scores per original token
    token_score_sum = np.zeros(total_tokens)
    token_window_counts = np.zeros(total_tokens, dtype=int)

    # 4. Iterate over windows
    for start in range(0, total_tokens, stride):
        end = start + max_len - 2  # reserve space for [CLS] and [SEP]
        if end > total_tokens:
            end = total_tokens
        # Avoid tiny windows at the end
        if end - start < 1:
            break

        # Prepare window input with special tokens
        window_ids = [tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id]
        window_mask = [1] * len(window_ids)
        # Map positions in window to original token indices (for content tokens)
        window_to_orig = list(range(start, end))  # length = end-start

        # Run model
        with torch.no_grad():
            outputs = model(input_ids=torch.tensor([window_ids]),
                            attention_mask=torch.tensor([window_mask]))
        attn = outputs.attentions[-1][0]  # last layer, batch index 0; shape (heads, seq_len, seq_len)
        # Average over heads
        attn = attn.mean(dim=0)  # (seq_len, seq_len)

        # Extract scores for content tokens only (ignore [CLS], [SEP])
        # Content tokens are positions 1..(len(window_ids)-2)
        for pos_in_window, orig_idx in enumerate(window_to_orig):
            # Score = sum of attention from all positions to this token (column sum)
            token_score = attn[:, pos_in_window+1].sum().item()  # +1 because of [CLS]
            token_score_sum[orig_idx] += token_score
            token_window_counts[orig_idx] += 1

    # 5. Average scores per token (avoid bias towards tokens in many windows)
    mask = token_window_counts > 0
    token_scores = np.zeros(total_tokens)
    token_scores[mask] = token_score_sum[mask] / token_window_counts[mask]

    # 6. Map tokens to lines
    line_scores = np.zeros(len(lines))
    for token_idx, (start_char, end_char) in enumerate(offset_mapping):
        # Skip special tokens that get offset (0,0) e.g., padding
        if start_char == end_char == 0:
            continue
        line_idx = char_to_line(start_char)  # use start of token
        line_scores[line_idx] += token_scores[token_idx]

    # 7. Optionally boost lines with critical API calls (hard-coded list)
    critical_keywords = ["exec", "loadLibrary", "Cipher", "SmsMessage", "getMessageBody",
                         "createFromPdu", "openConnection", "send"]
    boost = 0.0  # or small constant like 0.01 to slightly favor them
    for i, line in enumerate(lines):
        if any(kw in line for kw in critical_keywords):
            line_scores[i] += boost

    return line_scores, lines

def attention_slice(java_code, keep_ratio=0.7):
    line_scores, lines = get_line_scores(java_code)
    # Determine threshold: keep lines whose cumulative score is within top keep_ratio
    sorted_indices = np.argsort(line_scores)[::-1]  # descending
    total_score = line_scores.sum()
    if total_score == 0:
        # fallback: keep first keep_ratio of lines (not ideal)
        keep_n = max(1, int(len(lines) * keep_ratio))
        kept = list(range(len(lines)))[:keep_n]
    else:
        running = 0
        kept = []
        for idx in sorted_indices:
            running += line_scores[idx]
            kept.append(idx)
            if running / total_score >= keep_ratio:
                break
    kept.sort()  # restore reading order
    sliced_code = "".join(lines[i] for i in kept)
    return sliced_code






# def get_line_scores_batched(java_codes: list[str]):
#     """
#     Returns a list of (line_scores, lines) for each input code.
#     All sliding windows are packed into one big batch for a single model call.
#     """
#     if not java_codes:
#         return []

#     # ---- 1. Tokenize all codes and prepare windows -----------------
#     all_windows = []          # list of window token ID lists
#     window_meta = []          # (class_idx, start_orig, end_orig)
#     class_data = []           # per class: (offset_mapping, line_ends, total_tokens, lines)

#     for cls_idx, code in enumerate(java_codes):
#         enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False)
#         input_ids = enc["input_ids"]
#         offset_mapping = enc["offset_mapping"]
#         tokens = tokenizer.convert_ids_to_tokens(input_ids)

#         lines = code.splitlines(keepends=True)
#         line_ends = np.cumsum([len(line) for line in lines])

#         total_tokens = len(input_ids)
#         max_len = 512
#         stride = 256

#         for start in range(0, total_tokens, stride):
#             end = min(start + max_len - 2, total_tokens)
#             if end - start < 1:
#                 break
#             window_ids = [tokenizer.cls_token_id] + input_ids[start:end] + [tokenizer.sep_token_id]
#             all_windows.append(window_ids)
#             window_meta.append((cls_idx, start, end))

#         class_data.append((offset_mapping, line_ends, total_tokens, lines))

#     # ---- 2. Pad and batch windows ---------------------------------
#     max_wlen = max(len(w) for w in all_windows)
#     device = next(model.parameters()).device
#     batch_ids = torch.zeros((len(all_windows), max_wlen), dtype=torch.long, device=device)
#     batch_masks = torch.zeros((len(all_windows), max_wlen), dtype=torch.long, device=device)
#     for i, w in enumerate(all_windows):
#         batch_ids[i, :len(w)] = torch.tensor(w, device=device)
#         batch_masks[i, :len(w)] = 1

#     # ---- 3. Single model forward pass -----------------------------
#     with torch.no_grad():
#         outputs = model(input_ids=batch_ids, attention_mask=batch_masks)
#     # Average all heads of the last layer → (batch, seq_len, seq_len)
#     avg_attn = outputs.attentions[-1].mean(dim=1)

#     # ---- 4. Accumulate per‑token scores per class ------------------
#     num_classes = len(java_codes)
#     token_score_sum = [np.zeros(data[2]) for data in class_data]   # total_tokens
#     token_score_cnt = [np.zeros(data[2], dtype=int) for data in class_data]

#     for i, (cls_idx, start, end) in enumerate(window_meta):
#         attn_matrix = avg_attn[i]          # (seq_len, seq_len)
#         content_len = end - start          # number of original tokens in this window
#         # Column sums for content tokens (skip [CLS] at pos 0)
#         for pos_in_window in range(1, content_len + 1):
#             orig_idx = start + pos_in_window - 1
#             score = attn_matrix[:, pos_in_window].sum().item()  # all queries attend to this token
#             token_score_sum[cls_idx][orig_idx] += score
#             token_score_cnt[cls_idx][orig_idx] += 1

#     # ---- 5. Average and map to lines -------------------------------
#     results = []
#     for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
#         scores = token_score_sum[cls_idx]
#         cnts = token_score_cnt[cls_idx]
#         mask = cnts > 0
#         token_scores = np.zeros(total_tok)
#         token_scores[mask] = scores[mask] / cnts[mask]

#         line_scores = np.zeros(len(lines))
#         for token_idx, (start_char, end_char) in enumerate(offset_map):
#             if start_char == end_char == 0:
#                 continue
#             line_idx = char_to_line(start_char, line_ends)
#             line_scores[line_idx] += token_scores[token_idx]

#         results.append((line_scores, lines))

#     return results