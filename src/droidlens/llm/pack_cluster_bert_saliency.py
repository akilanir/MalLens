from pathlib import Path

from droidlens.core.datatypes import Cluster, Stage1Result, Stage2Result, Stage3Result
from droidlens.utils.pre_processing import preprocess_java_code, parse_java_blocks
from droidlens.config import Config
from droidlens.slicer.bert_pruner import prune_code_with_trained_model

import torch
import re
import numpy as np
from typing import List, Tuple
from transformers import AutoTokenizer, AutoModel

import os
OUTPUT_FOLDER = "graphcodebert_slicer"

# MODEL_NAME = "microsoft/codebert-base"
# MODEL_NAME = "microsoft/unixcoder-base"
MODEL_NAME = "microsoft/graphcodebert-base"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME, output_attentions=True, use_safetensors=True)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = model.to(device)
model.eval()  # inference mode (still allows gradient computation on inputs)

def char_to_line(start_char: int, line_ends: np.ndarray) -> int:
    for i, end in enumerate(line_ends):
        if start_char < end:
            return i
    return len(line_ends) - 1


def get_saliency_line_scores(
    java_codes: List[str],
    use_attention_fusion: bool = True,
    batch_size: int = 16
) -> List[Tuple[np.ndarray, List[str]]]:

    if not java_codes:
        return []

    all_windows = []
    window_meta = []
    class_data = []

    max_len = 512
    stride = 256

    cls_id = tokenizer.cls_token_id
    sep_id = tokenizer.sep_token_id
    # ---------------------------------------------------------
    # 1. Tokenize and create windows
    # ---------------------------------------------------------
    for cls_idx, code in enumerate(java_codes):
        enc = tokenizer(
            code,
            return_offsets_mapping=True,
            add_special_tokens=False,
            truncation=False
        )
        input_ids = enc["input_ids"]
        offset_map = enc["offset_mapping"]
        lines = code.splitlines(keepends=True)
        line_ends = np.cumsum([len(l) for l in lines])
        total_tokens = len(input_ids)
        for start in range(0, total_tokens, stride):
            end = min(start + max_len - 2, total_tokens)
            if end <= start:
                break
            window_ids = (
                [cls_id]
                + input_ids[start:end]
                + [sep_id]
            )
            all_windows.append(window_ids)
            window_meta.append((cls_idx, start, end))
        class_data.append((offset_map, line_ends, total_tokens, lines))
    # ---------------------------------------------------------
    # 2. Storage for token-level scores
    # ---------------------------------------------------------
    token_score_sum = [np.zeros(data[2], dtype=np.float32) for data in class_data]
    token_score_cnt = [np.zeros(data[2], dtype=np.int32) for data in class_data]
    # ---------------------------------------------------------
    # 3. Process windows in batches
    # ---------------------------------------------------------
    for batch_start in range(0, len(all_windows), batch_size):
        batch_windows = all_windows[batch_start:batch_start + batch_size]
        batch_meta = window_meta[batch_start:batch_start + batch_size]
        batch_max_len = max(len(x) for x in batch_windows)
        input_ids = torch.full(
            (len(batch_windows), batch_max_len),
            tokenizer.pad_token_id,
            dtype=torch.long,
            device=device
        )
        attention_mask = torch.zeros((len(batch_windows), batch_max_len),dtype=torch.long,device=device)
        # -----------------------------------------------------
        # Fill batch
        # -----------------------------------------------------
        for i, window in enumerate(batch_windows):
            length = len(window)
            input_ids[i, :length] = torch.tensor(
                window,
                dtype=torch.long,
                device=device
            )
            attention_mask[i, :length] = 1

        # -----------------------------------------------------
        # Input embeddings
        # -----------------------------------------------------
        embeddings = model.get_input_embeddings()(input_ids)
        embeddings.retain_grad()
        model.zero_grad(set_to_none=True)
        # -----------------------------------------------------
        # Mixed precision
        # -----------------------------------------------------
        with torch.autocast(
            device_type="cuda",
            dtype=torch.float16
        ):
            outputs = model(
                inputs_embeds=embeddings,
                attention_mask=attention_mask,
                output_attentions=use_attention_fusion
            )
            # CLS representation for each window
            cls_norm = outputs.last_hidden_state[:, 0, :].norm(
                dim=-1
            )
            # One backward pass for the whole batch
            loss = cls_norm.sum()
        loss.backward()
        # -----------------------------------------------------
        # Saliency
        # -----------------------------------------------------
        grad = embeddings.grad
        saliency = (
            embeddings.float() * grad.float()
        ).norm(dim=-1)
        # -----------------------------------------------------
        # Attention fusion
        # -----------------------------------------------------
        if use_attention_fusion:
            layer_indices = [6, 7, 8, 9]
            attn_weights = torch.zeros(
                embeddings.size(0),
                embeddings.size(1),
                device=device
            )
            for l_idx in layer_indices:
                layer_attn = outputs.attentions[l_idx]
                # Average over heads
                layer_attn = layer_attn.mean(dim=1)
                # CLS attention
                attn_weights += layer_attn[:, 0, :]
            attn_weights /= len(layer_indices)
            token_scores = saliency * attn_weights
        else:
            token_scores = saliency
        # -----------------------------------------------------
        # Move only final scores to CPU
        # -----------------------------------------------------
        token_scores = token_scores.detach().cpu().numpy()
        # -----------------------------------------------------
        # Map batch scores back to original tokens
        # -----------------------------------------------------
        for batch_idx, (cls_idx, start, end) in enumerate(batch_meta):
            content_len = end - start
            scores = token_scores[
                batch_idx,
                1:content_len + 1
            ]
            for pos, score in enumerate(scores):
                orig_idx = start + pos
                if orig_idx < len(token_score_sum[cls_idx]):
                    token_score_sum[cls_idx][orig_idx] += score
                    token_score_cnt[cls_idx][orig_idx] += 1
        # -----------------------------------------------------
        # Free batch tensors
        # -----------------------------------------------------
        del (input_ids, attention_mask, embeddings, outputs, grad, loss)
    # ---------------------------------------------------------
    # 4. Aggregate token scores → line scores
    # ---------------------------------------------------------
    results = []
    for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
        scores = token_score_sum[cls_idx]
        cnts = token_score_cnt[cls_idx]
        mask = cnts > 0
        token_scores_final = np.zeros(total_tok, dtype=np.float32)
        token_scores_final[mask] = (scores[mask] / cnts[mask])
        line_scores = np.zeros(len(lines), dtype=np.float32)

        # Added to average the token score
        line_token_count = np.zeros(len(lines), dtype=np.int32) #Calculate line token count
        for token_idx, (start_char, end_char) in enumerate(offset_map):
            if start_char == 0 and end_char == 0:
                continue
            line_idx = char_to_line(start_char, line_ends)
            line_scores[line_idx] += (token_scores_final[token_idx]) # Line with many tokens can recieve an artificially high score even if each token has low importance
            # line_token_count[line_idx] += 1 #Indexing/Counting
        # Vectorized division: average score per line
        # line_scores = line_scores / np.maximum(line_token_count, 1)  # avoid division by zero
        results.append((line_scores, lines))
    return results


def load_sensitive_apis(filepath):
    patterns = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Example line format: android/webkit/WebView;->dispatchTouchEvent
            if '->' in line:
                class_part, method_part = line.split(',')[0].split('->')
                # class_name = class_part.split('/')[-1]  # e.g., WebView
                method_name = method_part.split('(')[0]  # e.g., dispatchTouchEvent
                # print(method_name)
                # patterns.append(class_name)
                method_name = method_name + "("
                patterns.append(method_name)
            else:
                # If line is just a class name, use as is
                patterns.append(line.split('/')[-1])
    # Remove duplicates and empty
    patterns = list(set(filter(None, patterns)))
    return patterns

# sensitive_apis = load_sensitive_apis("data/sens.txt")
# compiled_patterns = [re.compile(r'\b' + re.escape(api) + r'\b') for api in sensitive_apis]


# def is_sensitive_line(line):
    # return any(p.search(line) for p in compiled_patterns)


def saliency_slice_whole_class(class_source: str, keep_ratio=0.8, use_attention_fusion=True) -> str:
    # print(f"IMPORTANT: WE RUN WITH --------------------- {keep_ratio}")
    # if len(class_source) < 100 * 4:  # approximate 4 chars per token
    #     print(f"The class source is small -> No Pruning {len(class_source)}")
    #     return class_source
    line_scores, lines = get_saliency_line_scores([class_source], use_attention_fusion, batch_size=32)[0]
    if len(lines) == 0:
        return ""

    # Normalize scores
    if line_scores.sum() > 0:
        norm_scores = line_scores / line_scores.sum()
    else:
        norm_scores = np.ones_like(line_scores) / len(line_scores)

    # 1. Collect lines that contain known risky patterns (mandatory keep)
    risky_patterns = [
        "System.exit", "stopSelf", "stopForeground", "newWakeLock",
        "acquire", "release", "createWifiLock", "startService",
        "Runtime.exec", "ProcessBuilder", "getRuntime", "loadLibrary",
        "new Thread", "execute", "sendTextMessage", "getDeviceId",
        "getSubscriberId", "getSimSerialNumber", "getLine1Number"
    ]
    mandatory_lines = set()
    # for i, line in enumerate(lines):
    #     if is_sensitive_line(line):
    #         # print(f"Sensitive Line: {line}")
    #         mandatory_lines.add(i)
    #         break

    for i, line in enumerate(lines):
        for pat in risky_patterns:
            if pat in line:
                mandatory_lines.add(i)
                break

    # 2. Select top lines by cumulative score
    sorted_idx = np.argsort(norm_scores)[::-1]
    running = 0
    keep_indices = set(mandatory_lines)
    for idx in sorted_idx:
        running += norm_scores[idx]
        keep_indices.add(idx)
        if running >= keep_ratio:
            break
    # 3. Always keep first and last few lines (package/imports and closing brace)
    keep_indices.add(0)
    if len(lines) > 1:
        keep_indices.add(len(lines)-1)
    keep_indices = sorted(keep_indices)
    return "".join(lines[i] for i in keep_indices)



def saliency_slice_batched(java_codes: List[str], keep_ratio: float = 0.7,
                           min_lines_per_method: int = 3,
                           use_attention_fusion: bool = True) -> List[str]:
    all_scored = get_saliency_line_scores(java_codes, use_attention_fusion)
    sliced = []
    for line_scores, lines in all_scored:
        if len(lines) == 0:
            sliced.append("")
            continue

        # Normalize scores to [0,1]
        if line_scores.sum() > 0:
            norm_scores = line_scores / line_scores.sum()
        else:
            norm_scores = np.ones_like(line_scores) / len(line_scores)

        # Sort by score descending
        sorted_idx = np.argsort(norm_scores)[::-1]
        running = 0
        keep_indices = set()
        for idx in sorted_idx:
            running += norm_scores[idx]
            keep_indices.add(idx)
            if running >= keep_ratio:
                break

        # Always keep the first and last lines of each method (ensure context)
        # (We rely on the fact that method boundaries often align with line breaks; you can refine this)
        keep_indices.add(0)
        keep_indices.add(len(lines) - 1)
        # Keep a minimum number of lines with highest scores
        for idx in sorted_idx[:min_lines_per_method]:
            keep_indices.add(idx)

        keep_indices = sorted(keep_indices)
        sliced.append("".join(lines[i] for i in keep_indices))
    return sliced



# SYS = r"""
# You are an Java Android code analyser and code pruner.
# Your task is to reduce the supplied Java class and deobfuscate it while preserving ALL code that
# could help another LLM determine whether the class is malicious or benign.
# This is CODE PRUNING, NOT CODE SUMMARIZATION.

# RULES:
# 1. Output ONLY Java source code.
# 2. Preserve the original source code EXACTLY whenever possible.
# 3. Do not rewrite, simplify, refactor, or invent code.
# 4. Remove irrelevant imports, boilerplate, UI-only code, logging, formatting
#    details, and unrelated exception handling.
# 5. KEEP complete methods when they contain security-relevant behavior.
# 6. KEEP method calls to helper classes if those calls may represent important
#    behavior, even when the helper implementation is unavailable.
# 7. KEEP the surrounding control flow needed to understand why those calls occur.
# 8. KEEP fields required to understand the retained behavior.
# 9. KEEP constructors/initialization when they establish security-relevant state.
# 10. KEEP Android lifecycle code when it starts, stops, hides, persists, or
#     controls suspicious behavior.
# 12. Remove code that contributes nothing to malware/benign classification.
# 13. Do NOT replace removed code with comments such as "// removed".
# 14. Do NOT produce explanations before or after the Java code.
# 15. The result must remain syntactically coherent Java as far as possible.
# 16. Preserve suspicious strings and constants because they may be important
#     evidence.
# 17. Preserve relationships between suspicious operations. Do not independently
#     remove pieces that make the behavior understandable.

# The goal is to produce a substantially smaller Java class (atleast 40-50% should be pruned) that retains the
# semantic evidence required for malware analysis.
# """

# PRO = """Input Class Soure code:
# {class_code}
# JUST PROVIDE THE PRUNED CODE NO NEED OF ANY EXPLANATION REQURED!!!!
# """


SYS ="""You are an expert Android code analyzer and aggressive code pruner for Java/Android malware analysis.
Given source code, delete at least 50% of the code.
Keep only code that helps decide whether the class is malicious or benign:
security-sensitive operations, suspicious strings/constants, and the control flow around them.
Preserve original code exactly for what remains; do not rewrite, summarize, or add comments.
Remove UI, logging, boilerplate, imports, and unrelated error handling.
Keep only imports/fields/method signatures needed by retained code.
If unsure, remove it.
Return only Java code, no explanation."""

PRO="""Input code:
{code}

Pruned Java code, at least 50% smaller, no explanation"""

from droidlens.llm.client import LLMClient

def pack_cluster_class_blocks_with_graph(cluster: Cluster, s1: "Stage1Result", s2: Stage2Result, s3: Stage3Result, char_budget: int, cfg: Config):
    client = LLMClient(cfg)
    import re
    debug = False
    # parts = []
    parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
    no_class_density = 0
    total_analyzed_classes = 0
    no_code_classes = 0
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
    cluster_class_data = {}

    parts.append("\n## DECOMPILED ATTENTION BASED IMPORTANT SOURCES:")

    for i, c in enumerate(cluster.class_names):
        safe_c = re.sub(r'[^a-zA-Z0-9_.-]', '_', c)
        filename = f"Cluster_{cluster.cluster_id}-sliced_comparison-{safe_c}.txt"
        filepath = os.path.join(OUTPUT_FOLDER,filename)
        rec = s2.records.get(c)
        share = int(char_budget * weights[i] / total_w)
        parts.append(f"\n### Class: {c}")
        if rec is None or not rec.java_path:
            print(f"{c} got no java path in the record..")
            class_code_attention = "No code found for this class"
            # We'll still output a placeholder later, but skip batched slicing
            continue
        java_path = rec.java_path
        try:
            if java_path in cluster_class_data:
                print(f"This class already analysed: {java_path}")
                class_code_attention = cluster_class_data[java_path]
            else:
                raw_src = Path(java_path).read_text(encoding="utf-8", errors="replace")
                src_clean = preprocess_java_code(raw_src)
                if len(src_clean) < 100:
                    print("No important code snippet found...")
                    class_code_attention = "No Important Code in this Class was found."
                else:
                    class_code_attention = saliency_slice_whole_class(src_clean,keep_ratio=0.7,use_attention_fusion=True)
                    # class_code_attention = src_clean
                    # class_code_attention = prune_code_with_trained_model(model_dir="/mnt/SATA_4/akila/vLLMTest/TrainBert/models/codebert_pruner", class_source=src_clean, keep_ratio=0.7)
                    # user = PRO.format(code=src_clean)
                    # print("--------- Calling LLM to prune....")
                    # try:
                    #     class_code_attention, usage = client.complete(SYS, user, model="qwen3.5:9b-q8_0")
                    #     class_code_attention = str(class_code_attention)
                    # except Exception as e:
                    #     print(f"Exception during llm: {e}")
                    #     class_code_attention = "Error in class pruning. Ommit this class"
                    #     usage = None
                cluster_class_data[java_path]=class_code_attention
            
            with open(filepath,"w",encoding="utf-8") as f:
                # print(f"IMPORNTANT WRITING: {filepath}")
                f.write("Raw Code ----\n")
                f.write(raw_src)
                f.write("\n\n")
                f.write("="*100)
                f.write("\nClean Code ----\n")
                f.write(src_clean)
                f.write("\n\n")
                f.write("="*100)
                f.write("\n Sliced  Code (saliency) --------------\n")
                f.write(class_code_attention)
                # f.write("\n\n")
                # f.write("="*100)
                # f.write("\n USAGE --------------\n")
                # f.write(str(usage))
                
            original_l = len(src_clean)
            attent_l = len(class_code_attention)
            # print(f"We reduced from: {original_l} -> {attent_l}")

            if len(class_code_attention) > share:
                class_code_attention = class_code_attention[:share] + f"\n// [truncated {len(class_code_attention) - share} chars]"
            length_after_pruning = len(class_code_attention)
            if length_after_pruning == 0:
                no_code_classes += 1
            total_analyzed_classes += 1
            parts.append("```java\n" + class_code_attention + "\n```")

        except OSError as error:
            print(f"PARSING EXCEPTION.....{error}")
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
    # no_class_density = no_code_classes/total_analyzed_classes #How many classes from total classes got data
    
    return "\n".join(parts), total_analyzed_classes




# def saliency_slice_batched(java_codes: List[str], keep_ratio: float = 0.7, use_attention_fusion: bool = True) -> List[str]:
#     """
#     For each Java code, keep lines that contain `keep_ratio` of total line saliency score.
#     Returns list of sliced source strings.
#     """
#     all_scored = get_saliency_line_scores(java_codes, use_attention_fusion)
#     sliced = []
#     for line_scores, lines in all_scored:
#         if len(lines) == 0 or line_scores.sum() == 0:
#             # fallback: keep all lines
#             keep_indices = list(range(len(lines)))
#         else:
#             # Sort by score descending, accumulate until ratio reached
#             sorted_idx = np.argsort(line_scores)[::-1]
#             running = 0
#             keep_indices = []
#             for idx in sorted_idx:
#                 running += line_scores[idx]
#                 keep_indices.append(idx)
#                 if running / line_scores.sum() >= keep_ratio:
#                     break
#             keep_indices.sort()
#         sliced.append("".join(lines[i] for i in keep_indices))
#     return sliced


# def get_saliency_line_scores(java_codes: list[str],
#                              use_attention_fusion: bool = True) -> list:
#     """
#     Sliding‑window gradient + attention saliency, same interface as your
#     original `get_saliency_line_scores`, but without truncation.
#     """
#     if not java_codes:
#         return []

#     # -------- 1. Pre‑tokenize & collect windows ----------
#     all_windows = []          # list of token-ID lists (for one window)
#     window_meta = []          # (class_idx, start_orig, end_orig)
#     class_data = []           # per class: (offset_mapping, line_ends, total_tokens, lines)

#     max_len = 512
#     stride = 256

#     for cls_idx, code in enumerate(java_codes):
#         enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False)
#         input_ids = enc["input_ids"]
#         offset_map = enc["offset_mapping"]
#         lines = code.splitlines(keepends=True)
#         line_ends = np.cumsum([len(l) for l in lines])
#         total_tokens = len(input_ids)

#         # Create windows: we do NOT add CLS/SEP – we use raw embeddings directly
#         for start in range(0, total_tokens, stride):
#             end = min(start + max_len, total_tokens)
#             if end - start < 1:
#                 break
#             # window tokens only, no special tokens
#             window_ids = input_ids[start:end]
#             all_windows.append(window_ids)
#             window_meta.append((cls_idx, start, end))

#         class_data.append((offset_map, line_ends, total_tokens, lines))

#     # -------- 2. Accumulators ----------
#     num_classes = len(java_codes)
#     token_score_sum = [np.zeros(data[2]) for data in class_data]
#     token_score_cnt = [np.zeros(data[2], dtype=int) for data in class_data]

#     # -------- 3. Process each window individually (or you can batch them,
#     #            but we keep it simple for gradient correctness) ----------
#     for w_idx, (window_ids, (cls_idx, start, end)) in enumerate(zip(all_windows, window_meta)):
#         if len(window_ids) == 0:
#             continue

#         # Convert to tensor [1, seq_len]
#         input_ids_t = torch.tensor([window_ids]).to(device)
#         # Get embeddings
#         embeddings = model.get_input_embeddings()(input_ids_t)
#         embeddings.retain_grad()
#         seq_len = embeddings.size(1)

#         # Create attention_mask and token_type_ids (all ones / zeros)
#         attn_mask = torch.ones((1, seq_len), dtype=torch.long, device=device)
#         token_type = torch.zeros((1, seq_len), dtype=torch.long, device=device)

#         # Zero previous gradients
#         model.zero_grad()

#         # Forward
#         outputs = model(inputs_embeds=embeddings,
#                         attention_mask=attn_mask,
#                         token_type_ids=token_type,
#                         output_attentions=True)
#         hidden_cls = outputs.last_hidden_state[:, 0, :]
#         cls_norm = hidden_cls.norm()
#         cls_norm.backward()

#         grad = embeddings.grad   # [1, seq_len, hidden_dim]
#         # Saliency per token in the window
#         saliency = (embeddings * grad).norm(dim=-1).squeeze(0).detach().cpu().numpy()

#         # Optionally fuse attention from layers 7-10
#         if use_attention_fusion:
#             layer_indices = [6, 7, 8, 9]   # layers 7-10 (0-indexed)
#             attn_weights = np.zeros(seq_len)
#             for l_idx in layer_indices:
#                 layer_attn = outputs.attentions[l_idx].mean(dim=1).squeeze(0).detach()
#                 attn_from_cls = layer_attn[0, :].cpu().numpy()
#                 attn_weights += attn_from_cls
#             attn_weights /= len(layer_indices)
#             token_scores = saliency * attn_weights
#         else:
#             token_scores = saliency

#         # Map window positions back to original token indices and accumulate
#         for pos_in_window, score in enumerate(token_scores):
#             orig_idx = start + pos_in_window
#             if orig_idx < len(token_score_sum[cls_idx]):
#                 token_score_sum[cls_idx][orig_idx] += score
#                 token_score_cnt[cls_idx][orig_idx] += 1

#         # Cleanup
#         del input_ids_t, embeddings, outputs, grad
#         torch.cuda.empty_cache()

#     # -------- 4. Average and aggregate to lines ----------
#     results = []
#     for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
#         scores = token_score_sum[cls_idx]
#         cnts = token_score_cnt[cls_idx]
#         mask = cnts > 0
#         token_scores_final = np.zeros(total_tok)
#         token_scores_final[mask] = scores[mask] / cnts[mask]

#         line_scores = np.zeros(len(lines))
#         for token_idx, (start_char, end_char) in enumerate(offset_map):
#             if start_char == 0 and end_char == 0:
#                 continue
#             line_idx = char_to_line(start_char, line_ends)
#             line_scores[line_idx] += token_scores_final[token_idx]

#         results.append((line_scores, lines))

#     return results


# -------------------------
# Helper: map character offset to line index
# -------------------------
# def char_to_line(start_char: int, line_ends: np.ndarray) -> int:
#     """Return index of the line containing start_char (0-based)."""
#     for i, end in enumerate(line_ends):
#         if start_char < end:
#             return i
#     return len(line_ends) - 1  # fallback

# # -------------------------
# # Main function: gradient + attention saliency per line
# # -------------------------
# def get_saliency_line_scores(java_codes: List[str], use_attention_fusion: bool = True) -> List[Tuple[np.ndarray, List[str]]]:
#     """
#     For each Java code snippet, compute line-level importance scores using:
#       - gradient-based saliency on the [CLS] embedding norm,
#       - (optionally) multi-layer attention from [CLS] across layers 7-10.

#     Returns:
#         list of (line_scores: np.ndarray, lines: list[str]) for each input code.
#     """
#     results = []
#     for code in java_codes:
#         # Tokenize with offset mapping (no special tokens in offset)
#         enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False, truncation=True, max_length=510)
#         if not enc["input_ids"]:
#             # empty code
#             results.append((np.array([]), []))
#             continue

#         input_ids = torch.tensor([enc["input_ids"]]).to(device)
#         # Get embeddings with gradient tracking
#         embeddings = model.get_input_embeddings()(input_ids)
#         embeddings.retain_grad()   # we need gradients of this tensor

#         # Forward pass (with attentions)
#         seq_len = embeddings.size(1)
#         attention_mask = torch.ones((1, seq_len), dtype=torch.long, device=device)
#         token_type_ids = torch.zeros((1, seq_len), dtype=torch.long, device=device)
#         model.zero_grad()  # also important to clear previous gradients
#         outputs = model(inputs_embeds=embeddings,
#                 attention_mask=attention_mask,
#                 token_type_ids=token_type_ids,
#                 output_attentions=True)
#         # outputs = model(inputs_embeds=embeddings,
#         #                 attention_mask=torch.ones_like(input_ids),
#         #                 output_attentions=True)
#         hidden_cls = outputs.last_hidden_state[:, 0, :]   # (1, hidden_dim)
#         # Scalar: L2 norm of [CLS]
#         cls_norm = hidden_cls.norm()

#         # Compute gradient of cls_norm w.r.t. embeddings
#         cls_norm.backward()
#         grad = embeddings.grad   # (1, seq_len, hidden_dim)
#         # Saliency = norm of (embedding ⊙ grad)
#         saliency = (embeddings * grad).norm(dim=-1).squeeze(0).detach().cpu().numpy()  # (seq_len,)

#         # Optionally fuse attention weights from layers 7–10
#         if use_attention_fusion:
#             layer_indices = [6, 7, 8, 9]   # layers 7,8,9,10 (0-indexed)
#             attn_weights = np.zeros(saliency.shape)
#             for l_idx in layer_indices:
#                 # attentions: tuple of (batch, heads, seq_len, seq_len)
#                 # We take average over heads, then [CLS] -> all tokens
#                 layer_attn = outputs.attentions[l_idx].mean(dim=1).squeeze(0).detach()  # (seq_len, seq_len)
#                 attn_from_cls = layer_attn[0, :].cpu().numpy()   # attention from [CLS] to all tokens
#                 attn_weights += attn_from_cls
#             attn_weights /= len(layer_indices)

#             # Combine saliency and attention (multiplicative combination)
#             token_scores = saliency * attn_weights
#         else:
#             token_scores = saliency

#         # Map tokens to lines using offset_mapping
#         offset_map = enc["offset_mapping"]
#         lines = code.splitlines(keepends=True)
#         line_ends = np.cumsum([len(line) for line in lines])
#         line_scores = np.zeros(len(lines))

#         for t_idx, (start_char, end_char) in enumerate(offset_map):
#             if start_char == 0 and end_char == 0:
#                 continue  # special token (e.g., padding), skip
#             line_idx = char_to_line(start_char, line_ends)
#             line_scores[line_idx] += token_scores[t_idx]

#         results.append((line_scores, lines))

#     return results