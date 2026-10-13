#!/usr/bin/env python3
"""
PoC: Compare saliency-based pruning with different Code Language Models
     (CodeBERT, UnixCoder, GraphCodeBERT).

Usage:
    python poc_models.py --input_dir /mnt/SATA_3/akila/AK_PHD3/droidlens3/src/droidlens/slicer/temp \
                               --output_base /mnt/SATA_3/akila/AK_PHD3/droidlens3/src/droidlens/slicer/outputs \
                               --model_name codesage/codesage-small \
                               --keep_ratio 0.7
                               microsoft/unixcoder-base
                               microsoft/graphcodebert-base
                               microsoft/codebert-base
                               codesage/codesage-small
"""

import os
import argparse
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
from typing import List, Tuple

# ------------------------- Global model-related objects -------------------------
tokenizer = None
model = None
device = None

# ------------------------- Helper function -------------------------------------
def char_to_line(start_char: int, line_ends: np.ndarray) -> int:
    for i, end in enumerate(line_ends):
        if start_char < end:
            return i
    return len(line_ends) - 1

# ------------------------- Saliency functions (unchanged) ---------------------
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
        attention_mask = torch.zeros((len(batch_windows), batch_max_len), dtype=torch.long, device=device)
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
        with torch.autocast(device_type="cuda", dtype=torch.float16):
            outputs = model(
                inputs_embeds=embeddings,
                attention_mask=attention_mask,
                output_attentions=use_attention_fusion
            )
            # CLS representation for each window
            cls_norm = outputs.last_hidden_state[:, 0, :].norm(dim=-1)
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
            scores = token_scores[batch_idx, 1:content_len + 1]
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

        # Added to average the token score (commented out in original PoC)
        # line_token_count = np.zeros(len(lines), dtype=np.int32)
        for token_idx, (start_char, end_char) in enumerate(offset_map):
            if start_char == 0 and end_char == 0:
                continue
            line_idx = char_to_line(start_char, line_ends)
            line_scores[line_idx] += token_scores_final[token_idx]
            # line_token_count[line_idx] += 1
        # line_scores = line_scores / np.maximum(line_token_count, 1)
        results.append((line_scores, lines))
    return results


def saliency_slice_whole_class(class_source: str, keep_ratio=0.8, use_attention_fusion=True) -> str:

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


# ------------------------- Main processing ------------------------------------
def process_folder(input_dir: str, output_base: str, model_name: str,
                   keep_ratio: float, use_attention_fusion: bool):
    global tokenizer, model, device

    # Load model and tokenizer
    print(f"Loading model: {model_name}")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name, output_attentions=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)
    model.eval()
    print("Model loaded.")

    # Create output directories
    model_short_name = model_name.split('/')[-1]  # e.g., "codebert-base"
    orig_dir = os.path.join(output_base, model_short_name, "original")
    pruned_dir = os.path.join(output_base, model_short_name, "pruned")
    os.makedirs(orig_dir, exist_ok=True)
    os.makedirs(pruned_dir, exist_ok=True)

    # Get all .java files in the input directory (non-recursive)
    java_files = [f for f in os.listdir(input_dir) if f.endswith(".java")]
    print(f"Found {len(java_files)} Java files.")

    for idx, filename in enumerate(java_files):
        filepath = os.path.join(input_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            original_code = f.read()

        print(f"[{idx+1}/{len(java_files)}] Processing {filename} ...")
        pruned_code = saliency_slice_whole_class(original_code, keep_ratio=keep_ratio,
                                                 use_attention_fusion=use_attention_fusion)

        # Save original (unchanged)
        orig_out = os.path.join(orig_dir, filename)
        with open(orig_out, "w", encoding="utf-8") as f:
            f.write(original_code)

        # Save pruned
        pruned_out = os.path.join(pruned_dir, filename)
        with open(pruned_out, "w", encoding="utf-8") as f:
            f.write(pruned_code)

        print(f"    Original: {len(original_code)} chars, Pruned: {len(pruned_code)} chars.")

    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run saliency pruning with different code models.")
    parser.add_argument("--input_dir", type=str, required=True,
                        help="Folder containing .java files (classes).")
    parser.add_argument("--output_base", type=str, default="pruning_output",
                        help="Base folder where output will be stored.")
    parser.add_argument("--model_name", type=str,
                        default="microsoft/graphcodebert-base",
                        help="HuggingFace model name (e.g., microsoft/codebert-base).")
    parser.add_argument("--keep_ratio", type=float, default=0.7,
                        help="Fraction of total saliency to keep (0.2 to 0.8).")
    parser.add_argument("--no_attention_fusion", action="store_true",
                        help="Disable attention fusion (use saliency only).")
    args = parser.parse_args()

    use_attn = not args.no_attention_fusion
    process_folder(args.input_dir, args.output_base, args.model_name,
                   args.keep_ratio, use_attn)
