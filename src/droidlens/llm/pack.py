"""Cluster -> (facts block, packed source). Facts are our structural
evidence stated as assertions the model must verify against the code."""
from __future__ import annotations

from pathlib import Path

from droidlens.core.datatypes import Cluster, Stage1Result, Stage2Result, Stage3Result

_CHARS_PER_TOKEN = 4

def _facts_for_class(cname: str, s2: Stage2Result, s3: Stage3Result) -> str:
    rec = s2.records[cname]
    names = s2.feature_names
    v = lambda k: rec.vector.values[names.index(k)]
    facts = [f"importance={s3.scores.get(cname, 0):.2f}"]
    if v("spoofed_framework"):
        # facts.append("SPOOFED (WEAK SIGNAL) — do not cite as malicious behavior. A malicious verdict requires ACTIONS in the quoted code: exfiltration, dynamic code loading, SMS abuse, C2, overlay, device-admin abuse, etc.")
        facts.append("SPOOFED: Android framework-style name but lives inside the app dex")
    if v("is_exported"):
        facts.append(f"exported component, {int(v('intent_filter_count'))} intent-filters")
    elif v("is_component"):
        facts.append("manifest component (not exported)")
    if rec.api_categories:
        facts.append("APIs: " + ", ".join(
            f"{k}x{n}" for k, n in sorted(rec.api_categories.items(),
                                          key=lambda kv: -kv[1])))
    # if v("api_undeclared_perm") > 0:
    #     facts.append("calls permission-gated APIs whose permission is NOT declared")
    si = [(k, int(v(k))) for k in ("str_urls", "str_ips", "str_shell",
                                   "str_exec_files", "str_high_entropy")]
    hits = [f"{k[4:]}={n}" for k, n in si if n > 0]
    if hits:
        facts.append("strings: " + ", ".join(hits))
    return "; ".join(facts)


def pack_cluster(cluster: Cluster, s2: Stage2Result, s3: Stage3Result, char_budget: int) -> str:
    parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
    for c in cluster.class_names:
        if c in s2.records:
            parts.append(f"- {c}: {_facts_for_class(c, s2, s3)}")
    parts.append("\n## DECOMPILED SOURCE")

    # budget shared by importance: seed gets the largest slice
    weights = [max(0.05, s3.scores.get(c, 0.0)) for c in cluster.class_names]
    total_w = sum(weights)
    for c, w in zip(cluster.class_names, weights):
        rec = s2.records.get(c)
        share = int(char_budget * w / total_w)
        parts.append(f"\n### {c}")
        if rec is None or not rec.java_path:
            parts.append("(no decompiled source available)")
            continue
        try:
            src = Path(rec.java_path).read_text(encoding="utf-8",errors="replace") # Reading java source 
            # Lets calculate number of chars
            char_raw_src = len(src)
            from droidlens.utils.pre_processing import preprocess_java_code
            src = preprocess_java_code(src) # Lets remove compiler artifacts
            char_processed_src = len(src)
            reduction = char_raw_src - char_processed_src
            # src = attention_slice(src) # No bert
            reduction_pct = ((reduction / char_raw_src) * 100 if char_raw_src > 0 else 0.0)
            # print( f"!!!!!IMPORTANT CHAR REDUCTION ---------------- " f"{char_raw_src:,} -> {char_processed_src:,} " f"({reduction:,} chars, {reduction_pct:.2f}% reduction)")
        except OSError:
            parts.append("(source unreadable)")
            continue
        if len(src) > share:
            src = src[:share] + f"\n// [truncated {len(src) - share} chars]"
        parts.append("```java\n" + src + "\n```")
    return "\n".join(parts)

def get_class_source(record, cfg) -> str | None:
    if record is None or not record.jadx_ok or not record.java_path:
        return None
    p = Path(record.java_path)
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else None




from droidlens.config import Config
from droidlens.summarization.summary_verfication import get_verified_summary
from droidlens.llm.client import LLMClient
import concurrent.futures
import networkx as nx

def _summarize_one_class(class_name: str, java_path: str, static_facts: dict, cfg: Config) -> dict:
    """
    Worker function for a single class. Instantiates its own LLMClient.
    Returns a dict with the summary result and the class name for ordering.
    """
    client = LLMClient(cfg)
    result = get_verified_summary(class_name, java_path, static_facts, client, max_iterations=3)
    result["class_name"] = class_name   # keep identity for later ordering
    return result


def pack_summary_cluster(cluster: Cluster, s1: "Stage1Result", s2: Stage2Result,
                         s3: Stage3Result, char_budget: int, cfg: Config) -> str:
    """
    Build a cluster prompt with per‑class verified summaries + intra‑cluster call edges.
    Requires Stage1Result to access the call graph.
    """
    debug = True
    parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
    for c in cluster.class_names:
        if c in s2.records:
            parts.append(f"- {c}: {_facts_for_class(c, s2, s3)}")

    # Extract the subgraph of only classes in this cluster
    cluster_graph = s1.graph.subgraph(cluster.class_names)

    if debug:
        print("Requested:", len(cluster.class_names))
        print("Subgraph:", cluster_graph.number_of_nodes())
        print("Nodes:", list(cluster_graph.nodes()))
        cluster_id = getattr(cluster, 'cluster_id', 'unknown')
        _save_cluster_subgraph(cluster_graph, str(cluster_id), Path("/mnt/SATA_3/akila/AK_PHD3/droidlens3/cluster_graphs"))

    # ---- Parallel summarisation (same as before) ----
    from collections import OrderedDict
    def _summarize_one_class(class_name, java_path, static_facts, cfg):
        client = LLMClient(cfg)
        res = get_verified_summary(class_name, java_path, static_facts, client, max_iterations=3)
        res["class_name"] = class_name
        return res

    jobs = []
    class_order = []
    for c in cluster.class_names:
        rec = s2.records.get(c)
        if rec is None or not rec.java_path:
            class_order.append((c, None))
            continue
        static_facts = rec.api_categories if hasattr(rec, "api_categories") else {}
        jobs.append((c, rec.java_path, static_facts))
        class_order.append((c, "pending"))

    results_by_class = {}
    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(_summarize_one_class, c, path, facts, cfg): c
                for c, path, facts in jobs
            }
            for future in concurrent.futures.as_completed(futures):
                c = futures[future]
                try:
                    res = future.result()
                    results_by_class[c] = res
                except Exception as e:
                    results_by_class[c] = {
                        "class_name": c,
                        "summary": f"(error: {e})",
                        "evidence": [],
                        "success": False,
                        "iterations": 0,
                        "usage": None
                    }

    # ---- Build the enriched summary block ----
    parts.append("\n## VERIFIED CLASS SUMMARIES (auto‑generated, fact‑checked)")
    for c, _ in class_order:
        rec = s2.records.get(c)
        if rec is None or not rec.java_path:
            parts.append(f"\n### {c} (no source available)")
            continue

        summary_result = results_by_class.get(c, {
            "summary": "Summarisation skipped",
            "evidence": [],
            "success": False,
            "iterations": 0,
            "usage": None
        })
        summary_text = summary_result["summary"]
        evidence = summary_result.get("evidence", [])
        success = summary_result["success"]

        block = f"### {c}\nSummary: {summary_text}\n"
        if evidence:
            block += "Evidence:\n" + "\n".join(f"- {e}" for e in evidence)

        # ---- Add outgoing edges to other cluster members ----
        if c in cluster_graph:
            callees = list(cluster_graph.successors(c))
            callees_in_cluster = [dst for dst in callees if dst in cluster.class_names]
            if callees_in_cluster:
                block += f"\nCalls: {', '.join(callees_in_cluster)}"

        if not success:
            block += "\n(⚠ Evidence verification below 80%)"
        parts.append(block)

    # ---- Add a compact graph overview (optional, but helpful) ----
    edges_str = []
    for caller in cluster.class_names:
        if caller in cluster_graph:
            callees = list(cluster_graph.successors(caller))
            callees_in = [dst for dst in callees if dst in cluster.class_names]
            if callees_in:
                edges_str.append(f"- {caller} → {', '.join(callees_in)}")
    if edges_str:
        parts.append("\n## GRAPH OVERVIEW")
        parts.extend(edges_str)

    return "\n".join(parts)


def pack_cluster_with_graph(cluster: Cluster, s1: "Stage1Result", s2: Stage2Result, s3: Stage3Result, char_budget: int, cfg: Config):
    debug = False
    parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
    # for c in cluster.class_names:
    #     if c in s2.records:
    #         parts.append(f"- {c}: {_facts_for_class(c, s2, s3)}")

    # Extract the subgraph of only classes in this cluster
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

    if debug:
        print("Requested:", len(cluster.class_names))
        print("Subgraph:", cluster_graph.number_of_nodes())
        print("Nodes:", list(cluster_graph.nodes()))
        cluster_id = getattr(cluster, 'cluster_id', 'unknown')
        _save_cluster_subgraph(cluster_graph, str(cluster_id), Path("/mnt/SATA_3/akila/AK_PHD3/droidlens3/cluster_graphs"))

    parts.append("\n## DECOMPILED ATTENTION BASED IMPORTANT SOURCES:")
    # budget shared by importance: seed gets the largest slice
    weights = [max(0.05, s3.scores.get(c, 0.0)) for c in cluster.class_names]
    total_w = sum(weights)
    for c, w in zip(cluster.class_names, weights):
        rec = s2.records.get(c)
        share = int(char_budget * w / total_w)
        parts.append(f"\n### Class: {c}")
        if rec is None or not rec.java_path:
            parts.append("(no decompiled source available)")
            continue
        try:
            src = Path(rec.java_path).read_text(encoding="utf-8",errors="replace") # Reading java source 
            # Lets calculate number of chars
            char_raw_src = len(src)
            from droidlens.utils.pre_processing import preprocess_java_code
            src = preprocess_java_code(src) # Lets remove compiler artifacts
            if "android/system/sa" in c:
                print("PORT FORWARDING SNIPPET IN PREPROCESSED SOURCE: --------")
                print(src)
            char_processed_src = len(src)
            reduction = char_raw_src - char_processed_src
            import time
            time_1 = time.time()
            src = attention_slice(src)
            time_2 = time.time()
            attention_reduction = char_processed_src - len(src)
            reduction_pct = ((reduction / char_raw_src) * 100 if char_raw_src > 0 else 0.0)
            print( f"!!!!!IMPORTANT CHAR REDUCTION ---------------- " f"{char_raw_src:,} -> {char_processed_src:,} " f"({reduction:,} chars, {reduction_pct:.2f}% reduction)")
            if "android/system/sa" in c:
                print("PORT FORWARDING SNIPPET IN ATTENTION PROCESSED SOURCE: --------")
                print(src)

            print(f"Attention based reduction ---------------------- : {attention_reduction} in {time_2-time_1} Seconds")
        except OSError:
            parts.append("(source unreadable)")
            continue
        if len(src) > share:
            src = src[:share] + f"\n// [truncated {len(src) - share} chars]"
        parts.append("```java\n" + src + "\n```")

        block = "## GRAPH CONNECTIONS: \n"
        if c in cluster_graph:
            callees = list(cluster_graph.successors(c))
            callees_in_cluster = [dst for dst in callees if dst in cluster.class_names]
            if callees_in_cluster:
                block += f"\nCalls: {', '.join(callees_in_cluster)}"
        parts.append(block)

    return "\n".join(parts)




#### ----- Packing the class summaries in to the cluster request
# from droidlens.config import Config
# def pack_summary_cluster(cluster: Cluster, s2: Stage2Result, s3: Stage3Result, char_budget: int, cfg: Config) -> str:
#     from droidlens.summarization.summary_verfication import get_verified_summary
#     from droidlens.llm.client import LLMClient
#     client = LLMClient(cfg)
#     parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
#     for c in cluster.class_names:
#         if c in s2.records:
#             parts.append(f"- {c}: {_facts_for_class(c, s2, s3)}")

#     # Instead of raw source, we now embed verified summaries
#     parts.append("\n## VERIFIED CLASS SUMMARIES (auto‑generated, fact‑checked)")
#     for c in cluster.class_names:
#         rec = s2.records.get(c)
#         if rec is None or not rec.java_path:
#             parts.append(f"\n### {c} (no source available)")
#             continue
#         static_facts = rec.api_categories  # whatever static facts you have ------ What do we need to add here? DO WE NEED this?
#         # Reduce time by batch processing with 10 classes and tiny llm
#         summary_result = get_verified_summary(c, rec.java_path, static_facts, client, max_iterations=3)
#         summary_text = summary_result["summary"]
#         evidence = summary_result.get("evidence", [])
#         success = summary_result["success"]
#         # Build a representation
#         summary_block = f"### {c}\nSummary: {summary_text}\n"
#         if evidence:
#             summary_block += "Evidence:\n" + "\n".join(f"- {e}" for e in evidence)
#         if not success:
#             summary_block += "\n(⚠ Evidence verification below 80%)"
#         parts.append(summary_block)

#     # ... later maybe add a minimal connections graph if needed, but the cluster verdict prompt will later combine these summaries
#     return "\n".join(parts)



# def pack_summary_cluster(cluster: Cluster, s2: Stage2Result, s3: Stage3Result,
#                          char_budget: int, cfg: Config) -> str:
#     parts = ["## CLUSTER FACTS (from static analysis — verify against code)"]
#     for c in cluster.class_names:
#         if c in s2.records:
#             parts.append(f"- {c}: {_facts_for_class(c, s2, s3)}")

#     # Prepare jobs for all classes that have source available
#     jobs = []
#     class_order = []
#     for c in cluster.class_names:
#         rec = s2.records.get(c)
#         if rec is None or not rec.java_path:
#             # class without source: we'll handle after parallel part
#             class_order.append((c, None))
#             continue
#         # Optional static facts – adjust to whatever your s2 record provides
#         static_facts = rec.api_categories if hasattr(rec, "api_categories") else {}
#         jobs.append((c, rec.java_path, static_facts))
#         class_order.append((c, "pending"))

#     # Run summarisation in parallel (thread pool)
#     results_by_class = {}
#     if jobs:
#         # tune max_workers to your hardware and LLM concurrency limit
#         with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
#             futures = {
#                 executor.submit(_summarize_one_class, c, path, facts, cfg): c
#                 for c, path, facts in jobs
#             }
#             for future in concurrent.futures.as_completed(futures):
#                 c = futures[future]
#                 try:
#                     res = future.result()
#                     results_by_class[c] = res
#                 except Exception as e:
#                     # If summarisation fails entirely, still record a fallback
#                     results_by_class[c] = {
#                         "class_name": c,
#                         "summary": f"(error: {e})",
#                         "evidence": [],
#                         "success": False,
#                         "iterations": 0,
#                         "usage": None
#                     }

#     # Build the output block, preserving original class order
#     parts.append("\n## VERIFIED CLASS SUMMARIES (auto‑generated, fact‑checked)")
#     for c, _ in class_order:
#         rec = s2.records.get(c)
#         if rec is None or not rec.java_path:
#             parts.append(f"\n### {c} (no source available)")
#             continue

#         summary_result = results_by_class.get(c, {
#             "summary": "Summarisation skipped",
#             "evidence": [],
#             "success": False,
#             "iterations": 0,
#             "usage": None
#         })
#         summary_text = summary_result["summary"]
#         evidence = summary_result.get("evidence", [])
#         success = summary_result["success"]

#         summary_block = f"### {c}\nSummary: {summary_text}\n"
#         if evidence:
#             summary_block += "Evidence:\n" + "\n".join(f"- {e}" for e in evidence)
#         if not success:
#             summary_block += "\n(⚠ Evidence verification below 80%)"
#         parts.append(summary_block)

#     # Optionally add a minimal graph representation here
#     return "\n".join(parts)

import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path

def _save_cluster_subgraph(graph: nx.DiGraph, cluster_id: str, output_dir: Path, figsize=(12,8)):
    """
    Save the subgraph as a PNG. Uses short class names for labels.
    """
    if graph.number_of_nodes() == 0:
        return

    plt.figure(figsize=figsize)

    # Use graphviz layout if available (gives better directional flow)
    try:
        pos = nx.nx_agraph.graphviz_layout(graph, prog='dot')
    except (ImportError, AttributeError):
        pos = nx.spring_layout(graph, seed=42)

    # Colour by node kind (if present)
    node_colors = []
    for n in graph.nodes():
        kind = graph.nodes[n].get('kind', 'unknown')
        color_map = {
            'application': '#aec7e8',
            'system':      '#ffbb78',
            'library':     '#98df8a',
        }
        node_colors.append(color_map.get(kind, '#d62728'))

    nx.draw_networkx_nodes(graph, pos, node_size=2000, node_color=node_colors, alpha=0.9)
    nx.draw_networkx_edges(graph, pos, arrowstyle='-|>', arrowsize=15, edge_color='gray')

    # Short names for readability
    labels = {n: n.split('.')[-1] if '.' in n else n for n in graph.nodes()}
    nx.draw_networkx_labels(graph, pos, labels, font_size=8)

    plt.axis('off')
    plt.tight_layout()
    out_path = output_dir / f"cluster_{cluster_id}_subgraph.png"
    plt.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close()



import torch
import numpy as np
from transformers import AutoTokenizer, AutoModel
from collections import defaultdict

# MODEL_NAME = "microsoft/codebert-base"
# tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
# model = AutoModel.from_pretrained(MODEL_NAME, output_attentions=True)

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
