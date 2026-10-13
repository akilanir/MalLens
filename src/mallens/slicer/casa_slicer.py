import torch
import numpy as np
import javalang
import re
from typing import List, Tuple, Dict, Set
from transformers import RobertaTokenizer, RobertaModel, AutoTokenizer, AutoModel

# ==========================================
# 1. SETUP & GPU OPTIMIZATION
# ==========================================
MODEL_NAME = "microsoft/codebert-base"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
# tokenizer = RobertaTokenizer.from_pretrained(MODEL_NAME)
# model = RobertaModel.from_pretrained(MODEL_NAME)
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME, output_attentions=True)

model.to(DEVICE)
model.eval() # Ensure we don't update weights

# Sink anchors for semantic similarity (Obfuscation resilient)
SINK_ANCHORS = [
    "Runtime.getRuntime().exec", "ProcessBuilder", "Cipher.doFinal",
    "sendTextMessage", "getDeviceId", "loadLibrary", "Method.invoke"
]

# Pre-compute sink anchor embeddings
def get_anchor_embeddings() -> torch.Tensor:
    enc = tokenizer(SINK_ANCHORS, return_tensors="pt", padding=True, truncation=True).to(DEVICE)
    with torch.no_grad():
        outputs = model(**enc)
    # Mean pooling over tokens
    mask = enc['attention_mask'].unsqueeze(-1).float()
    embeddings = (outputs.last_hidden_state * mask).sum(1) / mask.sum(1)
    return embeddings

ANCHOR_EMBEDS = get_anchor_embeddings()

# ==========================================
# 2. AST & DATA-FLOW GRAPH (DFG) ANALYSIS
# ==========================================
class ASTAnalyzer:
    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines(keepends=True)
        self.tree = None
        self.statement_ranges = [] # (start_line, end_line)
        self.dfg = {} # variable_name -> list of line numbers where defined
        self._parse_and_extract()

    def _parse_and_extract(self):
        try:
            self.tree = javalang.parse.parse(self.code)
        except Exception as e:
            # If obfuscation breaks parser, fallback to line-level
            self.tree = None
            return

        for path, node in self.tree:
            if hasattr(node, 'position') and node.position:
                start_line = node.position.line - 1
                # Estimate end line (simplistic: find next node start or EOF)
                end_line = start_line + 1
                self.statement_ranges.append((start_line, end_line, path, node))

                # Build basic DFG: track variable declarations and assignments
                if isinstance(node, javalang.tree.LocalVariableDeclaration):
                    for declarator in node.declarators:
                        var_name = declarator.name
                        if var_name not in self.dfg:
                            self.dfg[var_name] = []
                        self.dfg[var_name].append(start_line)

    def get_statement_index(self, line_idx: int) -> int:
        """Find which AST statement a line belongs to."""
        best_idx = -1
        for i, (start, end, _, _) in enumerate(self.statement_ranges):
            if start <= line_idx < end:
                best_idx = i
        return best_idx

    def get_def_use_closure(self, stmt_idx: int) -> Set[int]:
        """Backward trace: find lines where variables used in this stmt were defined."""
        if stmt_idx == -1 or not self.statement_ranges:
            return set()

        start, end, path, node = self.statement_ranges[stmt_idx]
        closure = {stmt_idx}

        # Extract all member references / method invocations in this statement
        for sub_path, sub_node in node.filter(javalang.tree.MemberReference):
            var_name = sub_node.member
            if var_name in self.dfg:
                # Add the lines where this variable was defined
                closure.update(self.dfg[var_name])

        return closure

# ==========================================
# 3. IDENTIFIER NORMALIZATION
# ==========================================
def normalize_identifiers(code: str) -> str:
    """
    Replaces user-defined variables with var1, var2, methods with methodA, etc.
    Obfuscation resilient because names don't matter, only structure.
    """
    # Simple regex-based normalization for POC (AST-based is more robust but verbose)
    code = re.sub(r'\b(?<!\.)[a-z_][a-zA-Z0-9_]*(?=\s*=|\s*\()', 'var', code) # variables
    return code

# ==========================================
# 4. CONTRASTIVE & ATTENTION-WALK SALIENCY
# ==========================================
def generate_benign_baseline(benign_java_files: List[str], output_path: str = "benign_baseline.npy"):
    """Run this once on AOSP/F-Droid code to generate the statistical baseline."""
    print("Generating benign baseline...")
    all_scores = []

    # Process in batches
    batch_size = 32
    for i in range(0, len(benign_java_files), batch_size):
        batch = benign_java_files[i:i+batch_size]
        # Compute saliency (same logic as below, but without contrastive subtraction)
        scores, _ = compute_casa_saliency(batch, contrastive_baseline=None)
        all_scores.extend([s.mean() for s, _ in scores])

    baseline = np.mean(all_scores) if all_scores else 0.0
    np.save(output_path, np.array([baseline]))
    print(f"Baseline saved to {output_path}")

def compute_casa_saliency(java_codes: List[str], contrastive_baseline: np.ndarray = None) -> List[Tuple[np.ndarray, List[str]]]:
    """
    Computes Contrastive Saliency fused with Attention-Walk reachability from Sinks.
    Fully batched for RTX 4090.
    """
    if not java_codes:
        return []

    all_windows = []
    window_meta = []
    class_data = []
    max_len = 512
    stride = 256
    cls_id = tokenizer.cls_token_id
    sep_id = tokenizer.sep_token_id

    # 1. Tokenize and create windows
    for cls_idx, code in enumerate(java_codes):
        enc = tokenizer(code, return_offsets_mapping=True, add_special_tokens=False, truncation=False)
        input_ids = enc["input_ids"]
        offset_map = enc["offset_mapping"]
        lines = code.splitlines(keepends=True)
        line_ends = np.cumsum([len(l) for l in lines])
        total_tokens = len(input_ids)

        for start in range(0, total_tokens, stride):
            end = min(start + max_len - 2, total_tokens)
            if end <= start: break
            window_ids = [cls_id] + input_ids[start:end] + [sep_id]
            all_windows.append(window_ids)
            window_meta.append((cls_idx, start, end))
        class_data.append((offset_map, line_ends, total_tokens, lines))

    token_score_sum = [np.zeros(data[2], dtype=np.float32) for data in class_data]
    token_score_cnt = [np.zeros(data[2], dtype=np.int32) for data in class_data]

    # 2. Process in batches
    batch_size = 16
    for batch_start in range(0, len(all_windows), batch_size):
        batch_windows = all_windows[batch_start:batch_start + batch_size]
        batch_meta = window_meta[batch_start:batch_start + batch_size]
        batch_max_len = max(len(x) for x in batch_windows)

        input_ids = torch.full((len(batch_windows), batch_max_len), tokenizer.pad_token_id, dtype=torch.long, device=DEVICE)
        attention_mask = torch.zeros((len(batch_windows), batch_max_len), dtype=torch.long, device=DEVICE)

        for i, window in enumerate(batch_windows):
            length = len(window)
            input_ids[i, :length] = torch.tensor(window, dtype=torch.long, device=DEVICE)
            attention_mask[i, :length] = 1

        embeddings = model.get_input_embeddings()(input_ids)
        embeddings.retain_grad()
        model.zero_grad(set_to_none=True)

        with torch.autocast(device_type="cuda", dtype=torch.float16):
            outputs = model(inputs_embeds=embeddings, attention_mask=attention_mask, output_attentions=True)
            cls_rep = outputs.last_hidden_state[:, 0, :]
            loss = cls_rep.norm(dim=-1).sum()

        loss.backward()
        grad = embeddings.grad
        saliency = (embeddings.float() * grad.float()).norm(dim=-1)

        # Attention Walk: Reachability from Sinks
        # We compute cosine similarity between token embeddings and SINK_ANCHORS
        token_embeds = outputs.last_hidden_state.float() # [B, L, D]
        # Normalize for cosine sim
        token_embeds_norm = torch.nn.functional.normalize(token_embeds, p=2, dim=-1)
        anchor_embeds_norm = torch.nn.functional.normalize(ANCHOR_EMBEDS, p=2, dim=-1)

        # Sim shape: [B, L, num_anchors]
        sim = torch.bmm(token_embeds_norm, anchor_embeds_norm.T.unsqueeze(0).expand(token_embeds_norm.size(0), -1, -1).transpose(1,2))
        max_sim, _ = sim.max(dim=-1) # [B, L]

        # Use attention to propagate from high-similarity tokens
        attn_weights = torch.zeros_like(saliency)
        layer_indices = [6, 7, 8, 9]
        for l_idx in layer_indices:
            layer_attn = outputs.attentions[l_idx].mean(dim=1) # Average over heads
            # Propagate attention 1-hop from sink-like tokens
            sink_mask = (max_sim > 0.5).float().unsqueeze(1) # [B, 1, L]
            propagated = torch.bmm(sink_mask, layer_attn).squeeze(1) # [B, L]
            attn_weights += propagated

        attn_weights /= len(layer_indices)

        # Contrastive Saliency
        token_scores = saliency * (1.0 + attn_weights) # Fuse saliency with reachability
        if contrastive_baseline is not None:
            # Subtract normal code baseline to isolate anomaly
            token_scores = torch.relu(token_scores - torch.tensor(contrastive_baseline[0], device=DEVICE, dtype=torch.float32))

        token_scores = token_scores.detach().cpu().numpy()

        # Map back
        for batch_idx, (cls_idx, start, end) in enumerate(batch_meta):
            content_len = end - start
            scores = token_scores[batch_idx, 1:content_len + 1]
            for pos, score in enumerate(scores):
                orig_idx = start + pos
                if orig_idx < len(token_score_sum[cls_idx]):
                    token_score_sum[cls_idx][orig_idx] += score
                    token_score_cnt[cls_idx][orig_idx] += 1

    # 3. Aggregate to Line Scores
    results = []
    for cls_idx, (offset_map, line_ends, total_tok, lines) in enumerate(class_data):
        scores = token_score_sum[cls_idx]
        cnts = token_score_cnt[cls_idx]
        mask = cnts > 0
        token_scores_final = np.zeros(total_tok, dtype=np.float32)
        token_scores_final[mask] = (scores[mask] / cnts[mask])

        line_scores = np.zeros(len(lines), dtype=np.float32)
        for token_idx, (start_char, end_char) in enumerate(offset_map):
            if start_char == 0 and end_char == 0: continue
            # Binary search for line index
            line_idx = np.searchsorted(line_ends, start_char, side='right')
            if line_idx < len(lines):
                line_scores[line_idx] += token_scores_final[token_idx]
        results.append((line_scores, lines))

    return results, class_data

# ==========================================
# 5. CASA SLICING ALGORITHM
# ==========================================
def casa_slice_class(class_source: str, keep_ratio=0.8, contrastive_baseline=None) -> str:
    """
    Smart slicing using AST closure and Contrastive Saliency.
    """
    # 1. Normalize Identifiers (Obfuscation Resilience)
    norm_source = normalize_identifiers(class_source)

    # 2. Analyze AST & DFG
    ast_analyzer = ASTAnalyzer(norm_source)

    # 3. Compute Saliency
    results, _ = compute_casa_saliency([norm_source], contrastive_baseline)
    line_scores, lines = results[0]

    if len(lines) == 0: return ""
    if line_scores.sum() > 0:
        norm_scores = line_scores / line_scores.sum()
    else:
        norm_scores = np.ones_like(line_scores) / len(lines)

    # 4. Group scores by AST statements
    stmt_scores = {}
    for i, score in enumerate(norm_scores):
        stmt_idx = ast_analyzer.get_statement_index(i)
        if stmt_idx == -1:
            stmt_idx = i # Fallback to line if AST failed
        stmt_scores[stmt_idx] = stmt_scores.get(stmt_idx, 0.0) + score

    # 5. Greedy Selection with Def-Use Closure
    sorted_stmts = sorted(stmt_scores.keys(), key=lambda k: stmt_scores[k], reverse=True)

    keep_stmts = set()
    running_score = 0.0
    total_score = sum(stmt_scores.values())

    for stmt_idx in sorted_stmts:
        keep_stmts.add(stmt_idx)
        running_score += stmt_scores[stmt_idx]

        # Expand backward via DFG closure
        closure = ast_analyzer.get_def_use_closure(stmt_idx)
        keep_stmts.update(closure)

        if running_score / total_score >= keep_ratio:
            break

    # 6. Map statements back to lines
    keep_indices = set()
    for stmt_idx in keep_stmts:
        if stmt_idx < len(ast_analyzer.statement_ranges):
            start, end, _, _ = ast_analyzer.statement_ranges[stmt_idx]
            for i in range(start, min(end, len(lines))):
                keep_indices.add(i)
        else:
            keep_indices.add(stmt_idx) # Fallback

    # Always keep package/imports and closing brace
    keep_indices.add(0)
    if len(lines) > 1: keep_indices.add(len(lines)-1)

    keep_indices = sorted(keep_indices)
    return "".join(lines[i] for i in keep_indices)

# ==========================================
# 6. POC EXECUTION
# ==========================================
def load_cluster(file_path: str) -> List[str]:
    """Mock function to load a cluster saved from your pipeline"""
    # In reality, load your pickle/json containing the cluster classes
    mock_code = """
package com.malware;
import android.telephony.SmsManager;
import java.io.*;

public class Payload {
    public void execute() {
        String cmd = "sh";
        Process p = Runtime.getRuntime().exec(cmd);
        SmsManager sm = SmsManager.getDefault();
        sm.sendTextMessage("1234", null, "data", null, null);
    }
}
"""
    # Duplicate to simulate a larger cluster
    return [mock_code] * 5 

if __name__ == "__main__":
    # 1. Setup baseline (Simulated for POC)
    # In reality, you run: generate_benign_baseline(list_of_aosp_files)
    # For POC, we create a dummy baseline file if it doesn't exist
    import os
    if not os.path.exists("benign_baseline.npy"):
        print("Creating dummy baseline. Replace with AOSP generated baseline.")
        np.save("benign_baseline.npy", np.array([0.1])) 

    baseline = np.load("benign_baseline.npy")

    # 2. Load cluster from earlier pipeline stage
    cluster_classes = load_cluster("mock_cluster.pkl")

    # 3. Run CASA Slicer
    print(f"Processing {len(cluster_classes)} classes in cluster...")
    sliced_classes = []
    for code in cluster_classes:
        # Keep ratio 60% for POC to show heavy pruning
        sliced = casa_slice_class(code, keep_ratio=0.6, contrastive_baseline=baseline)
        sliced_classes.append(sliced)

    # 4. Show output (This goes to your LLM)
    print("\n--- SLICED CLUSTER OUTPUT ---")
    for i, s in enumerate(sliced_classes[:1]): # Print just 1 for brevity
        print(f"Class {i} Output:\n{s}")