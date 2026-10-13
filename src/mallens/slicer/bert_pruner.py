#!/usr/bin/env python3
"""
Trained CodeBERT Line Pruner

Usage:
    from bert_pruner import BertPruner
    pruner = BertPruner(model_dir="./models/codebert_pruner", device="cuda")
    pruned_code = pruner.prune(src_code, keep_ratio=0.5)

Supports batch processing of multiple classes for efficiency.
"""

import os
import logging
import numpy as np
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel
from typing import List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------------------
# Model wrapper (identical to training/eval)
# ------------------------------------------------------------------------------
class LinePruningModel(nn.Module):
    """Loads fine-tuned CodeBERT + classifier."""
    def __init__(self, model_dir: str, device: torch.device):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_dir)
        hidden_size = self.encoder.config.hidden_size
        self.classifier = nn.Linear(hidden_size, 1)
        classifier_path = os.path.join(model_dir, "classifier.pt")
        if not os.path.exists(classifier_path):
            raise FileNotFoundError(f"Classifier weights not found at {classifier_path}")
        self.classifier.load_state_dict(torch.load(classifier_path, map_location=device))
        self.device = device
        self.to(device)

    def forward(self, input_ids, attention_mask, line_indices, num_lines):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        last_hidden = outputs.last_hidden_state  # (batch, seq, hidden)

        batch_size = input_ids.size(0)
        line_probs = []
        for i in range(batch_size):
            hidden_i = last_hidden[i]               # (seq, hidden)
            indices_i = line_indices[i]             # (seq)
            n_lines = num_lines[i]

            line_sums = torch.zeros(n_lines, hidden_i.size(-1), device=self.device)
            line_counts = torch.zeros(n_lines, device=self.device)

            for token_idx, line_idx in enumerate(indices_i):
                if line_idx >= 0:
                    line_sums[line_idx] += hidden_i[token_idx]
                    line_counts[line_idx] += 1

            line_counts = torch.clamp(line_counts, min=1)
            line_embeds = line_sums / line_counts.unsqueeze(-1)

            logits = self.classifier(line_embeds).squeeze(-1)
            probs = torch.sigmoid(logits)
            line_probs.append(probs)
        return line_probs


# ------------------------------------------------------------------------------
# Pruner class
# ------------------------------------------------------------------------------
class BertPruner:
    """
    Fine-tuned CodeBERT line pruner with chunking for long classes.
    """

    def __init__(self, model_dir: str, device: Optional[str] = None, max_length: int = 512):
        """
        Args:
            model_dir: Directory containing encoder weights, tokenizer files, classifier.pt.
            device: 'cpu', 'cuda', or None (auto).
            max_length: Maximum sequence length (default 512).
        """
        self.model_dir = model_dir
        self.max_length = max_length
        self.device = torch.device(device if device else ("cuda" if torch.cuda.is_available() else "cpu"))
        logger.info(f"Initialising BertPruner on {self.device}")

        self.tokenizer = AutoTokenizer.from_pretrained(model_dir)
        self.model = LinePruningModel(model_dir, self.device)
        self.model.eval()

    def _chunk_lines(self, lines: List[str]) -> List[Tuple[List[str], int]]:
        """
        Split lines into chunks of whole lines that fit within max_length tokens.
        Returns list of (chunk_lines, start_line_index_in_original).
        """
        chunks = []
        current_chunk = []
        current_token_count = 0
        start_idx = 0
        max_content_tokens = self.max_length - 2  # reserve for [CLS] and [SEP]

        for idx, line in enumerate(lines):
            # Tokenize without special tokens
            line_tokens = self.tokenizer.tokenize(line)
            if len(line_tokens) > max_content_tokens:
                # Extremely long line: truncate (rare, but safe)
                line_tokens = line_tokens[:max_content_tokens]
            line_token_len = len(line_tokens)

            if current_token_count + line_token_len > max_content_tokens and current_chunk:
                # Save current chunk
                chunks.append((current_chunk, start_idx))
                current_chunk = []
                current_token_count = 0
                start_idx = idx  # new chunk begins at this line

            current_chunk.append(line)
            current_token_count += line_token_len

        if current_chunk:
            chunks.append((current_chunk, start_idx))
        return chunks

    def _tokenize_chunk(self, chunk_lines: List[str]) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, int]:
        """
        Tokenize a chunk, return input_ids, attention_mask, line_indices, num_lines.
        All tensors are unsqueezed for batch dimension = 1.
        """
        chunk_code = "\n".join(chunk_lines)
        tokenized = self.tokenizer(
            chunk_code,
            return_offsets_mapping=True,
            add_special_tokens=True,
            truncation=True,
            max_length=self.max_length,
            padding=False
        )
        input_ids = tokenized["input_ids"]
        attention_mask = tokenized["attention_mask"]
        offsets = tokenized["offset_mapping"]

        # Compute line start offsets in the chunk code string
        line_starts = []
        pos = 0
        for line in chunk_lines:
            line_starts.append(pos)
            pos += len(line)
            # account for newline character
            if pos < len(chunk_code) and chunk_code[pos] == "\n":
                pos += 1

        import bisect
        line_indices = []
        for start, end in offsets:
            if start == 0 and end == 0:
                line_indices.append(-1)  # special token
            else:
                line_idx = bisect.bisect_right(line_starts, start) - 1
                line_idx = max(0, min(line_idx, len(chunk_lines) - 1))
                line_indices.append(line_idx)

        return (
            torch.tensor(input_ids, dtype=torch.long).unsqueeze(0),
            torch.tensor(attention_mask, dtype=torch.long).unsqueeze(0),
            torch.tensor(line_indices, dtype=torch.long).unsqueeze(0),
            len(chunk_lines)
        )

    def _predict_chunk_batch(self, chunks: List[Tuple[List[str], int]]) -> List[np.ndarray]:
        """
        Process a list of chunks in one forward pass.
        Returns list of probability arrays, one per chunk, in the same order.
        """
        if not chunks:
            return []

        batch_input_ids = []
        batch_attention_mask = []
        batch_line_indices = []
        batch_num_lines = []

        for chunk_lines, _ in chunks:
            input_ids, attention_mask, line_indices, num_lines = self._tokenize_chunk(chunk_lines)
            batch_input_ids.append(input_ids.squeeze(0))
            batch_attention_mask.append(attention_mask.squeeze(0))
            batch_line_indices.append(line_indices.squeeze(0))
            batch_num_lines.append(num_lines)

        # Pad to same length
        max_len = max(ids.size(0) for ids in batch_input_ids)
        padded_ids = torch.full((len(batch_input_ids), max_len), self.tokenizer.pad_token_id, dtype=torch.long)
        padded_mask = torch.zeros((len(batch_input_ids), max_len), dtype=torch.long)
        padded_line_idx = torch.full((len(batch_input_ids), max_len), -1, dtype=torch.long)  # -1 for padding

        for i in range(len(batch_input_ids)):
            seq_len = batch_input_ids[i].size(0)
            padded_ids[i, :seq_len] = batch_input_ids[i]
            padded_mask[i, :seq_len] = batch_attention_mask[i]
            padded_line_idx[i, :seq_len] = batch_line_indices[i]

        # Move to device
        padded_ids = padded_ids.to(self.device)
        padded_mask = padded_mask.to(self.device)
        padded_line_idx = padded_line_idx.to(self.device)

        with torch.no_grad():
            probs_list = self.model(padded_ids, padded_mask, padded_line_idx, batch_num_lines)

        # Convert to CPU numpy arrays
        return [probs.cpu().numpy() for probs in probs_list]

    def _prune_single(self, code: str, keep_ratio: float, threshold: Optional[float]) -> str:
        """
        Prune a single class source code.
        """
        if not code.strip():
            return code

        lines = code.splitlines()
        n_total = len(lines)
        if n_total == 0:
            return ""

        # Step 1: chunk lines
        chunks = self._chunk_lines(lines)
        if not chunks:
            return code

        # Step 2: predict probabilities for all chunks in a batch
        chunk_probs = self._predict_chunk_batch(chunks)

        # Step 3: assign probabilities to original line indices
        all_probs = np.zeros(n_total, dtype=np.float32)
        for (_, start_idx), probs in zip(chunks, chunk_probs):
            n_lines = len(probs)
            all_probs[start_idx:start_idx + n_lines] = probs

        # Step 4: select lines to keep
        if keep_ratio is not None:
            keep_ratio = max(0.0, min(1.0, keep_ratio))
            n_keep = max(1, int(round(keep_ratio * n_total))) if n_total > 0 else 0
            if n_keep >= n_total:
                keep_mask = np.ones(n_total, dtype=bool)
            else:
                # top-k indices by probability
                top_indices = np.argsort(all_probs)[::-1][:n_keep]
                keep_mask = np.zeros(n_total, dtype=bool)
                keep_mask[top_indices] = True
        else:
            threshold = threshold if threshold is not None else 0.5
            keep_mask = all_probs >= threshold

        # Step 5: reconstruct code
        pruned_lines = [line for line, keep in zip(lines, keep_mask) if keep]
        return "\n".join(pruned_lines)

    def prune(self, code: str, keep_ratio: float = 0.5, threshold: Optional[float] = None) -> str:
        """
        Prune a single Java class string.

        Args:
            code: original source code as string.
            keep_ratio: fraction of lines to keep (0.0 - 1.0). Used if not None.
            threshold: probability threshold if keep_ratio is None.

        Returns:
            pruned code (verbatim subset of original lines).
        """
        try:
            return self._prune_single(code, keep_ratio, threshold)
        except Exception as e:
            logger.warning(f"Pruning failed with error: {e}. Returning original code.")
            return code

    def prune_batch(self, code_list: List[str], keep_ratio: float = 0.5,
                    threshold: Optional[float] = None) -> List[str]:
        """
        Prune a list of class strings. This is more efficient than calling prune() in a loop
        because all chunks from different classes can be batched together if desired.
        However, for simplicity, we loop internally; future optimisation can batch across classes.
        """
        results = []
        for code in code_list:
            results.append(self.prune(code, keep_ratio, threshold))
        return results


# ------------------------------------------------------------------------------
# Convenience function replacing old saliency_slice_whole_class
# ------------------------------------------------------------------------------
def prune_code_with_trained_model(model_dir: str, class_source: str,
                                  keep_ratio: float = 0.5,
                                  device: Optional[str] = None) -> str:
    """
    Standalone function that loads the model (if not already loaded globally),
    and prunes a single class.

    Usage:
        pruned = prune_code_with_trained_model(
            model_dir="./models/codebert_pruner",
            class_source=src_clean,
            keep_ratio=0.7
        )
    """
    global _PRUNER_INSTANCE
    if "_PRUNER_INSTANCE" not in globals() or _PRUNER_INSTANCE is None:
        _PRUNER_INSTANCE = BertPruner(model_dir, device=device)
    return _PRUNER_INSTANCE.prune(class_source, keep_ratio=keep_ratio)


# ------------------------------------------------------------------------------
# Example usage
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python bert_pruner.py <model_dir> <input_file> [keep_ratio]")
        sys.exit(1)

    model_dir = sys.argv[1]
    input_file = sys.argv[2]
    keep_ratio = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5

    with open(input_file, "r", encoding="utf-8") as f:
        src = f.read()

    pruned = prune_code_with_trained_model(model_dir, src, keep_ratio=keep_ratio)
    print(pruned)
