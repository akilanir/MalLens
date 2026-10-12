import numpy as np
import torch
from sentence_transformers import SentenceTransformer
from droidlens.tpl.tpl_utils import normalize_vec
from pathlib import Path
from loguru import logger


EMB_DTYPE = np.float32
MINI_LM_EMB_DIM = 384 
BATCH_SIZE = 64
MODEL_MAX_LENGTH = 256
MODEL = "all-MiniLM-L6-v2"

class MiniLMEmbedder:
    """
    Wrapper for 'all-MiniLM-L6-v2' sentence-transformer embedding model.
    Automatically handles batching, normalization, and device placement.
    """

    def __init__(self, model_name: str = MODEL, max_length: int = MODEL_MAX_LENGTH):
        logger.info(f"[**] Loading embedding model: {model_name} ---------------------")
        self.model_name = model_name
        self.max_length = max_length
        self.batch_size = BATCH_SIZE
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

        # Load the sentence-transformers model
        self.model = SentenceTransformer(model_name)
        self.model = self.model.to(self.device)
        self.model.eval()

        # Infer embedding dimension
        dummy_emb = self.model.encode("dummy", convert_to_numpy=True)
        self.emb_dim = dummy_emb.shape[0]
        logger.info(f"[INFO] Embedding dimension: {self.emb_dim}, Max tokens: {self.max_length}")

    def embed_text(self, text: str) -> np.ndarray:
        """
        Generates a normalized embedding for a single text string.
        """
        if not text:
            logger.info("[!] Warning: Empty text input for embedding. Returning zero vector.")
            return np.zeros(self.emb_dim, dtype=EMB_DTYPE)

        emb = self.model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return emb

    def embed_text_chunked(self, text: str, chunk_size: int = None) -> np.ndarray:
        """
        Splits long text into chunks and averages embeddings for final vector.
        """
        if not text:
            return np.zeros(self.emb_dim, dtype=EMB_DTYPE)

        if chunk_size is None:
            chunk_size = self.max_length

        tokens = text.split()  # simple whitespace tokenizer
        embeddings_list = []
        for start in range(0, len(tokens), chunk_size):
            chunk_text = " ".join(tokens[start:start+chunk_size])
            chunk_emb = self.embed_text(chunk_text)
            embeddings_list.append(chunk_emb)

        final_emb = np.mean(np.stack(embeddings_list), axis=0)
        return normalize_vec(final_emb)


    def embed_batch(self, texts: list[str]) -> np.ndarray:
        """
        Batch embedding using sentence-transformers MiniLM model
        with manual micro-batching to avoid CUDA OOM.
        """
        if not texts:
            return np.empty((0, self.emb_dim), dtype=EMB_DTYPE)

        all_embeddings = []

        for i in range(0, len(texts), self.batch_size):
            batch_texts = texts[i:i + self.batch_size]

            emb = self.model.encode(
                batch_texts,
                convert_to_numpy=True,
                normalize_embeddings=True,
                show_progress_bar=False,
                batch_size=self.batch_size,   # still safe to pass
            ).astype(EMB_DTYPE)

            all_embeddings.append(emb)

            # Critical for long APK runs
            # if torch.cuda.is_available():
            #     torch.cuda.empty_cache()

        return np.vstack(all_embeddings)

    


