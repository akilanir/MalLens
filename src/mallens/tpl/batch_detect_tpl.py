"""
Batch TPL detection using smali files on disk.
Assumes library FAISS indexes have already been built (with tpl_utils.build_faiss_indexes_new).
"""
from pathlib import Path
import numpy as np
from loguru import logger
from typing import List, Dict, Optional, Tuple
import faiss
import torch
import time
import pickle

# Import your own utilities – adjust import paths as needed
from mallens.tpl.tpl_utils import (
    generate_class_embeddings,          # per‑class (slow when called many times)
    load_library_indexes,
    build_faiss_indexes_new,
    collect_files,
    load_library_map,
    preprocess_smali_code,
    parse_smali_blocks,
    calculate_positional_decay,
    weighted_average,
    normalize_vec,
    EMB_DTYPE,
    MINI_LM_EMB_DIM,
    LIB_MAP_CSV
)
from mallens.tpl.miniLM_embedder import MiniLMEmbedder

# def _build_merged_index(lib_indexes: dict) -> Tuple[faiss.Index, np.ndarray, list]:
#     """
#     Returns:
#       - merged_index (faiss.IndexIDMap with flat inner‑product)
#       - id_to_meta: a list of dicts with keys 'lib_name', 'version', 'class_name', etc.
#     The vectors must be normalized to unit length for cosine similarity (inner‑product).
#     """
#     all_vectors = []
#     id_to_meta = []
#     dim = None
#     for lib_name, lib_data in lib_indexes.items():
#         vectors = lib_data["smali_raw"]   # (n, dim) normalized
#         if dim is None:
#             dim = vectors.shape[1]
#         all_vectors.append(vectors)
#         for i, meta_entry in enumerate(lib_data["meta"]):
#             id_to_meta.append({
#                 "lib_name": lib_name,
#                 "version": meta_entry.get("version", "unknown"),
#                 "class_name": meta_entry.get("class_name", "unknown"),
#                 # any other fields you need...
#             })
#     all_vectors = np.vstack(all_vectors).astype(np.float32)
#     # Build flat IP index and wrap with ID mapping
#     base_index = faiss.IndexFlatIP(dim)
#     merged_index = faiss.IndexIDMap(base_index)
#     merged_index.add_with_ids(all_vectors, np.arange(len(all_vectors)))
#     return merged_index, id_to_meta


def _build_merged_index(lib_indexes: dict) -> Tuple[faiss.Index, list]:
    """
    Merge all per‑library IndexFlatIP indexes into one IndexIDMap.
    Returns (merged_index, id_to_meta).
    """
    all_vectors = []
    id_to_meta = []
    dim = None
    total_libs = len(lib_indexes)
    logger.info(f"Merging {total_libs} FAISS indexes...")

    for lib_name, lib_data in lib_indexes.items():
        index = lib_data["index"]
        meta = lib_data["meta"]

        # FAISS IndexIDMap wraps a flat index; we need the base flat index.
        if isinstance(index, faiss.IndexIDMap):
            base_index = faiss.downcast_index(index)
        else:
            base_index = index

        nvec = base_index.ntotal
        if nvec == 0:
            continue
        if dim is None:
            dim = base_index.d
        # Reconstruct vectors one by one – acceptable for a one‑time build.
        for i in range(nvec):
            vec = base_index.reconstruct(i)
            all_vectors.append(vec)
            # Map metadata: lib_name + per‑vector metadata entry
            id_to_meta.append({
                "lib_name": lib_name,
                "version": meta[i].get("version", "unknown"),
                "class_name": meta[i].get("class_name", "unknown"),
            })
        logger.debug(f"  {lib_name}: {nvec} vectors")

    if not all_vectors:
        raise ValueError("No vectors found in library indexes")

    all_vectors = np.array(all_vectors, dtype=np.float32)
    # Vectors are already normalized if your pipeline normalizes them before indexing.
    # Double‑check: if you used IndexFlatIP without normalization, you should
    # normalize here: norms = np.linalg.norm(all_vectors, axis=1, keepdims=True); all_vectors /= norms

    base_index = faiss.IndexFlatIP(dim)
    merged_index = faiss.IndexIDMap(base_index)
    merged_index.add_with_ids(all_vectors, np.arange(len(all_vectors)))
    return merged_index, id_to_meta



# def batch_detect_tpl(
#     class_paths: List[Path],             # list of *.smali file paths
#     lib_index_dir: Path,
#     embeddings_pkl: Optional[Path] = None,
#     threshold: float = 0.95,
#     pos_decay_alpha: float = 0.8
# ) -> Dict[str, Tuple[bool, Optional[str], Optional[str], Optional[str], float]]:
#     """
#     Detect TPL for a batch of smali classes.

#     Returns: dict mapping class_name -> (is_tpl, library_name, version, matched_lib_class, score)
#     """
#     n = len(class_paths)
#     if n == 0:
#         return {}

#     # 1. Ensure FAISS indexes exist (build if missing)
#     index_map_file = lib_index_dir / "library_indexes.pkl"
#     if not index_map_file.exists():
#         if embeddings_pkl is None:
#             raise FileNotFoundError("FAISS indexes missing and no embeddings_pkl provided to build them.")
#         logger.info("FAISS indexes not found – building from embeddings...")
#         build_faiss_indexes_new(lib_index_dir, embeddings_pkl)

#     # Merging the embeddings to one faiss index
#     merged_index_map_file = lib_index_dir / "merged.index"
#     if not (merged_index_map_file).exists():
#         logger.info("Building merged FAISS index...")
#         lib_indexes = load_library_indexes(index_map_file)
#         merged_index, id_to_meta = _build_merged_index(lib_indexes)
#         faiss.write_index(merged_index, str(lib_index_dir / "merged.index"))
#         import pickle
#         with open(lib_index_dir / "merged_meta.pkl", "wb") as f:
#             pickle.dump(id_to_meta, f)
#     else:
#         merged_index = faiss.read_index(str(lib_index_dir / "merged.index"))
#         with open(lib_index_dir / "merged_meta.pkl", "rb") as f:
#             id_to_meta = pickle.load(f)

#     # After loading/creating merged_index
#     if torch.cuda.is_available():
#         res = faiss.StandardGpuResources()
#         merged_index = faiss.index_cpu_to_gpu(res, 0, merged_index)



#     # 2. Load all library indexes + metadata
#     logger.info("Loading Lib Indexes...")
#     lib_indexes = load_library_indexes(index_map_file)
#     if not lib_indexes:
#         logger.error("No library indexes could be loaded")
#         return {cls.stem: (False, None, None, None, 0.0) for cls in class_paths}

#     # 3. Instantiate embedder once
#     embedder = MiniLMEmbedder()

#     # 4. Pre‑process all classes: parse blocks and collect *all* texts for a single batch embedding
#     class_info = []          # (class_name, list_of_texts, list_of_weights)
#     all_raw_texts = []       # accumulated texts from all classes
#     no_smali_classes = 0
#     logger.info("Reading Smali and Parsing....")
#     for cls_path in class_paths:
#         cname = cls_path.stem  # simple class name, if you need full name you can derive it
#         try:
#             smali_text = cls_path.read_text(errors="ignore")
#             no_smali_classes += 1
#         except Exception as e:
#             logger.debug(f"Failed to read {cls_path}: {e}")
#             class_info.append((cname, [], []))   # will yield zero vector
#             continue

#         blocks = parse_smali_blocks(smali_text)
#         texts = []
#         weights = []
#         for i, block in enumerate(blocks, start=1):
#             processed = preprocess_smali_code(block["text"])
#             texts.append(processed)
#             # length × positional weight
#             w = len(processed) * calculate_positional_decay(pos_decay_alpha, i)
#             weights.append(w)
#         class_info.append((cname, texts, weights))
#         all_raw_texts.extend(texts)

#     # 5. One giant embedding call for all texts
#     logger.info("Generating Embeddings...")
#     import time
#     time_1 = time.time()
#     if all_raw_texts:
#         logger.debug(f"Embedding {len(all_raw_texts)} smali blocks from {n} classes...")
#         all_emb = embedder.embed_batch(all_raw_texts)   # returns list of vectors
#         all_emb = np.array(all_emb, dtype=EMB_DTYPE)
#     else:
#         all_emb = np.empty((0, MINI_LM_EMB_DIM), dtype=EMB_DTYPE)
#     time_2 = time.time()

#     print(f"!!! It took {time_2-time_1} Seconds to analyse {no_smali_classes} smali classes")
#     print(f"AVERAGE EMBEDDING TIME: {(time_2-time_1)/no_smali_classes} SEconds")

#     # 6. Compute fused class vectors by pooling per‑class blocks
#     class_names = []
#     class_vectors = []
#     ptr = 0
#     for cname, texts, weights in class_info:
#         k = len(texts)
#         if k == 0:
#             class_names.append(cname)
#             class_vectors.append(np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE))
#         else:
#             vecs = all_emb[ptr:ptr+k]
#             fused = weighted_average(vecs, weights)
#             class_names.append(cname)
#             class_vectors.append(fused)
#             ptr += k

#     class_vectors = np.array(class_vectors, dtype=EMB_DTYPE)
#     # Normalise for exact cosine similarity with IndexFlatIP
#     norms = np.linalg.norm(class_vectors, axis=1, keepdims=True)
#     norms[norms == 0] = 1.0
#     class_vectors /= norms

#     # 7. Batch FAISS search across all library indexes
#     # Strategy: for each library, search all query vectors at once.
#     logger.info("Batch processing to detect Lib Classses..")
#     best_scores = -1.0 * np.ones(n)
#     best_lib_names = [None] * n
#     best_versions = [None] * n
#     best_lib_classes = [None] * n

#     lib_map = load_library_map(LIB_MAP_CSV)

#     for lib_name, lib_data in lib_indexes.items():
#         index = lib_data["index"]
#         meta = lib_data["meta"]
#         try:
#             D, I = index.search(class_vectors, 1)   # D.shape = (n,1), I.shape = (n,1)
#             scores = D[:, 0]
#             indices = I[:, 0]
#             for idx, (score, hit_idx) in enumerate(zip(scores, indices)):
#                 if hit_idx >= 0 and score > best_scores[idx]:
#                     best_scores[idx] = score
#                     best_lib_names[idx] = lib_name
#                     entry = meta[hit_idx]
#                     best_versions[idx] = entry.get("version", "unknown")
#                     best_lib_classes[idx] = entry.get("class_name", "unknown")
#         except Exception as e:
#             logger.warning(f"Error searching library {lib_name}: {e}")

#     # 8. Build result dict
#     results = {}
#     for idx, cname in enumerate(class_names):
#         score = float(best_scores[idx])
#         is_tpl = score >= threshold
#         readable_lib = lib_map.get(f"{best_lib_names[idx]}.jar", {}).get("library", best_lib_names[idx]) \
#                        if best_lib_names[idx] else None
#         results[cname] = (is_tpl, readable_lib, best_versions[idx], best_lib_classes[idx], score)

#     time_3 = time.time()

#     logger.info(f"Batch TPL detection: {sum(1 for r in results.values() if r[0])}/{n} classes flagged as TPL | Done in {time_3-time_2}Seconds")
#     return results


def batch_detect_tpl(
    class_paths: List[Path],             # list of *.smali file paths
    lib_index_dir: Path,
    embeddings_pkl: Optional[Path] = None,
    threshold: float = 0.95,
    pos_decay_alpha: float = 0.8
) -> Dict[str, Tuple[bool, Optional[str], Optional[str], Optional[str], float]]:
    """
    Detect TPL for a batch of smali classes.

    Returns: dict mapping class_name -> (is_tpl, library_name, version, matched_lib_class, score)
    """
    n = len(class_paths)
    if n == 0:
        return {}

    # ------------------------------------------------------------------
    # 1. Ensure FAISS indexes exist (build merged index if missing)
    # ------------------------------------------------------------------
    index_map_file = lib_index_dir / "library_indexes.pkl"
    merged_index_file = lib_index_dir / "merged.index"
    merged_meta_file = lib_index_dir / "merged_meta.pkl"

    if not merged_index_file.exists():
        # Need per‑library indexes to build the merged one
        if not index_map_file.exists():
            if embeddings_pkl is None:
                raise FileNotFoundError(
                    "FAISS indexes missing and no embeddings_pkl provided to build them."
                )
            logger.info("FAISS indexes not found – building from embeddings...")
            build_faiss_indexes_new(lib_index_dir, embeddings_pkl)

        logger.info("Building merged FAISS index...")
        lib_indexes = load_library_indexes(index_map_file)
        merged_index, id_to_meta = _build_merged_index(lib_indexes)
        faiss.write_index(merged_index, str(merged_index_file))
        with open(merged_meta_file, "wb") as f:
            pickle.dump(id_to_meta, f)
    else:
        logger.info("Loading merged FAISS index...")
        merged_index = faiss.read_index(str(merged_index_file))
        with open(merged_meta_file, "rb") as f:
            id_to_meta = pickle.load(f)

    # ------------------------------------------------------------------
    # 2. Move merged index to GPU (if available)
    # ------------------------------------------------------------------
    # print("IS CUDA AVAIABLE?---->")
    if torch.cuda.is_available():
        # print("CUDA AVAILABLE........")
        res = faiss.StandardGpuResources()
        merged_index = faiss.index_cpu_to_gpu(res, 0, merged_index)
        logger.debug("Merged index moved to GPU")

    # ------------------------------------------------------------------
    # 3. Instantiate embedder (once)
    # ------------------------------------------------------------------
    embedder = MiniLMEmbedder()

    # ------------------------------------------------------------------
    # 4. Pre‑process all classes: read smali, parse blocks, collect texts
    # ------------------------------------------------------------------
    class_info = []          # (class_name, list_of_texts, list_of_weights)
    all_raw_texts = []       # all block texts across all classes
    no_smali_classes = 0
    logger.info("Reading Smali and Parsing....")

    for cls_path in class_paths:
        # logger.info(f"We NEED TO CHSANGE THIS TO GET THE CLASS NAME: {cls_path}")
        # cname = cls_path.stem   # adjust if you need full path–based naming
        import re
        cname = "L" + re.split(r"smali(?:_classes\d+)?/", str(cls_path), maxsplit=1)[1][:-6] + ";"
        try:
            smali_text = cls_path.read_text(errors="ignore")
            no_smali_classes += 1
        except Exception as e:
            logger.debug(f"Failed to read {cls_path}: {e}")
            class_info.append((cname, [], []))
            continue

        blocks = parse_smali_blocks(smali_text)
        texts = []
        weights = []
        for i, block in enumerate(blocks, start=1):
            processed = preprocess_smali_code(block["text"])
            texts.append(processed)
            w = len(processed) * calculate_positional_decay(pos_decay_alpha, i)
            weights.append(w)
        class_info.append((cname, texts, weights))
        all_raw_texts.extend(texts)

    # ------------------------------------------------------------------
    # 5. Batch embedding for all block texts
    # ------------------------------------------------------------------
    t_embed_start = time.time()
    if all_raw_texts:
        logger.info(f"Embedding {len(all_raw_texts)} smali blocks from {n} classes...")
        all_emb = embedder.embed_batch(all_raw_texts)
        all_emb = np.array(all_emb, dtype=EMB_DTYPE)
    else:
        all_emb = np.empty((0, MINI_LM_EMB_DIM), dtype=EMB_DTYPE)
    t_embed_end = time.time()
    logger.info(f"Embedding took {t_embed_end - t_embed_start:.2f} s "
                f"({(t_embed_end - t_embed_start) / max(no_smali_classes, 1):.4f} s per class)")

    # ------------------------------------------------------------------
    # 6. Fuse per‑class vectors (weighted average of block embeddings)
    # ------------------------------------------------------------------
    class_names = []
    class_vectors = []
    ptr = 0
    for cname, texts, weights in class_info:
        k = len(texts)
        if k == 0:
            class_names.append(cname)
            class_vectors.append(np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE))
        else:
            vecs = all_emb[ptr:ptr + k]
            fused = weighted_average(vecs, weights)
            class_names.append(cname)
            class_vectors.append(fused)
            ptr += k

    class_vectors = np.array(class_vectors, dtype=EMB_DTYPE)
    # Normalise for cosine similarity via inner product
    norms = np.linalg.norm(class_vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    class_vectors /= norms

    # ------------------------------------------------------------------
    # 7. Single FAISS search on the merged index
    # ------------------------------------------------------------------
    t_search_start = time.time()
    logger.info("Performing single FAISS search on merged index...")
    k = 1
    D, I = merged_index.search(class_vectors, k)   # D: (n, 1), I: (n, 1)
    scores = D[:, 0]        # cosine similarity (inner product)
    hit_ids = I[:, 0]       # IDs in id_to_meta

    # Map back to library metadata
    best_lib_names = [None] * n
    best_versions = [None] * n
    best_lib_classes = [None] * n

    for idx in range(n):
        if hit_ids[idx] >= 0:
            meta = id_to_meta[hit_ids[idx]]
            best_lib_names[idx] = meta.get("lib_name")    # same keys as built in _build_merged_index
            best_versions[idx] = meta.get("version", "unknown")
            best_lib_classes[idx] = meta.get("class_name", "unknown")

    t_search_end = time.time()
    logger.info(f"FAISS search completed in {t_search_end - t_search_start:.3f} s")

    # ------------------------------------------------------------------
    # 8. Build result dictionary
    # ------------------------------------------------------------------
    # load library map to convert raw lib filename to human‑readable name
    lib_map = load_library_map(LIB_MAP_CSV)
    results = {}
    for idx, cname in enumerate(class_names):
        score = float(scores[idx])
        is_tpl = score >= threshold
        raw_lib_name = best_lib_names[idx]
        readable_lib = (lib_map.get(f"{raw_lib_name}.jar", {}).get("library", raw_lib_name) if raw_lib_name else None)

        # print(f"CNAME: {cname}")
        results[cname] = (
            is_tpl,
            readable_lib,
            best_versions[idx],
            best_lib_classes[idx],
            score,
        )

    logger.info(
        f"Batch TPL detection: {sum(1 for r in results.values() if r[0])}/{n} "
        f"classes flagged as TPL (total FAISS + mapping: {time.time() - t_search_start:.2f} s)"
    )
    return results


# if __name__ == "__main__":
#     APK_DECOMPILED_PATH = Path("/mnt/SATA_4/akila/GraphBasedMD/DroidLens/.droidlens_cache_decomp/0a6d35476819afa791ae37428aeb473ce89a850573ecf486e12afb4bea9d2086/0A6D35476819AFA791AE37428AEB473CE89A850573ECF486E12AFB4BEA9D2086")
#     LIB_INDEX = Path("/mnt/SATA_4/akila/GraphBasedMD/datasets/tpl_embeddings/lib_indexes")
#     EMBEDDING_PKL = Path("/mnt/SATA_4/akila/GraphBasedMD/datasets/tpl_embeddings/smali_raw_embeddings.pkl")
#     smali_files = collect_files(APK_DECOMPILED_PATH, ".smali")

#     results = batch_detect_tpl(smali_files, LIB_INDEX, EMBEDDING_PKL)