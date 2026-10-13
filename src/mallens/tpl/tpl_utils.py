"""
Utility functions for Third‑Party Library (TPL) detection in Android smali code.
Handles file I/O, smali parsing, embedding generation, FAISS index building and loading.
"""
from pathlib import Path
import os
import re
import pickle
import csv
import numpy as np
import faiss
from loguru import logger
from typing import List, Dict, Tuple, Optional, Any

# ----------------------------------------------------------------------
#  CONFIGURATION (adjust paths / dimensions to your setup)
# ----------------------------------------------------------------------
EMB_DTYPE = np.float32
MINI_LM_EMB_DIM = 384          # typical for MiniLM‑L6‑v2
LIB_MAP_CSV = "LibMap.csv"    # path to your library‑mapping CSV

# ----------------------------------------------------------------------
#  FILE & TEXT HELPERS
# ----------------------------------------------------------------------
def collect_files(base_dir: Path, ext: str) -> List[Path]:
    """Recursively collect files with a given extension, skipping resource directories."""
    files = []
    try:
        for root, _, filenames in os.walk(base_dir):
            if "resources" in root:
                continue
            for fn in filenames:
                if fn.endswith(ext):
                    files.append(Path(root) / fn)
    except Exception as e:
        logger.error(f"Failed to walk directory {base_dir}: {e}")
    return files


def read_file_text(path: Path) -> str:
    """Read file content safely, returning empty string on error."""
    try:
        return path.read_text(errors="ignore")
    except Exception as e:
        logger.warning(f"Failed to read {path}: {e}")
        return ""


def load_library_map(csv_path: str) -> Dict[str, Dict[str, str]]:
    """
    Load library jar‑to‑name & version mapping from CSV.
    CSV format: jar_name, library_name, version
    """
    library_map = {}
    try:
        with open(csv_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for jar, library, version in reader:
                library_map[jar.strip()] = {
                    "library": library.strip(),
                    "version": version.strip()
                }
        logger.debug(f"Loaded {len(library_map)} library entries from {csv_path}")
    except FileNotFoundError:
        logger.warning(f"Library map CSV not found: {csv_path}")
    except Exception as e:
        logger.error(f"Error reading library map CSV: {e}")
    return library_map


# ----------------------------------------------------------------------
#  SMALI PARSING & PREPROCESSING
# ----------------------------------------------------------------------
def extract_smali_class_name(smali_code: str) -> Optional[str]:
    """Extract the fully‑qualified class name from a .class directive."""
    match = re.search(r'\.class\s+(?:public|private|protected)?\s*(?:final|abstract|synthetic)?\s*(?:interface|enum|annotation)?\s+L(.+?);',
                      smali_code, re.MULTILINE)
    if match:
        return match.group(1).replace('/', '.')
    return None


def get_cname_package_from_path(class_path: Path) -> Tuple[str, str]:
    """
    Infer class name and package from a smali file path.
    Works with standard Android reverse‑engineering directory layouts.
    """
    # The class name is the file stem (without .smali)
    cname = class_path.stem
    # Try to find smali directory structure; package is derived from the relative path.
    # Assume a structure like: .../smali/org/example/MyClass.smali
    parts = list(class_path.parts)
    try:
        smali_idx = parts.index("smali")  # look for 'smali' folder
        package_parts = parts[smali_idx+1:-1]
        package_name = ".".join(package_parts)
    except ValueError:
        # Fallback: if 'smali' not in path, use everything after the first component as package
        package_name = ".".join(parts[1:-1]) if len(parts) > 2 else cname
    logger.debug(f"Class {cname} -> package {package_name}")
    return cname, package_name


def parse_smali_blocks(smali_code: str) -> List[Dict[str, str]]:
    """
    Split smali code into REST block (field declarations, etc.)
    and METHOD blocks (each .method ... .end method).
    Returns ordered list of dicts: {'type': 'REST'|'METHOD', 'text': str}
    """
    lines = smali_code.splitlines()
    blocks = []
    rest_lines = []
    current_method = []
    in_method = False

    def flush_method():
        nonlocal current_method, in_method
        if current_method:
            text = "\n".join(current_method).strip()
            blocks.append({"type": "METHOD", "text": text})
            current_method = []
            in_method = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(".method"):
            flush_method()
            in_method = True
            current_method = [line]
            continue
        if stripped.startswith(".end method") and in_method:
            current_method.append(line)
            flush_method()
            continue
        if in_method:
            current_method.append(line)
        else:
            rest_lines.append(line)

    flush_method()
    rest_text = "\n".join(rest_lines).strip()
    if rest_text:
        blocks.insert(0, {"type": "REST", "text": rest_text})
    return blocks


def preprocess_smali_code(smali: str) -> str:
    """Remove debug info, comments, annotations and clean whitespace."""
    patterns = [
        r'\.source\s+".*?"',
        r'(?s)\.annotation.*?\.end annotation',
        r'\.line \d+',
        r'\.prologue',
        r'\.epilogue',
        r'\.local .*',
        r'\.end local',
        r'\.restart local',
        r'\.param .*',
        r'\.end param',
    ]
    cleaned = smali
    for p in patterns:
        cleaned = re.sub(p, '', cleaned)
    cleaned = re.sub(r'#.*$', '', cleaned, flags=re.MULTILINE)   # single‑line comments
    cleaned = "\n".join(line.rstrip() for line in cleaned.splitlines() if line.strip())
    return cleaned


def calculate_positional_decay(alpha: float, position: int) -> float:
    """Higher weight for earlier blocks (position starts at 1)."""
    return 1.0 / (1.0 + alpha * (position - 1))


def normalize_vec(v: np.ndarray) -> np.ndarray:
    """Normalise to unit length. If zero vector, return as is."""
    v = v.astype(EMB_DTYPE)
    norm = np.linalg.norm(v)
    if norm == 0:
        return v
    return (v / norm).astype(EMB_DTYPE)


def weighted_average(vectors: np.ndarray, weights: List[float]) -> np.ndarray:
    """Compute length‑weighted + position‑weighted average vector and normalise."""
    if vectors is None or len(vectors) == 0:
        return np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE)
    w = np.array(weights, dtype=EMB_DTYPE)
    w = w / (w.sum() + 1e-8)
    averaged = (w[:, None] * vectors).sum(axis=0)
    return normalize_vec(averaged)


# ----------------------------------------------------------------------
#  EMBEDDING GENERATION
# ----------------------------------------------------------------------
def embed_smali_blocks_batch(
    smali_blocks: List[Dict[str, str]],
    embedder,                     # expects MiniLMEmbedder with embed_batch method
    pos_decay_alpha: float = 0.8
) -> np.ndarray:
    """
    Embed a list of smali blocks, apply positional decay, and return the fused vector.
    Returns a normalised embedding of shape (MINI_LM_EMB_DIM,).
    """
    raw_texts = []
    weights = []
    for i, block in enumerate(smali_blocks, start=1):
        processed = preprocess_smali_code(block["text"])
        raw_texts.append(processed)
        # Length weight * positional weight
        len_weight = len(processed)
        pos_weight = calculate_positional_decay(pos_decay_alpha, i)
        weights.append(len_weight * pos_weight)

    if not raw_texts:
        logger.warning("No smali blocks to embed")
        return np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE)

    try:
        raw_emb = embedder.embed_batch(raw_texts)   # returns list/array of vectors
        raw_emb = np.array(raw_emb, dtype=EMB_DTYPE)
    except Exception as e:
        logger.error(f"Embedding batch failed: {e}")
        return np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE)

    return weighted_average(raw_emb, weights)


def generate_class_embeddings(class_path: Path, embedder) -> Tuple[str, str, np.ndarray]:
    """
    For a single .smali file, return (class_name, package_name, embedding).
    Requires MiniLMEmbedder to be importable.
    """
    cname, package = get_cname_package_from_path(class_path)
    smali_text = read_file_text(class_path)
    if not smali_text:
        logger.warning(f"Empty file: {class_path}")
        return cname, package, np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE)

    smali_blocks = parse_smali_blocks(smali_text)
    emb = embed_smali_blocks_batch(smali_blocks, embedder, pos_decay_alpha=0.8)
    return cname, package, emb


def generate_lib_embeddings(
    lib_root_dir: Path,
    lib_smali_path: Path,
    out_file: Optional[Path] = None
) -> Path:
    """
    Process all .smali files under lib_smali_path, generate library class embeddings,
    and save as a pickle file. Returns path to the saved file.
    """
    lib_root_dir.mkdir(parents=True, exist_ok=True)
    if out_file is None:
        out_file = lib_root_dir / "lib_embeddings.pkl"

    logger.info(f"Generating Lib Embeddings: {lib_smali_path} and output to: {out_file}")
    embeddings = []
    smali_files = collect_files(lib_smali_path, ".smali")
    logger.info(f"Processing {len(smali_files)} library smali files...")
    try:
        from mallens.tpl.miniLM_embedder import MiniLMEmbedder
    except ImportError:
        logger.critical("miniLM_embedder.MiniLMEmbedder not found. Install the embedding model.")
        raise
    
    embedder = MiniLMEmbedder()
    for idx, smali_file in enumerate(smali_files, 1):
        try:
            cname, package, emb = generate_class_embeddings(smali_file, embedder)
            # print(f"CNAME: {cname} | Package_name: {package}")
            embeddings.append({
                "class_name": cname,
                "package_name": package,
                "smali_raw": emb
            })
            if idx % 100 == 0:
                logger.info(f"  ...processed {idx}/{len(smali_files)}")
        except Exception as e:
            logger.warning(f"Skipping {smali_file}: {e}")

    with open(out_file, "wb") as fh:
        pickle.dump(embeddings, fh)
    logger.success(f"Saved {len(embeddings)} library class embeddings to {out_file}")
    return out_file


# ----------------------------------------------------------------------
#  FAISS INDEX MANAGEMENT
# ----------------------------------------------------------------------
def build_library_specific_index(
    embeddings: List[Dict],
    lib_name: str,
    out_dir: Path
) -> Tuple[Optional[Path], Optional[Path]]:
    """
    For a given library (package root), build a FAISS Inner‑Product index
    from its smali_raw embeddings. Saves .index and _meta.pkl files.
    """
    lib_embeddings = [e for e in embeddings if e["package_name"] == lib_name]
    if not lib_embeddings:
        logger.warning(f"No embeddings for library {lib_name}")
        return None, None

    vecs = np.array([normalize_vec(e["smali_raw"]) for e in lib_embeddings], dtype=EMB_DTYPE)
    dim = vecs.shape[1]
    index = faiss.IndexFlatIP(dim)
    try:
        index.add(vecs)
    except Exception as e:
        logger.error(f"Failed to add vectors to FAISS index for {lib_name}: {e}")
        return None, None

    out_dir.mkdir(parents=True, exist_ok=True)
    index_file = out_dir / f"{lib_name.replace('.', '_')}.index"
    meta_file = out_dir / f"{lib_name.replace('.', '_')}_meta.pkl"

    faiss.write_index(index, str(index_file))
    meta = []
    for e in lib_embeddings:
        meta.append({
            "class_name": e["class_name"],
            "package_name": e["package_name"],
            "version": load_library_map(LIB_MAP_CSV).get(f"{lib_name}.jar", {}).get("version", "unknown")
        })
    with open(meta_file, "wb") as fh:
        pickle.dump(meta, fh)

    return index_file, meta_file


def build_faiss_indexes_new(
    faiss_dir: Path,
    embeddings_pkl: Path
) -> Path:
    """
    From a pickle of library embeddings, create per‑library FAISS indexes.
    Saves a mapping dict (library_indexes.pkl) in faiss_dir.
    """
    if not embeddings_pkl.exists():
        raise FileNotFoundError(f"Embeddings file not found: {embeddings_pkl}")
    with open(embeddings_pkl, "rb") as fh:
        all_embeddings = pickle.load(fh)
    if not all_embeddings:
        raise RuntimeError("No embeddings in file")

    libraries = {e["package_name"] for e in all_embeddings}
    library_indexes = {}

    for lib in libraries:
        logger.debug(f"Building index for library: {lib}")
        index_file, meta_file = build_library_specific_index(all_embeddings, lib, faiss_dir)
        if index_file:
            library_indexes[lib] = {"index_file": str(index_file), "meta_file": str(meta_file)}

    index_map_file = faiss_dir / "library_indexes.pkl"
    with open(index_map_file, "wb") as fh:
        pickle.dump(library_indexes, fh)

    logger.success(f"Built {len(library_indexes)} library‑specific indexes in {faiss_dir}")
    for lib, files in library_indexes.items():
        logger.info(f"  - {lib}: {Path(files['index_file']).name}")
    return index_map_file


def load_library_indexes(index_map_file: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load all FAISS indexes and their metadata into a dict:
    { lib_name: {'index': faiss.Index, 'meta': list} }
    """
    if not index_map_file.exists():
        logger.error(f"Library index map not found: {index_map_file}")
        return {}
    with open(index_map_file, "rb") as fh:
        library_indexes = pickle.load(fh)

    loaded = {}
    for lib_name, files in library_indexes.items():
        try:
            index = faiss.read_index(files["index_file"])
            with open(files["meta_file"], "rb") as fh:
                meta = pickle.load(fh)
            loaded[lib_name] = {"index": index, "meta": meta}
        except Exception as e:
            logger.error(f"Failed to load index for {lib_name}: {e}")
    logger.info(f"Loaded {len(loaded)} library indexes")
    return loaded
