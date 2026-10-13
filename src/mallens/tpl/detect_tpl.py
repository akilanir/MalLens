"""
Main TPL detection logic.
Uses tpl_utils.py to generate embeddings and query pre‑built FAISS indexes.
Can be run as a script or imported to call is_class_TPL / detect_apk_tpl.
"""
import sys
from pathlib import Path
from loguru import logger
import numpy as np
from typing import Tuple, Optional, Dict, List

from mallens.tpl.tpl_utils import (
    generate_class_embeddings,
    load_library_indexes,
    build_faiss_indexes_new,
    generate_lib_embeddings,
    collect_files,
    load_library_map,
    LIB_MAP_CSV,
    MINI_LM_EMB_DIM,
    EMB_DTYPE
)

# Configure logger (adjust to your needs)
logger.remove()
logger.add(sys.stderr, level="INFO")


def is_class_TPL(
    class_path: Path,
    lib_index_dir: Path,
    embeddings_pkl: Path,
    threshold: float = 0.95
) -> Tuple[bool, Optional[str], Optional[str], Optional[str], float]:
    """
    Check if a single smali class belongs to a known TPL.
    Returns:
        is_tpl (bool),
        best_lib_name (str or None),
        best_version (str or None),
        best_lib_class (str or None),
        best_score (float)
    """
    index_map = lib_index_dir / "library_indexes.pkl"
    # Build indexes if missing
    if not index_map.exists():
        logger.info("FAISS indexes not found, building them...")
        try:
            build_faiss_indexes_new(lib_index_dir, embeddings_pkl)
        except Exception as e:
            logger.error(f"Index building failed: {e}")
            return False, None, None, None, 0.0

    lib_indexes = load_library_indexes(index_map)
    if not lib_indexes:
        logger.error("No library indexes loaded.")
        return False, None, None, None, 0.0

    # Generate embedding for the target class
    try:
        from mallens.tpl.miniLM_embedder import MiniLMEmbedder
    except ImportError:
        logger.critical("miniLM_embedder.MiniLMEmbedder not found. Install the embedding model.")
        raise
    embedder = MiniLMEmbedder()
    try:
        cname, package, emb = generate_class_embeddings(class_path,embedder)
    except Exception as e:
        logger.error(f"Failed to embed {class_path}: {e}")
        return False, None, None, None, 0.0

    # Normalize and prepare query vector
    vec = np.array([emb], dtype=EMB_DTYPE)
    vec /= np.linalg.norm(vec)  # guarantee unit length (redundant but safe)

    best_score = -1.0
    best_lib_name = None
    best_version = None
    best_lib_class = None

    # Search across all library indexes
    for lib_name, lib_data in lib_indexes.items():
        index = lib_data["index"]
        meta = lib_data["meta"]
        try:
            D, I = index.search(vec, 1)   # inner product for unit vectors = cosine similarity
            if I[0][0] >= 0:
                score = float(D[0][0])
                if score > best_score:
                    best_score = score
                    best_lib_name = lib_name
                    entry = meta[I[0][0]]
                    best_version = entry.get("version", "unknown")
                    best_lib_class = entry.get("class_name", "unknown")
        except Exception as e:
            logger.debug(f"Error searching index for {lib_name}: {e}")

    # Resolve library name to a more readable form using the map
    lib_map = load_library_map(LIB_MAP_CSV)
    readable_lib = None
    if best_lib_name:
        readable_lib = lib_map.get(f"{best_lib_name}.jar", {}).get("library", best_lib_name)

    is_tpl = best_score >= threshold
    logger.info(
        f"Class {class_path.name}: best score={best_score:.4f}, "
        f"lib={readable_lib}, version={best_version}, threshold={threshold} -> {'TPL' if is_tpl else 'NOT TPL'}"
    )

    return is_tpl, readable_lib, best_version, best_lib_class, best_score


def detect_apk_tpl(
    apk_smali_dir: Path,
    lib_index_dir: Path,
    embeddings_pkl: Path,
    threshold: float = 0.95,
    output_csv: Optional[Path] = None
) -> List[Dict]:
    """
    Scan all .smali files in an APK directory, detect TPL classes, and optionally write CSV report.
    Returns a list of match details.
    """
    smali_files = collect_files(apk_smali_dir, ".smali")
    logger.info(f"Scanning {len(smali_files)} smali files for TPL...")
    results = []

    for smali_file in smali_files:
        try:
            is_tpl, lib, ver, lib_class, score = is_class_TPL(
                smali_file, lib_index_dir, embeddings_pkl, threshold
            )
            if is_tpl:
                results.append({
                    "apk_class": smali_file.stem,
                    "library": lib,
                    "version": ver,
                    "matched_lib_class": lib_class,
                    "score": round(score, 4)
                })
        except Exception as e:
            logger.warning(f"Skipping {smali_file}: {e}")

    if output_csv and results:
        import csv
        output_csv = Path(output_csv)
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        with open(output_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["apk_class", "library", "version", "matched_lib_class", "score"])
            writer.writeheader()
            writer.writerows(results)
        logger.success(f"TPL report saved to {output_csv}")

    logger.info(f"Found {len(results)} TPL classes out of {len(smali_files)}")
    return results


# ----------------------------------------------------------------------
#  COMMAND‑LINE INTERFACE
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="TPL Detection for Android smali")
    subparsers = parser.add_subparsers(dest="command")

    # ---- Subcommand: index (build library FAISS indexes) ----
    index_parser = subparsers.add_parser("index", help="Build FAISS indexes from library embeddings")
    index_parser.add_argument("--embed_pkl", required=True, help="Pickle file of library class embeddings")
    index_parser.add_argument("--out_dir", required=True, help="Directory to store built indexes")

    # ---- Subcommand: generate (create library embeddings from smali) ----
    gen_parser = subparsers.add_parser("generate", help="Generate library class embeddings from smali directory")
    gen_parser.add_argument("--lib_smali", required=True, help="Root directory of library smali files")
    gen_parser.add_argument("--out_pkl", required=True, help="Output pickle file for embeddings")

    # ---- Subcommand: scan (check a single class) ----
    scan_parser = subparsers.add_parser("scan", help="Check if a single smali class is TPL")
    scan_parser.add_argument("--class_path", required=True, help="Path to the .smali file")
    scan_parser.add_argument("--index_dir", required=True, help="Directory containing library_indexes.pkl and indexes")
    scan_parser.add_argument("--embed_pkl", required=True, help="Library embeddings pickle (for index building if needed)")
    scan_parser.add_argument("--threshold", type=float, default=0.95)

    # ---- Subcommand: detect‑apk (batch scan) ----
    detect_parser = subparsers.add_parser("detect-apk", help="Scan all smali in an APK directory")
    detect_parser.add_argument("--apk_smali", required=True, help="APK smali root directory")
    detect_parser.add_argument("--index_dir", required=True, help="Directory with built indexes")
    detect_parser.add_argument("--embed_pkl", required=True, help="Library embeddings pickle")
    detect_parser.add_argument("--threshold", type=float, default=0.95)
    detect_parser.add_argument("--output_csv", help="Optional CSV report path")

    args = parser.parse_args()

    if args.command == "index":
        build_faiss_indexes_new(Path(args.out_dir), Path(args.embed_pkl))

    elif args.command == "generate":
        generate_lib_embeddings(
            lib_root_dir=Path(args.out_pkl).parent,
            lib_smali_path=Path(args.lib_smali),
            out_file=Path(args.out_pkl)
        )

    elif args.command == "scan":
        is_tpl, lib, ver, cls, score = is_class_TPL(
            Path(args.class_path),
            Path(args.index_dir),
            Path(args.embed_pkl),
            args.threshold
        )
        print(f"TPL: {is_tpl}, Library: {lib}, Version: {ver}, Best Lib Class: {cls}, Score: {score:.4f}")

    elif args.command == "detect-apk":
        detect_apk_tpl(
            apk_smali_dir=Path(args.apk_smali),
            lib_index_dir=Path(args.index_dir),
            embeddings_pkl=Path(args.embed_pkl),
            threshold=args.threshold,
            output_csv=args.output_csv if args.output_csv else None
        )

    else:
        parser.print_help()
