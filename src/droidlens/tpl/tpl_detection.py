# from pathlib import Path
# from loguru import logger
# import pickle


# # ---- Helpers
# import os
# from typing import List, Dict, Tuple, Optional
# import re
# import numpy as np
# import faiss
# import csv

# EMB_DTYPE = "NONE"
# MINI_LM_EMB_DIM = "NONE"
# LIB_MAP_CSV = "NONE"

# def collect_files(base_dir: Path, ext: str) -> List[Path]:
#     files = []
#     for root, _, filenames in os.walk(base_dir):
#         for fn in filenames:
#             if fn.endswith(ext) and not ("/resources") in root: # Exclude resource files which can be very large and noisy
#                 files.append(Path(root) / fn)
#     return files


# def read_file_text(path: Path) -> str:
#     try:
#         text = path.read_text(errors="ignore")
#         return text
#     except Exception as e:
#         logger.info("[!] Failed to read file: %s Error: %s", path, e)
#         return ""


# def parse_smali_blocks(smali_code: str):
#     lines = smali_code.splitlines()
#     blocks = []
#     rest_block = []
#     current_block = []
#     in_method = False

#     def flush_method():
#         nonlocal current_block, in_method
#         if current_block:
#             method = "\n".join(current_block).strip()
#             # Extracting method signature
#             # sig = extract_smali_method_sigs(method)
#             blocks.append({
#                 "type": "METHOD",
#                 "text": method 
#             })
#             current_block = []
#             in_method = False

#     for line in lines:
#         stripped = line.strip()

#         # ---- method start ----
#         if stripped.startswith(".method"):
#             flush_method()
#             in_method = True
#             current_block = [line]
#             continue

#         # ---- method end ----
#         if stripped.startswith(".end method") and in_method:
#             current_block.append(line)
#             flush_method()
#             continue

#         # ---- inside method ----
#         if in_method:
#             current_block.append(line)
#         else:
#             # everything else goes to REST
#             rest_block.append(line)

#     flush_method()

#     # prepend REST block if non-empty
#     rest_text = "\n".join(rest_block).strip()
#     if rest_text:
#         blocks.insert(0, {
#             "type": "REST",
#             "text": rest_text
#         })

#     return blocks


# def preprocess_smali_code(smali: str) -> str:
#     patterns = [
#         # Remove source line
#         r'\.source\s+".*?"',
#         # Remove annotation blocks safely
#         r'(?s)\.annotation.*?\.end annotation',
#         # Remove debug info
#         r'\.line \d+',
#         r'\.prologue',
#         r'\.epilogue',
#         r'\.local .*',
#         r'\.end local',
#         r'\.restart local',
#         r'\.param .*',
#         r'\.end param',
#     ]

#     cleaned = smali
#     for p in patterns:
#         cleaned = re.sub(p, '', cleaned)

#     # Remove single line comments ONLY
#     cleaned = re.sub(r'#.*$', '', cleaned, flags=re.MULTILINE)

#     # Clean whitespace
#     cleaned = "\n".join(
#         line.rstrip()
#         for line in cleaned.splitlines()
#         if line.strip()
#     )

#     return cleaned


# def calculate_positional_decay(alpha, i):
#     weight_i = 1 / (1 + alpha * (i - 1))
#     return weight_i


# def normalize_vec(v: np.ndarray) -> np.ndarray:
#     v = v.astype(np.float32)
#     norm = np.linalg.norm(v)
#     if norm == 0:
#         return v
#     return (v / norm).astype(EMB_DTYPE)

# def weighted_average(vectors, weights):
#     if vectors is None or len(vectors) == 0:
#         # logger.info("[!WARN!]: Empty Weights for avearaging blocks. Returning zero vector of size: %s", MINI_LM_EMB_DIM)
#         return np.zeros(MINI_LM_EMB_DIM, dtype=EMB_DTYPE)
#     w = np.array(weights, dtype=np.float32)
#     w = w / (w.sum() + 1e-8)

#     averaged_vector = (w[:, None] * vectors).sum(axis=0)
#     # We normalise the averaged vector
#     norm_vector = normalize_vec(averaged_vector)
#     return norm_vector  


# def embed_smali_blocks_batch(smali_blocks, smali_embedder, pos_decay_alpha):
#     smali_weights = []
#     raw_texts = []
#     block_id = 1

#     for block in smali_blocks:
#         processed = preprocess_smali_code(block["text"])
#         raw_texts.append(processed)
#         positional_decay_8 = calculate_positional_decay(pos_decay_alpha, block_id)
#         smali_weights.append(len(processed) * positional_decay_8)
#         block_id += 1
        
#     raw_emb = smali_embedder.embed_batch(raw_texts)   
#     smali_raw_cls   = weighted_average(raw_emb, smali_weights)
#     return smali_raw_cls


# def load_library_map(csv_path: str) -> Dict[str, Dict[str, str]]:
#     library_map = {}
#     with open(csv_path, newline='') as csvfile:
#         reader = csv.reader(csvfile)
#         for jar, library, version in reader:
#             library_map[jar.strip()] = {"library": library.strip(), "version": version.strip()}
#     return library_map

# lib_map = load_library_map(LIB_MAP_CSV)


# def build_library_specific_index(embeddings: list, lib_name: str, out_dir: Path) -> Tuple[Optional[Path], Optional[Path]]:
#     """Builds a FAISS index for a specific library and its versions."""
#     logger.info("LIB NAME READ FROM PACKAGE NAME: %s", lib_name)
#     # Filter embeddings for this library
#     lib_embeddings = [e for e in embeddings if e['package_name'] == lib_name]

#     if not lib_embeddings:
#         return None, None
    
#     # Here loads the FUSED EMBEDDINGS
#     vecs = np.array([normalize_vec(e['smali_raw']) for e in lib_embeddings], dtype=EMB_DTYPE)
#     dim = vecs.shape[1]
#     index = faiss.IndexFlatIP(dim)
#     index.add(vecs)
    
#     # Create library-specific files
#     ### ---- NOTE: out_dir -- FAISS Directory ---- ###
#     index_file = out_dir / f"{lib_name.replace('.', '_')}.index"
#     meta_file = out_dir / f"{lib_name.replace('.', '_')}_meta.pkl"
    
#     out_dir.mkdir(parents=True, exist_ok=True)
#     faiss.write_index(index, str(index_file))
    
#     # Save meta with class names and version info
#     meta = [
#         {
#             "class_name": e['class_name'],
#             "package_name": e['package_name'],
#             "version": lib_map.get(f"{e['package_name']}.jar", {}).get('version', 'unknown_version')
#         }
#         for e in lib_embeddings
#     ]
#     with open(meta_file, "wb") as fh:
#         pickle.dump(meta, fh)
    
#     return index_file, meta_file

# def build_faiss_indexes_new(faiss_dir, embeddings_pkl: Path) -> Path:
#     """Builds separate FAISS indexes for each library from embeddings."""
#     if not embeddings_pkl.exists():
#         raise FileNotFoundError(f"Embeddings file not found: {embeddings_pkl}")
#     with open(embeddings_pkl, "rb") as fh:
#         embeddings = pickle.load(fh)
#     if not embeddings:
#         raise RuntimeError("No embeddings in file")
#     # Group by library name
#     libraries = {e['package_name'] for e in embeddings}
#     library_indexes = {}

#     for lib in libraries:
#         logger.info("Library: %s - Building index... ", lib)
#         index_file, meta_file = build_library_specific_index(embeddings, lib, faiss_dir)
#         if index_file:
#             library_indexes[lib] = {
#                 "index_file": index_file,
#                 "meta_file": meta_file
#             }
#     # Save library index mapping
#     index_map_file = faiss_dir / "library_indexes.pkl"
#     with open(index_map_file, "wb") as fh:
#         pickle.dump(library_indexes, fh)

#     logger.info("[+] Built %d library-specific indexes in %s", len(library_indexes), faiss_dir)
#     for lib, files in library_indexes.items():
#         logger.info("  - %s: %s", lib, files['index_file'].name)

#     return index_map_file


# def load_library_indexes(index_map_file: Path) -> Dict[str, Dict]:
#     """Load all library indexes and their metadata."""
#     with open(index_map_file, "rb") as fh:
#         library_indexes = pickle.load(fh)
    
#     loaded_indexes = {}
#     for lib_name, files in library_indexes.items():
#         index = faiss.read_index(str(files["index_file"]))
#         with open(files["meta_file"], "rb") as fh:
#             meta = pickle.load(fh)
#         loaded_indexes[lib_name] = {"index": index, "meta": meta}
    
#     return loaded_indexes



# def generate_class_embeddings(class_path: Path):
#     from miniLM_embedder import MiniLMEmbedder
#     embedder = MiniLMEmbedder()
#     pos_decay_alpha = 0.8
    
#     cname, package_name = get_cname_package_from_path(class_path)
#     smali_text = read_file_text(class_path)
#     smali_blocks = parse_smali_blocks(smali_text)
#     smali_raw_emb = embed_smali_blocks_batch(smali_blocks, embedder, pos_decay_alpha)
#     return cname, package_name, smali_raw_emb


# def generate_lib_embeddings(lib_root_dir: Path, lib_smali_path: Path, out_file):
#     lib_root_dir.mkdir(parents=True, exist_ok=True)
#     if out_file is None:
#         out_file = lib_root_dir / "lib_embeddings_unknwn.pkl"

#     lib_embeddings = []
#     smali_files = collect_files(lib_smali_path, ".smali")
#     for smali_file in smali_files:
#         cname, package_name, smali_raw_emb = generate_class_embeddings(smali_file)

#         lib_embeddings.append({"class_name": cname,"package_name": package_name,"smali_raw": smali_raw_emb,})

#     with open(out_file, "wb") as fh:
#         pickle.dump(lib_embeddings, fh)
#         logger.info(f"Saved {len(lib_embeddings)} library class embeddings to {out_file}")
    

# def is_class_TPL(lib_index_dir: Path, embeddings_pkl: Path, out_dir: Path, class_path: Path):
#     index_map = lib_index_dir / "library_indexes.pkl"
#     out_dir.mkdir(parents=True, exist_ok=True)

#     if not index_map.exists():
#         logger.info("[*] Building FAISS library indexes in %s", lib_index_dir) #If this is the first time that tpl detection running we need to create the faiss indexes
#         build_faiss_indexes_new(lib_index_dir, embeddings_pkl)
#     lib_indexes = load_library_indexes(index_map)
#     cname, package_name, smali_emb_detect_class = generate_class_embeddings(class_path)

#     #Then using below method we need to check in the library indexes whther we have a same class embedding that similiartiy is more than 95%
#     Then we can return True (saying this class belongs to a known TPL) False if no sim matches
#     for apk_emb in apk_embeddings:
#             try:
#                 apk_vectors.append(apk_emb[apk_e_read])
#             except KeyError:
#                 raise KeyError(f"Missing {apk_e_read} embedding in apk_emb")
#         logger.info("[*] Total APK classes with embeddings: %d", len(apk_vectors))
#         for apk_emb, apk_vec in zip(apk_embeddings, apk_vectors):
#             best_score = -1
#             best_lib = None
#             best_version = None
#             best_lib_class = None

#             for lib_name, lib_index in lib_indexes.items():
#                 index = lib_index["index"]
#                 meta = lib_index["meta"]
#                 vec = np.array([apk_vec]).astype(np.float32)
#                 D, I = index.search(vec, 1)
#                 if I[0][0] >= 0 and D[0][0] > best_score:
#                     match_meta = meta[I[0][0]]
#                     best_score = D[0][0]
#                     best_lib = lib_map.get(f"{lib_name}.jar", {}).get("library", "unknown_lib")
#                     if best_lib == "unknown_lib":
#                         logger.error("[!WARN] Unknown Library detected: %s.jar", lib_name)
#                     best_version = match_meta.get("version", "unknown")
#                     best_lib_class = match_meta.get("class_name", "unknown")
#             if best_lib is not None and best_score >= 0:
#                 best_matches.append({
#                     "apk_class": apk_emb["class_name"],
#                     "best_lib": best_lib,
#                     "best_version": best_version,
#                     "best_lib_class": best_lib_class,
#                     "score": float(best_score)
#                 })


# # 1. raw smali code --> parse_smali_blocks (per class)
# # 2. embed_smali_blocks_batch --> stor lib_embeddings: smali_raw_emb
# # 3. save lib_embeddings.pkl
# # 4. build_faiss_indexes_new() --> build faiss indexes from the lib embeddings
# # 5. When apk comes --> generate class level embedding smali raw -> faiss match with smali > 90% no importance will be calculated for that smali class (Library Class)