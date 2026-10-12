"""Worker script that loads PyTorch, runs TPL batch, and saves results."""
import sys
import pickle
import json
from pathlib import Path
from droidlens.tpl.batch_detect_tpl import batch_detect_tpl

def main():
    if len(sys.argv) != 4:
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    config_json = sys.argv[3]   # JSON with lib_index_dir, embeddings_pkl, threshold, etc.

    with open(input_file, 'rb') as f:
        smali_paths = pickle.load(f)  # list of Path objects

    print("##################### RUNNING TPL WORKER.....")

    cfg = json.loads(config_json)
    results = batch_detect_tpl(
        class_paths=smali_paths,
        lib_index_dir=Path(cfg["lib_index_dir"]),
        embeddings_pkl=Path(cfg["embeddings_pkl"]),
        threshold=cfg["threshold"],
        pos_decay_alpha=cfg.get("pos_decay_alpha", 0.8),
    )

    with open(output_file, 'wb') as f:
        pickle.dump(results, f)

if __name__ == "__main__":
    main()
