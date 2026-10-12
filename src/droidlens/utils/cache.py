"""sha256-keyed artifact cache: .droidlens_cache/<sha256>/<stage>.pkl.gz
Every expensive stage checks here first — re-running experiments must
never re-analyze an APK."""
from __future__ import annotations

import gzip
import hashlib
import json
import pickle
import time
from pathlib import Path
from typing import Any

from loguru import logger


def sha256_of_file(path: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while blob := fh.read(chunk):
            h.update(blob)
    return h.hexdigest()


class ArtifactCache:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _dir(self, sha256: str) -> Path:
        d = self.root / sha256
        d.mkdir(parents=True, exist_ok=True)
        return d

    def path_for(self, sha256: str, stage: str) -> Path:
        return self._dir(sha256) / f"{stage}.pkl.gz"

    def has(self, sha256: str, stage: str) -> bool:
        return self.path_for(sha256, stage).exists()

    def save(self, sha256: str, stage: str, obj: Any, meta: dict | None = None) -> Path:
        p = self.path_for(sha256, stage)
        print(f"This is P: {p}")
        tmp = p.with_suffix(".tmp")          # atomic-ish write
        print(f"This is temp: {tmp}")
        with gzip.open(tmp, "wb", compresslevel=6) as fh:
            pickle.dump(obj, fh, protocol=pickle.HIGHEST_PROTOCOL)
        tmp.replace(p)
        meta_p = self._dir(sha256) / f"{stage}.meta.json"
        meta_p.write_text(json.dumps(
            {"stage": stage, "saved_at": time.time(), **(meta or {})}, indent=2))
        logger.debug(f"cached {stage} -> {p}")
        return p

    def load(self, sha256: str, stage: str) -> Any:
        with gzip.open(self.path_for(sha256, stage), "rb") as fh:
            return pickle.load(fh)

