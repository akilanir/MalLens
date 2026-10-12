import hashlib, json, re
from pathlib import Path
from dataclasses import asdict
from droidlens.core.datatypes import ClassFactSheet, FactEntry

def src_hash(source: str) -> str:
    # normalize whitespace so jadx cosmetic differences don't split the cache
    return hashlib.sha256(re.sub(r"\s+", " ", source).strip()
                          .encode("utf-8")).hexdigest()

class FactSheetCache:
    def __init__(self, cache_dir: str, model: str, prompt_version: str):
        self.root = (Path(cache_dir) / "factsheets"
                     / model.replace("/", "_") / prompt_version)
        self.root.mkdir(parents=True, exist_ok=True)

    def _p(self, h: str) -> Path:
        return self.root / h[:2] / f"{h}.json"

    def get(self, h: str) -> ClassFactSheet | None:
        p = self._p(h)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        for k in ("sources", "sinks", "transforms", "triggers"):
            d[k] = [FactEntry(**e) for e in d[k]]
        return ClassFactSheet(**d)

    def put(self, fs: ClassFactSheet) -> None:
        p = self._p(fs.src_hash)
        p.parent.mkdir(exist_ok=True)
        p.write_text(json.dumps(asdict(fs), ensure_ascii=False))
