"""jadx wrapper. Runs once per APK into the artifact cache directory
(kept as real files — the LLM stage reads them later). Non-fatal on
failure: callers fall back to bytecode_size."""
from __future__ import annotations

import subprocess
from pathlib import Path

from loguru import logger

from mallens.config import Config


class JadxOutput:
    def __init__(self, sources_dir: Path | None):
        self.sources_dir = sources_dir
        self.ok = sources_dir is not None

    def java_path_for(self, smali_name: str) -> Path | None:
        """'Lcom/foo/Bar$Inner;' -> sources/com/foo/Bar.java (inner classes
        live in the outer class's file)."""
        if not self.ok:
            return None
        inner = smali_name.strip()
        if not (inner.startswith("L") and inner.endswith(";")):
            return None
        rel = inner[1:-1].split("$")[0] + ".java"
        p = self.sources_dir / rel
        # if p.is_file():
        #     return p
        # else:
        #     print(f"Cannot find the java file: {smali_name}:-> {p}")
        #     return None
        return p if p.is_file() else None

    def loc_for(self, smali_name: str) -> int | None:
        p = self.java_path_for(smali_name)
        if p is None:
            return None
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return sum(1 for line in fh if line.strip())
        except OSError:
            return None


def run_jadx(apk_path: str | Path, sha256: str, cfg: Config) -> JadxOutput:
    out_dir = Path(cfg.paths.cache_dir_decomp) / sha256 / "jadx"
    marker = out_dir / ".done"
    sources = out_dir / "sources"

    if marker.exists() and sources.is_dir():
        logger.info(f"jadx cache hit [{sha256[:12]}]")
        return JadxOutput(sources)

    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [cfg.paths.jadx_binary, "-d", str(out_dir),
           *cfg.features.jadx_extra_args, str(apk_path)]
    logger.info(f"jadx: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.features.jadx_timeout_seconds)
    except subprocess.TimeoutExpired:
        logger.error(f"jadx timeout after {cfg.features.jadx_timeout_seconds}s")
        return JadxOutput(sources if sources.is_dir() else None)  # partial ok
    except FileNotFoundError:
        logger.error(f"jadx binary not found: {cfg.paths.jadx_binary}")
        return JadxOutput(None)

    # jadx exits 1 on partial decompile errors — partial output is fine.
    n_files = sum(1 for _ in sources.rglob("*.java")) if sources.is_dir() else 0
    if n_files == 0:
        logger.error(f"jadx produced no sources (rc={proc.returncode}): " f"{proc.stderr[-500:] if proc.stderr else ''}")
        return JadxOutput(None)
    marker.touch()
    logger.info(f"jadx ok: {n_files} java files (rc={proc.returncode})")
    return JadxOutput(sources)


def run_apktool(apk_path: Path, cfg: Config, sha256: str, force: bool = False) -> Path:
    """
    Decompile APK with apktool (smali).
    Skips decompilation if outputs already exist unless force=True.
    Returns (apktool_out_dir)
    """
    logger.info(f"SHA 256: {sha256}")
    out_dir = Path(cfg.paths.cache_dir_decomp) / sha256 / "apktool"

    marker = out_dir / ".done"
    
    if not force and marker.exists() and out_dir.is_dir():
        logger.info(f"jadx cache hit [{sha256[:12]}]")
        return Path(out_dir)
    
    out_dir.mkdir(parents=True, exist_ok=True)

    def is_apktool_decompiled(apktool_out: Path) -> bool:
        return ((apktool_out / "AndroidManifest.xml").exists() and any(apktool_out.glob("smali*")))

    # ----- apktool -----
    if not force and is_apktool_decompiled(out_dir):
        logger.info(f"[✓] apktool already decompiled → {out_dir}")
    else:
        cmd = [cfg.paths.apktool_binary, "d", str(apk_path), "-o", str(out_dir), "--force"]
        logger.info(f"[i] Running apktool → {cmd}")
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.features.apktool_timeout_seconds)
        except subprocess.TimeoutExpired:
            logger.error(f"jadx timeout after {cfg.features.jadx_timeout_seconds}s")
            return (Path(out_dir) if out_dir.is_dir() else None)
        except FileNotFoundError:
            logger.error(f"apktool binary not found: {cfg.paths.apktool_binary}")
            return Path(None)
        except Exception:
            logger.info("[!] apktool failed. Aborting. - for APKOUT: {out_dir}")
            raise

    n_files = sum(1 for _ in out_dir.rglob("*.smali")) if out_dir.is_dir() else 0
    if n_files == 0:
        logger.error(f"APKTOOL produced no sources (rc={proc.returncode}): " f"{proc.stderr[-500:] if proc.stderr else ''}")
        return Path(None)
    marker.touch()
    logger.info(f"APKTOOL ok: {n_files} java files (rc={proc.returncode})")

    return out_dir
