# """Public entry point for stage 1. Androguard runs in a spawned child
# process so that hangs (timeout->kill), OOM (rlimit->crash), and segfaults
# in malformed dex never take down a batch run. Results cross the boundary
# via a temp pickle file, never a Queue (large graphs deadlock pipes)."""
# from __future__ import annotations

# import multiprocessing as mp
# import os
# import pickle
# import sys
# import tempfile
# import traceback
# from pathlib import Path

# from loguru import logger

# from droidlens.config import Config
# from droidlens.core.datatypes import Stage1Result
# from droidlens.core.exceptions import IngestCrash, IngestError, IngestTimeout
# from droidlens.utils.cache import ArtifactCache, sha256_of_file
# from droidlens.ingest.extractor import extract

# STAGE = "stage1_graph"

# from droidlens.utils.logsetup import setup_logging

# def _child(apk_path: str, cfg_dict: dict, out_path: str, max_mem_mb: int) -> None:
#     try:
#         if max_mem_mb > 0 and sys.platform.startswith("linux"):
#             import resource
#             lim = max_mem_mb * 1024 * 1024
#             resource.setrlimit(resource.RLIMIT_AS, (lim, lim))

#         cfg = Config.from_dict(cfg_dict)
#         setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
#         result = extract(apk_path, cfg)
#         with open(out_path, "wb") as fh:
#             pickle.dump(("ok", result), fh, protocol=pickle.HIGHEST_PROTOCOL)
#     except MemoryError:
#         _write_err(out_path, "MemoryError: rlimit exceeded")
#     except Exception:
#         _write_err(out_path, traceback.format_exc())


# def _write_err(out_path: str, msg: str) -> None:
#     try:
#         with open(out_path, "wb") as fh:
#             pickle.dump(("err", msg), fh)
#     except Exception:
#         pass


# def build_class_graph(apk_path: str | Path, cfg: Config, force: bool = False) -> Stage1Result:
#     apk_path = Path(apk_path)

#     if not apk_path.is_file():
#         raise IngestError(f"not a file: {apk_path}")
    
#     setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)

#     sha = sha256_of_file(apk_path)
#     cache = ArtifactCache(cfg.paths.cache_dir)
#     if not force and cache.has(sha, STAGE):
#         logger.info(f"###### BUILD CLASS GRAPH: cache hit [{sha[:12]}] {apk_path.name}")
#         return cache.load(sha, STAGE)

#     with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tf:
#         out_path = tf.name
#     try:
#         ctx = mp.get_context("spawn")
#         proc = ctx.Process(
#             target=_child,
#             args=(str(apk_path), cfg.to_dict(), out_path, cfg.ingest.max_memory_mb),
#             daemon=True,
#         )
#         proc.start()
#         proc.join(timeout=cfg.ingest.timeout_seconds)

#         if proc.is_alive():
#             proc.terminate()
#             proc.join(10)
#             if proc.is_alive():
#                 proc.kill()
#             raise IngestTimeout(
#                 f"{apk_path.name}: exceeded {cfg.ingest.timeout_seconds}s")

#         if not os.path.getsize(out_path):
#             raise IngestCrash(
#                 f"{apk_path.name}: child died, exitcode={proc.exitcode} "
#                 f"(likely OOM or native crash in dex parsing)")

#         with open(out_path, "rb") as fh:
#             status, payload = pickle.load(fh)
#         if status == "err":
#             raise IngestError(f"{apk_path.name}: extraction failed:\n{payload}")

#         result: Stage1Result = payload
#         cache.save(sha, STAGE, result, meta={
#             "apk": apk_path.name, **result.stats})
#         return result
#     finally:
#         try:
#             os.unlink(out_path)
#         except OSError:
#             pass

"""Public entry point for stage 1. Androguard runs directly in the current
process. No child-process isolation, timeout, or memory limit is applied."""
from __future__ import annotations

from pathlib import Path
from loguru import logger

from droidlens.config import Config
from droidlens.core.datatypes import Stage1Result
from droidlens.core.exceptions import IngestError
from droidlens.utils.cache import ArtifactCache, sha256_of_file
from droidlens.ingest.extractor import extract
from droidlens.utils.logsetup import setup_logging

# STAGE = "stage1_graph"
STAGE = "stage1_graph_temp"

def build_class_graph(apk_path: str | Path, cfg: Config, force: bool = False) -> Stage1Result:
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        raise IngestError(f"not a file: {apk_path}")
    setup_logging(cfg.logging.level, cfg.logging.androguard_level, cfg.paths.log_file)
    sha = sha256_of_file(apk_path)
    cache = ArtifactCache(cfg.paths.cache_dir)
    if not force and cache.has(sha, STAGE):
        logger.info(f"###### BUILD CLASS GRAPH: cache hit [{sha[:12]}] {apk_path.name}")
        return cache.load(sha, STAGE)
    logger.info(f"###### BUILD CLASS GRAPH: extracting [{sha[:12]}] {apk_path.name}")
    try:
        result: Stage1Result = extract(str(apk_path), cfg)
        # print("----------------- APP ROLE DATA.......")
        # print(result.apk.app_role)
    except MemoryError as exc:
        logger.error(f"IMPORTANT: ----> Extraction **FAILED**: {sha}--> {exc}")
        raise IngestError(f"{apk_path.name}: extraction failed with MemoryError") from exc
    except Exception as exc:
        logger.info(f"Extraction Failed: {sha}--> {exc}")
        raise IngestError(f"{apk_path.name}: extraction failed: {exc}") from exc
    cache.save(sha, STAGE, result, meta={"apk": apk_path.name, **result.stats})

    return result