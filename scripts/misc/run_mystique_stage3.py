#!/usr/bin/env python3
"""
DroidLens Stage-3 cached experiment runner.

Stage 1 and Stage 2 are NEVER recomputed.

Expected cache layout:

<cache_root>/
    <apk_sha256>/
        stage1_graph_temp.pkl.gz
        stage2_api_features.pkl.gz
        stage2_attack_features.pkl.gz

For every experiment the script stores:

experiment/
    experiment.json
    per_apk.csv
    summary.json
    failures.json
    stage3/
        <sha>.pkl.gz
    scores/
        <sha>.csv
    clusters/
        <sha>.json

A top-level:
    combined_per_apk.csv
    experiment_comparison.csv
    run_metadata.json
    suite_manifest.json

This allows all later tables/figures to be regenerated without rerunning
Stage 3.

No LLM calls are made.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import pickle
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from mallens.config import Config
from mallens.clustering.expand import rank_clusters


# ============================================================================
# EXPERIMENT PARAMETERS
# ============================================================================

TOP_K = (1, 5, 10, 15, 20)

# PPR mixing parameter:
#   mu = 1.0 -> base suspicion only
#   mu = 0.0 -> PPR only
#   mu = 0.5 -> equal mixing
MU_VALUES = (0.0, 0.5, 1.0)

# Total evidence-unit budgets.
# Principal configuration:
#   15 suspicion seeds + 5 manifest seeds = 20 total
BUDGETS = (5, 10, 15, 20)

# Seed suspicion threshold sensitivity.
SEED_THRESHOLDS = (0.0, 0.05, 0.10, 0.20)

# Graph expansion depth.
HOPS = (1, 2, 3)

# Maximum number of clusters in which a class may appear.
OVERLAPS = (1, 2)

S1_FILENAME = "stage1_graph_temp.pkl.gz"
S2_API_FILENAME = "stage2_ap_features.pkl.gz"
S2_ATTACK_FILENAME = "stage2_att_features.pkl.gz"


# ============================================================================
# GENERAL HELPERS
# ============================================================================

def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_json(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (str, int, bool)):
        return value

    if isinstance(value, float):
        return None if not math.isfinite(value) else value

    if isinstance(value, (np.integer,)):
        return int(value)

    if isinstance(value, (np.floating,)):
        value = float(value)
        return None if not math.isfinite(value) else value

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {
            str(k): safe_json(v)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            safe_json(v)
            for v in value
        ]

    return repr(value)


def write_json(path: Path, obj: Any) -> None:
    ensure_dir(path.parent)

    path.write_text(
        json.dumps(
            safe_json(obj),
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return

    ensure_dir(path.parent)

    fields = list(rows[0].keys())

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(rows)


def load_pickle_gz(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(
            f"Cached artifact not found: {path}"
        )

    with gzip.open(path, "rb") as f:
        return pickle.load(f)


def dump_pickle_gz(path: Path, obj: Any) -> None:
    ensure_dir(path.parent)

    tmp = path.with_name(
        path.name + ".tmp"
    )

    with gzip.open(
        tmp,
        "wb",
        compresslevel=3,
    ) as f:

        pickle.dump(
            obj,
            f,
            protocol=pickle.HIGHEST_PROTOCOL,
        )

    tmp.replace(path)


def set_nested_attr(obj: Any, dotted_name: str, value: Any,) -> None:
    parts = dotted_name.split(".")
    current = obj
    for part in parts[:-1]:
        current = getattr(current, part)
    setattr(current,parts[-1],value,)


def set_config_value(cfg: Config,dotted_name: str,value: Any,) -> None:
    try:
        set_nested_attr(cfg,dotted_name,value,)
    except (AttributeError, TypeError) as exc:
        raise RuntimeError(f"Config field '{dotted_name}' does not exist.") from exc


# ============================================================================
# APK SHA MAPPING
# ============================================================================
def sha256_file(path: Path,chunk_size: int = 1024 * 1024,) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_sha_to_apk(apk_root: Path,) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    apk_files = sorted(apk_root.rglob("*.apk"))
    print(f"[APK MAP] Found {len(apk_files)} APKs")
    for index, apk in enumerate(apk_files,start=1,):
        try:
            sha = sha256_file(apk)
            mapping[sha] = apk
        except Exception as exc:
            print(f"[APK MAP] FAILED {apk}: {exc}",file=sys.stderr,)

        if index % 250 == 0:
            print(f"[APK MAP] {index}/{len(apk_files)}")
    return mapping


# ============================================================================
# GROUND TRUTH
# ============================================================================
def normalize_gt_entry(value: str) -> str:
    value = value.strip()
    if not value:
        return ""

    if value.startswith("L"):
        return value.rstrip(";")

    return ("L"+ value.replace(".", "/").rstrip(";"))


def locate_gt_file(gt_dir: Path,apk: Path,) -> Path | None:
    check_1 = apk.stem.split("-release")[0]
    candidates = [gt_dir / f"{check_1}.conf.gt.txt",gt_dir / f"{check_1}.conf.gt.txt",gt_dir / f"{check_1}.gt.txt",]

    for candidate in candidates:
        if candidate.exists():
            print(f"IMPORTANT2: RETURN CANDIDATE: {candidate}")
            return candidate
    print(f"IMPORTANT: No CANDIDATES: {candidates}")
    return None


def load_ground_truth(gt_dir: Path,apk: Path | None,) -> set[str]:
    if apk is None:
        return set()
    gt_file = locate_gt_file(gt_dir,apk,)

    if gt_file is None:
        return set()

    gt: set[str] = set()
    for line in gt_file.read_text(encoding="utf-8",errors="replace",).splitlines():
        line = line.split("#",1,)[0].strip()
        if not line:
            continue
        gt.add(normalize_gt_entry(line) + ";")
    print(f"IMPORTANT 3: GT: {gt}")
    return gt


def is_payload_class(class_name: str,gt: set[str],) -> bool:
    if class_name in gt:
        return True
    for gt_entry in gt:
        if (gt_entry.endswith("/") and class_name.startswith(gt_entry)):
            return True
    return False


# ============================================================================
# CACHE DISCOVERY
# ============================================================================
def discover_cached_apks(cache_root: Path,) -> list[Path]:
    cache_dirs: list[Path] = []
    for directory in sorted(cache_root.iterdir()):
        if not directory.is_dir():
            continue
        required = (
            directory / S1_FILENAME,
            directory / S2_API_FILENAME,
            directory / S2_ATTACK_FILENAME,
        )
        if all(path.exists() for path in required):
            cache_dirs.append(directory)
    return cache_dirs


def load_cached_s1_s2(cache_dir: Path,score_variant: str,) -> tuple[Any, Any]:
    s1 = load_pickle_gz(cache_dir / S1_FILENAME)
    if score_variant == "api":
        s2 = load_pickle_gz(cache_dir / S2_API_FILENAME)
    elif score_variant == "attack":
        s2 = load_pickle_gz(cache_dir / S2_ATTACK_FILENAME)
    else:
        raise ValueError(f"Unknown S2 score variant: {score_variant}")

    return s1, s2


# ============================================================================
# CONFIGURATION
# ============================================================================
def make_experiment_config(config_path: str | None,params: dict[str, Any],) -> Config:
    cfg = Config.load(config_path)
    set_config_value(cfg,"importance.scorer",params["scorer"],)

    if "mu" in params:
        set_config_value(cfg,"importance.mix_base",float(params["mu"]),)

    if "max_seeds" in params:
        set_config_value(cfg,"clustering.max_seeds",int(params["max_seeds"]),)

    if "max_total_seeds" in params:
        set_config_value(cfg,"clustering.max_total_seeds",int(params["max_total_seeds"]),)

    if "manifest_seed_max" in params:
        set_config_value(cfg,"clustering.manifest_seed_max",int(params["manifest_seed_max"]),)

    if "seed_threshold" in params:
        set_config_value(cfg,"clustering.min_seed_suspicion",float(params["seed_threshold"]),)

    if "context_threshold" in params:
        set_config_value(cfg,"clustering.context_min_suspicion",float(params["context_threshold"]),)

    if "max_hops" in params:
        set_config_value(cfg,"clustering.max_hops",int(params["max_hops"]),)

    if "max_membership" in params:
        set_config_value(cfg,"clustering.max_membership",int(params["max_membership"]),)

    if "token_budget_per_cluster" in params:
        set_config_value(cfg,"clustering.token_budget_per_cluster",int(params["token_budget_per_cluster"]),)

    return cfg


# ============================================================================
# DATA EXTRACTION
# ============================================================================
def get_s2_records(s2: Any,) -> dict[str, Any]:
    records = getattr(s2,"records",None,)
    if records is None:
        raise RuntimeError("Stage2Result does not contain 'records'.")
    return records


def get_s3_scores(s3: Any,) -> dict[str, float]:
    scores = getattr(s3,"scores",None,)
    if scores is None:
        raise RuntimeError("Stage3Result does not contain 'scores'.")
    return {str(class_name): float(score) for class_name, score in scores.items()}


def get_s3_clusters(s3: Any,) -> list[Any]:
    clusters = getattr(s3,"clusters",None,)
    if clusters is None:
        raise RuntimeError("Stage3Result does not contain 'clusters'.")

    return sorted(list(clusters),key=lambda c: -float(getattr(c,"importance",0.0,)),)


def cluster_classes(cluster: Any,) -> list[str]:
    return list(getattr(cluster,"class_names",[],) or [])


def cluster_seed(cluster: Any,) -> str:
    return str(getattr(cluster,"seed_class","",))


def cluster_importance(cluster: Any,) -> float:
    return float(getattr(cluster,"importance",0.0,))


def cluster_est_tokens(cluster: Any,) -> int:
    return int(getattr(cluster,"est_tokens",0,) or 0)


def ranking_from_scores(scores: dict[str, float],) -> list[str]:
    return sorted(scores.keys(), key=lambda cname: (-float(scores[cname]), cname,),)


# ============================================================================
# METRICS
# ============================================================================
def finite_mean(
    values: Iterable[float],
) -> float:
    values = [
        float(value)
        for value in values
        if math.isfinite(float(value))
    ]
    if not values:
        return float("nan")
    return float(
        np.mean(values)
    )


def recall_at_k(
    payload: set[str],
    ranking: list[str],
    k: int,
) -> float:
    if not payload:
        return float("nan")
    return (
        len(
            payload.intersection(
                ranking[:k]
            )
        )
        / len(payload)
    )


def cluster_coverage_at_k(
    payload: set[str],
    clusters: list[Any],
    k: int,
) -> float:

    if not payload:
        return float("nan")

    covered = {
        class_name
        for cluster in clusters[:k]
        for class_name in cluster_classes(cluster)
    }

    return (
        len(
            payload.intersection(covered)
        )
        / len(payload)
    )


def first_payload_cluster(
    payload: set[str],
    clusters: list[Any],
) -> int | None:

    for rank, cluster in enumerate(
        clusters,
        start=1,
    ):

        if payload.intersection(
            cluster_classes(cluster)
        ):

            return rank

    return None


def seed_payload_recall(
    payload: set[str],
    clusters: list[Any],
) -> float:

    if not payload:
        return float("nan")

    payload_seeds = {
        cluster_seed(cluster)
        for cluster in clusters
        if cluster_seed(cluster) in payload
    }

    return (
        len(payload_seeds)
        / len(payload)
    )


def score_statistics(
    scores: dict[str, float],
    payload: set[str],
) -> dict[str, float]:

    payload_scores = [
        scores[c]
        for c in payload
        if c in scores
        and math.isfinite(scores[c])
    ]

    non_payload_scores = [
        score
        for class_name, score in scores.items()
        if class_name not in payload
        and math.isfinite(score)
    ]

    return {
        "payload_score_mean": (
            float(np.mean(payload_scores))
            if payload_scores
            else float("nan")
        ),
        "payload_score_median": (
            float(np.median(payload_scores))
            if payload_scores
            else float("nan")
        ),
        "payload_score_max": (
            float(np.max(payload_scores))
            if payload_scores
            else float("nan")
        ),
        "non_payload_score_mean": (
            float(np.mean(non_payload_scores))
            if non_payload_scores
            else float("nan")
        ),
        "non_payload_score_median": (
            float(np.median(non_payload_scores))
            if non_payload_scores
            else float("nan")
        ),
    }


# ============================================================================
# PERSIST DETAILED SCORES
# ============================================================================

def save_score_table(
    path: Path,
    s2: Any,
    s3: Any,
    gt: set[str],
) -> None:

    records = get_s2_records(s2)
    scores = get_s3_scores(s3)

    ranking = ranking_from_scores(
        scores
    )

    rows: list[dict[str, Any]] = []

    for rank, class_name in enumerate(
        ranking,
        start=1,
    ):

        record = records[class_name]

        rows.append({
            "rank": rank,
            "class": class_name,
            "final_importance": scores[class_name],
            "raw_suspicion": float(
                getattr(
                    record,
                    "suspicion_naive",
                    0.0,
                )
            ),
            "is_payload_gt": is_payload_class(
                class_name,
                gt,
            ),
            "api_category_count": len(
                getattr(
                    record,
                    "api_categories",
                    {},
                )
                or {}
            ),
            "api_call_count": len(
                getattr(
                    record,
                    "api_calls",
                    [],
                )
                or []
            ),
        })

    write_csv(
        path,
        rows,
    )


# ============================================================================
# PERSIST DETAILED CLUSTERS
# ============================================================================

def save_cluster_table(
    path: Path,
    s3: Any,
    gt: set[str],
) -> None:

    clusters = get_s3_clusters(
        s3
    )

    data = []

    for rank, cluster in enumerate(
        clusters,
        start=1,
    ):

        class_names = cluster_classes(
            cluster
        )

        payload_classes = [
            class_name
            for class_name in class_names
            if is_payload_class(
                class_name,
                gt,
            )
        ]

        data.append({
            "rank": rank,
            "cluster_id": int(
                getattr(
                    cluster,
                    "cluster_id",
                    rank - 1,
                )
            ),
            "seed_class": cluster_seed(
                cluster
            ),
            "importance": cluster_importance(
                cluster
            ),
            "estimated_tokens": cluster_est_tokens(
                cluster
            ),
            "n_classes": len(class_names),
            "classes": class_names,
            "payload_classes": payload_classes,
        })

    write_json(
        path,
        {
            "apk_sha256": str(
                getattr(
                    s3,
                    "apk_sha256",
                    "",
                )
            ),
            "scorer": str(
                getattr(
                    s3,
                    "scorer_name",
                    "",
                )
            ),
            "stats": getattr(
                s3,
                "stats",
                {},
            ),
            "clusters": data,
        },
    )


# ============================================================================
# PER-APK SUMMARY
# ============================================================================

def summarize_apk(
    cache_dir: Path,
    apk: Path | None,
    gt: set[str],
    s1: Any,
    s2: Any,
    s3: Any,
    experiment: dict[str, Any],
) -> dict[str, Any]:

    records = get_s2_records(s2)
    scores = get_s3_scores(s3)

    classes = list(records.keys())

    payload = {
        class_name
        for class_name in classes
        if is_payload_class(
            class_name,
            gt,
        )
    }

    ranking = ranking_from_scores(
        scores
    )

    clusters = get_s3_clusters(
        s3
    )

    covered_classes = {
        class_name
        for cluster in clusters
        for class_name in cluster_classes(cluster)
    }

    row: dict[str, Any] = {
        "experiment": experiment["name"],
        "score_variant": experiment["score_variant"],
        "scorer": experiment["params"]["scorer"],
        "sha256": cache_dir.name,
        "apk": (
            apk.name
            if apk is not None
            else ""
        ),
        "apk_stem": (
            apk.stem
            if apk is not None
            else ""
        ),
        "n_app_classes": len(classes),
        "n_gt_entries": len(gt),
        "n_payload_classes": len(payload),
        "payload_found": bool(payload),
        "clusters_formed": len(clusters),
        "classes_covered": len(covered_classes),
        "coverage_ratio": (
            len(covered_classes)
            / max(1, len(classes))
        ),
        "seed_payload_recall": seed_payload_recall(
            payload,
            clusters,
        ),
        "first_payload_cluster_rank": (
            first_payload_cluster(
                payload,
                clusters,
            )
        ),
        "total_est_tokens": sum(
            cluster_est_tokens(cluster)
            for cluster in clusters
        ),
        "mean_cluster_size": (
            float(
                np.mean([
                    len(
                        cluster_classes(cluster)
                    )
                    for cluster in clusters
                ])
            )
            if clusters
            else 0.0
        ),
        "max_cluster_size": (
            max(
                len(
                    cluster_classes(cluster)
                )
                for cluster in clusters
            )
            if clusters
            else 0
        ),
        "s1_nodes": int(
            s1.graph.number_of_nodes()
        ),
        "s1_edges": int(
            s1.graph.number_of_edges()
        ),
        "top20_classes": " | ".join(
            ranking[:20]
        ),
        "payload_classes": " | ".join(
            sorted(payload)
        ),
    }

    for k in TOP_K:

        row[
            f"class_recall@{k}"
        ] = recall_at_k(
            payload,
            ranking,
            k,
        )

        row[
            f"cluster_coverage@{k}"
        ] = cluster_coverage_at_k(
            payload,
            clusters,
            k,
        )

    row.update(
        score_statistics(
            scores,
            payload,
        )
    )

    return row


# ============================================================================
# AGGREGATION
# ============================================================================

def aggregate(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:

    if not rows:
        return {
            "n": 0
        }

    metric_names = [
        key
        for key in rows[0].keys()
        if (
            key.startswith("class_recall@")
            or key.startswith("cluster_coverage@")
            or key in {
                "n_app_classes",
                "n_gt_entries",
                "n_payload_classes",
                "clusters_formed",
                "classes_covered",
                "coverage_ratio",
                "seed_payload_recall",
                "first_payload_cluster_rank",
                "total_est_tokens",
                "mean_cluster_size",
                "max_cluster_size",
                "s1_nodes",
                "s1_edges",
                "payload_score_mean",
                "payload_score_median",
                "payload_score_max",
                "non_payload_score_mean",
                "non_payload_score_median",
            }
        )
    ]

    summary: dict[str, Any] = {
        "n": len(rows),
        "payload_found_rate": finite_mean([
            1.0
            if str(
                row["payload_found"]
            ).lower() == "true"
            else 0.0
            for row in rows
        ]),
    }

    for metric in metric_names:

        values: list[float] = []

        for row in rows:

            try:

                value = float(
                    row[metric]
                )

                if math.isfinite(value):

                    values.append(value)

            except (
                KeyError,
                TypeError,
                ValueError,
            ):
                continue

        if values:

            summary[
                f"{metric}_mean"
            ] = float(
                np.mean(values)
            )

            summary[
                f"{metric}_median"
            ] = float(
                np.median(values)
            )

            summary[
                f"{metric}_std"
            ] = float(
                np.std(values)
            )

    return summary


# ============================================================================
# EXPERIMENT DEFINITIONS
# ============================================================================

def split_budget(
    total_budget: int,
) -> tuple[int, int]:

    # Principal design:
    #   K=20 -> 15 suspicion + 5 manifest
    #
    # For smaller ablations retain approximately 75/25.
    if total_budget == 20:

        return 15, 5

    suspicion = max(
        1,
        round(
            0.75 * total_budget
        ),
    )

    manifest = (
        total_budget
        - suspicion
    )

    return suspicion, manifest


def make_experiment_suite(
    direct_scorer: str,
    ppr_scorer: str,
) -> list[dict[str, Any]]:

    experiments: list[dict[str, Any]] = []

    # ----------------------------------------------------------------------
    # E01: scoring formulation [No page rank]
    # ----------------------------------------------------------------------
    experiments.append({
        "name": "E01_api_score",
        "score_variant": "api",
        "params": {
            "scorer": direct_scorer,
        },
        "description": (
            "Class ranking using the API-based Stage-2 suspicion score."
        ),
    })

    experiments.append({
        "name": "E01_attack_score",
        "score_variant": "attack",
        "params": {
            "scorer": direct_scorer,
        },
        "description": (
            "Class ranking using the ATT&CK-based Stage-2 suspicion score."
        ),
    })

    # ----------------------------------------------------------------------
    # E02: PPR mixing [Page rank with mix base change]
    # ----------------------------------------------------------------------

    for mu in MU_VALUES:
        experiments.append({
            "name": f"E02_ppr_mu_{mu:g}",
            "score_variant": "attack",
            "params": {
                "scorer": ppr_scorer,
                "mu": mu,
            },
            "description": (
                f"PPR refinement with mix_base={mu:g}."
            ),
        })

    # ----------------------------------------------------------------------
    # E03: total evidence-unit budget
    # ----------------------------------------------------------------------

    for total_budget in BUDGETS:
        suspicion_budget, manifest_budget = (
            split_budget(total_budget)
        )

        experiments.append({
            "name": (
                f"E03_evidence_budget_K"
                f"{total_budget}"
            ),
            "score_variant": "attack",
            "params": {
                "scorer": ppr_scorer,
                "max_seeds": suspicion_budget,
                "max_total_seeds": total_budget,
                "manifest_seed_max": manifest_budget,
            },
            "description": (
                f"At most {total_budget} evidence units: "
                f"{suspicion_budget} suspicion + "
                f"{manifest_budget} manifest."
            ),
        })

    # ----------------------------------------------------------------------
    # E04: manifest contribution
    # ----------------------------------------------------------------------

    experiments.append({
        "name": "E04_manifest_0",
        "score_variant": "attack",
        "params": {
            "scorer": ppr_scorer,
            "max_seeds": 15,
            "max_total_seeds": 15,
            "manifest_seed_max": 0,
        },
        "description": (
            "Suspicion seeds only."
        ),
    })

    experiments.append({
        "name": "E04_manifest_5",
        "score_variant": "attack",
        "params": {
            "scorer": ppr_scorer,
            "max_seeds": 15,
            "max_total_seeds": 20,
            "manifest_seed_max": 5,
        },
        "description": (
            "15 suspicion seeds + up to 5 manifest seeds."
        ),
    })

    # ----------------------------------------------------------------------
    # E05: seed suspicion threshold
    # ----------------------------------------------------------------------

    for threshold in SEED_THRESHOLDS:

        experiments.append({
            "name": (
                f"E05_seed_threshold_"
                f"{threshold:g}"
            ),
            "score_variant": "attack",
            "params": {
                "scorer": ppr_scorer,
                "seed_threshold": threshold,
            },
            "description": (
                f"Minimum suspicion seed threshold={threshold:g}."
            ),
        })

    # ----------------------------------------------------------------------
    # E06: graph expansion depth
    # ----------------------------------------------------------------------

    for hops in HOPS:

        experiments.append({
            "name": f"E06_hops_{hops}",
            "score_variant": "attack",
            "params": {
                "scorer": ppr_scorer,
                "max_hops": hops,
            },
            "description": (
                f"Maximum graph expansion depth={hops}."
            ),
        })

    # ----------------------------------------------------------------------
    # E07: class-overlap limit
    # ----------------------------------------------------------------------

    for overlap in OVERLAPS:

        experiments.append({
            "name": f"E07_overlap_{overlap}",
            "score_variant": "attack",
            "params": {
                "scorer": ppr_scorer,
                "max_membership": overlap,
            },
            "description": (
                f"Maximum class membership across clusters={overlap}."
            ),
        })

    return experiments


# ============================================================================
# RUNNER
# ============================================================================

class Stage3Runner:

    def __init__(self,args: argparse.Namespace,) -> None:
        self.args = args
        self.cache_root = Path(args.cache_root)
        self.gt_dir = Path(args.gt_dir)
        self.apk_root = (Path(args.apk_root) if args.apk_root else None)
        self.output_root = ensure_dir(Path(args.output) / f"stage3_{timestamp()}")
        self.cache_dirs: list[Path] = []
        self.sha_to_apk: dict[str,Path,] = {}

    # ------------------------------------------------------------------
    # Preparation
    # ------------------------------------------------------------------

    def prepare(self) -> None:
        if not self.cache_root.exists():
            raise RuntimeError(
                f"Cache root does not exist: "
                f"{self.cache_root}"
            )
        if not self.gt_dir.exists():
            raise RuntimeError(
                f"GT directory does not exist: "
                f"{self.gt_dir}"
            )
        self.cache_dirs = (discover_cached_apks(self.cache_root))
        if not self.cache_dirs:
            raise RuntimeError(
                "No complete cached APK directories found."
            )

        if self.apk_root:
            if not self.apk_root.exists():
                raise RuntimeError(
                    f"APK root does not exist: "
                    f"{self.apk_root}"
                )
            self.sha_to_apk = (
                build_sha_to_apk(
                    self.apk_root
                )
            )

        write_json(
            self.output_root
            / "run_metadata.json",
            {
                "created": datetime.now().isoformat(),
                "cache_root": str(
                    self.cache_root
                ),
                "apk_root": (
                    str(self.apk_root)
                    if self.apk_root
                    else None
                ),
                "gt_dir": str(
                    self.gt_dir
                ),
                "config": self.args.config,
                "n_cached_apks": len(
                    self.cache_dirs
                ),
                "direct_scorer": (
                    self.args.direct_scorer
                ),
                "ppr_scorer": (
                    self.args.ppr_scorer
                ),
                "no_stage1_recomputation": True,
                "no_stage2_recomputation": True,
                "no_llm_calls": True,
            },
        )

    # ------------------------------------------------------------------
    # APK mapping
    # ------------------------------------------------------------------

    def get_apk(
        self,
        sha256: str,
        s1: Any,
    ) -> Path | None:

        if sha256 in self.sha_to_apk:
            return self.sha_to_apk[
                sha256
            ]

        # Fallback: see if S1 contains a usable APK path.
        apk_meta = getattr(
            s1,
            "apk",
            None,
        )

        if apk_meta is not None:
            for attr in (
                "path",
                "apk_path",
                "filename",
                "name",
            ):

                value = getattr(
                    apk_meta,
                    attr,
                    None,
                )

                if value:

                    candidate = Path(
                        str(value)
                    )

                    if candidate.exists():

                        return candidate

        return None

    # ------------------------------------------------------------------
    # Run one APK
    # ------------------------------------------------------------------

    def run_one_apk(
        self,
        experiment: dict[str, Any],
        cache_dir: Path,
        experiment_dir: Path,
    ) -> dict[str, Any]:

        start = time.perf_counter()

        sha256 = cache_dir.name

        # IMPORTANT:
        # This is the ONLY data-loading operation.
        #
        # No build_class_graph()
        # No extract_features()
        s1, s2 = load_cached_s1_s2(cache_dir,experiment["score_variant"],)

        cfg = make_experiment_config(
            self.args.config,
            experiment[
                "params"
            ],
        )

        # THE ONLY STAGE-3 COMPUTATION.
        s3 = rank_clusters(s1,s2,cfg,)

        apk = self.get_apk(
            sha256,
            s1,
        )

        gt = load_ground_truth(
            self.gt_dir,
            apk,
        )

        row = summarize_apk(
            cache_dir=cache_dir,
            apk=apk,
            gt=gt,
            s1=s1,
            s2=s2,
            s3=s3,
            experiment=experiment,
        )

        row[
            "runtime_stage3_sec"
        ] = round(
            time.perf_counter()
            - start,
            4,
        )

        row[
            "gt_file_found"
        ] = bool(gt)

        # --------------------------------------------------------------
        # Save complete Stage3Result
        # --------------------------------------------------------------

        dump_pickle_gz(
            experiment_dir
            / "stage3"
            / f"{sha256}.pkl.gz",
            s3,
        )

        # --------------------------------------------------------------
        # Save class ranking information
        # --------------------------------------------------------------

        save_score_table(
            experiment_dir
            / "scores"
            / f"{sha256}.csv",
            s2,
            s3,
            gt,
        )

        # --------------------------------------------------------------
        # Save clusters
        # --------------------------------------------------------------

        save_cluster_table(
            experiment_dir
            / "clusters"
            / f"{sha256}.json",
            s3,
            gt,
        )

        return row

    # ------------------------------------------------------------------
    # Run experiment
    # ------------------------------------------------------------------

    def run_experiment(
        self,
        experiment: dict[str, Any],
    ) -> list[dict[str, Any]]:

        experiment_dir = ensure_dir(
            self.output_root
            / experiment["name"]
        )

        write_json(
            experiment_dir
            / "experiment.json",
            experiment,
        )

        rows: list[
            dict[str, Any]
        ] = []

        failures: list[
            dict[str, Any]
        ] = []

        total = len(
            self.cache_dirs
        )

        for index, cache_dir in enumerate(
            self.cache_dirs,
            start=1,
        ):

            sha256 = cache_dir.name

            print(
                f"[{experiment['name']}] "
                f"{index}/{total} "
                f"{sha256[:16]}..."
            )

            s3_path = (
                experiment_dir
                / "stage3"
                / f"{sha256}.pkl.gz"
            )

            # ----------------------------------------------------------
            # Resume support
            # ----------------------------------------------------------

            if (
                s3_path.exists()
                and not self.args.force
            ):

                try:

                    s1, s2 = load_cached_s1_s2(
                        cache_dir,
                        experiment[
                            "score_variant"
                        ],
                    )

                    s3 = load_pickle_gz(
                        s3_path
                    )

                    apk = self.get_apk(
                        sha256,
                        s1,
                    )

                    gt = load_ground_truth(
                        self.gt_dir,
                        apk,
                    )

                    row = summarize_apk(
                        cache_dir,
                        apk,
                        gt,
                        s1,
                        s2,
                        s3,
                        experiment,
                    )

                    row[
                        "runtime_stage3_sec"
                    ] = 0.0

                    row[
                        "reused_existing_s3"
                    ] = True

                    rows.append(row)

                    continue

                except Exception as exc:

                    print(
                        f"Existing S3 result invalid for "
                        f"{sha256}: {exc}; recomputing.",
                        file=sys.stderr,
                    )

            # ----------------------------------------------------------
            # Actual run
            # ----------------------------------------------------------

            try:

                row = self.run_one_apk(
                    experiment,
                    cache_dir,
                    experiment_dir,
                )

                row[
                    "reused_existing_s3"
                ] = False

                rows.append(row)

            except Exception as exc:

                failures.append({
                    "sha256": sha256,
                    "cache_dir": str(
                        cache_dir
                    ),
                    "error": repr(exc),
                    "traceback": traceback.format_exc(),
                })

                print(
                    f"[FAILED] "
                    f"{experiment['name']} "
                    f"{sha256}: {exc}",
                    file=sys.stderr,
                )

        write_csv(
            experiment_dir
            / "per_apk.csv",
            rows,
        )

        write_json(
            experiment_dir
            / "failures.json",
            failures,
        )

        if rows:

            write_json(
                experiment_dir
                / "summary.json",
                aggregate(rows),
            )

        print(
            f"[{experiment['name']}] "
            f"success={len(rows)} "
            f"failed={len(failures)}"
        )

        return rows

    # ------------------------------------------------------------------
    # Complete suite
    # ------------------------------------------------------------------

    def run(self) -> None:

        self.prepare()
        experiments = (
            make_experiment_suite(
                self.args.direct_scorer,
                self.args.ppr_scorer,
            )
        )
        # Optional subset.
        if self.args.experiments:
            requested = set(
                self.args.experiments
            )

            available = {
                experiment["name"]
                for experiment in experiments
            }

            missing = requested - available

            if missing:

                raise RuntimeError(
                    "Unknown experiments: "
                    f"{sorted(missing)}"
                )

            experiments = [
                experiment
                for experiment in experiments
                if experiment["name"]
                in requested
            ]

        write_json(
            self.output_root
            / "suite_manifest.json",
            {
                "n_experiments": len(
                    experiments
                ),
                "experiments": experiments,
            },
        )

        all_rows: list[
            dict[str, Any]
        ] = []

        for experiment in experiments:

            rows = self.run_experiment(
                experiment
            )

            all_rows.extend(rows)

        write_csv(
            self.output_root
            / "combined_per_apk.csv",
            all_rows,
        )

        self.create_comparison_table(
            all_rows,
            experiments,
        )

        print()
        print("=" * 80)
        print(
            "STAGE 3 COMPLETE"
        )
        print(
            f"Results: {self.output_root}"
        )
        print("=" * 80)

    # ------------------------------------------------------------------
    # Experiment-level comparison
    # ------------------------------------------------------------------

    def create_comparison_table(
        self,
        rows: list[dict[str, Any]],
        experiments: list[dict[str, Any]],
    ) -> None:

        grouped: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        for row in rows:

            grouped.setdefault(
                row["experiment"],
                [],
            ).append(row)

        summary_rows: list[
            dict[str, Any]
        ] = []

        for experiment in experiments:

            name = experiment["name"]

            experiment_rows = grouped.get(
                name,
                [],
            )

            if not experiment_rows:
                continue

            summary_rows.append({
                "experiment": name,
                "score_variant": (
                    experiment[
                        "score_variant"
                    ]
                ),
                "scorer": (
                    experiment[
                        "params"
                    ]["scorer"]
                ),
                "n": len(
                    experiment_rows
                ),
                "class_recall@1": finite_mean([
                    float(
                        r["class_recall@1"]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "class_recall@1"
                            ]
                        )
                    )
                ]),
                "class_recall@5": finite_mean([
                    float(
                        r["class_recall@5"]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "class_recall@5"
                            ]
                        )
                    )
                ]),
                "class_recall@10": finite_mean([
                    float(
                        r["class_recall@10"]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "class_recall@10"
                            ]
                        )
                    )
                ]),
                "class_recall@15": finite_mean([
                    float(
                        r["class_recall@15"]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "class_recall@15"
                            ]
                        )
                    )
                ]),
                "class_recall@20": finite_mean([
                    float(
                        r["class_recall@20"]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "class_recall@20"
                            ]
                        )
                    )
                ]),
                "cluster_coverage@10": finite_mean([
                    float(
                        r[
                            "cluster_coverage@10"
                        ]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "cluster_coverage@10"
                            ]
                        )
                    )
                ]),
                "cluster_coverage@20": finite_mean([
                    float(
                        r[
                            "cluster_coverage@20"
                        ]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "cluster_coverage@20"
                            ]
                        )
                    )
                ]),
                "seed_payload_recall": finite_mean([
                    float(
                        r[
                            "seed_payload_recall"
                        ]
                    )
                    for r in experiment_rows
                    if math.isfinite(
                        float(
                            r[
                                "seed_payload_recall"
                            ]
                        )
                    )
                ]),
                "clusters_formed": finite_mean([
                    float(
                        r[
                            "clusters_formed"
                        ]
                    )
                    for r in experiment_rows
                ]),
                "total_est_tokens": finite_mean([
                    float(
                        r[
                            "total_est_tokens"
                        ]
                    )
                    for r in experiment_rows
                ]),
                "coverage_ratio": finite_mean([
                    float(
                        r[
                            "coverage_ratio"
                        ]
                    )
                    for r in experiment_rows
                ]),
            })

        write_csv(
            self.output_root
            / "experiment_comparison.csv",
            summary_rows,
        )


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(description=("Run cached DroidLens Stage-3 experiments."))

    parser.add_argument(
        "--cache-root",
        required=True,
        help=(
            "DroidLens cache containing SHA256-named "
            "APK directories."
        ),
    )

    parser.add_argument(
        "--apk-root",
        default=None,
        help=(
            "Original Mystique APK directory. "
            "Used only to map SHA256 -> APK filename "
            "for ground-truth lookup."
        ),
    )

    parser.add_argument(
        "--gt-dir",
        required=True,
        help=(
            "Directory containing "
            "*.conf.gt.txt ground-truth files."
        ),
    )

    parser.add_argument(
        "--config",
        default=None,
        help="DroidLens YAML configuration.",
    )

    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Directory under which a timestamped "
            "Stage-3 experiment run is created."
        ),
    )

    parser.add_argument(
        "--direct-scorer",
        default="naive",
        help=(
            'Registered direct scorer name. '
            'Default: "naive".'
        ),
    )

    parser.add_argument(
        "--ppr-scorer",
        default="pagerank",
        help=(
            'Registered PPR scorer name. '
            'Default: "pagerank".'
        ),
    )

    parser.add_argument(
        "--experiments",
        nargs="*",
        default=None,
        help=(
            "Optional subset, e.g. "
            "E01_api_score "
            "E01_attack_score "
            "E02_ppr_mu_0.5"
        ),
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Recompute an existing Stage-3 artifact."
        ),
    )

    return parser


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:

    parser = build_parser()
    args = parser.parse_args()

    try:
        runner = Stage3Runner(args)
        runner.run()
        return 0

    except KeyboardInterrupt:
        print("\nInterrupted.",file=sys.stderr,)
        return 130

    except Exception as exc:
        print(f"\nFATAL: {exc}",file=sys.stderr,)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())