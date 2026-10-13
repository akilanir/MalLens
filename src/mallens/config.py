"""Central configuration. Everything is validated pydantic; a plain-dict
snapshot can cross process boundaries (see ingest.runner)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class PathsConfig(BaseModel):
    cache_dir: Path = Path(".droidlens_cache")
    cache_dir_decomp: Path = Path(".droidlens_cache_decomp")
    jadx_binary: str = "jadx"
    log_file: Path = Path("global_logfiles/pipeline.log")
    apktool_binary: str = "apktool"


class IngestConfig(BaseModel):
    timeout_seconds: int = 600
    max_memory_mb: int = 8192
    max_strings_per_class: int = 300
    max_string_length: int = 400
    include_library_nodes: bool = False


class FeaturesConfig(BaseModel):
    sensitive_api_csv: Path = Path("data/sensitive_apis.csv")
    jadx_timeout_seconds: int = 900
    apktool_timeout_seconds: int = 900
    jadx_extra_args: list[str] = Field(
        default_factory=lambda: ["--no-res", "--no-debug-info"])
    entropy_threshold: float = 4.5
    min_string_len_for_entropy: int = 12
    spoof_bonus: float = 10.0


class ReportConfig(BaseModel):
    t_malicious_conf: float = 0.7
    t_suspicious_conf: float = 0.5
    t_unseen_importance: float = 0.5
    min_evidence_classes: int = 2
    out_dir: str = "reports"


class LLMConfig(BaseModel):
    base_url: str = "http://localhost:11434"
    api_key_env: str = "ollama"
    model: str = "qwen3-coder:latest"
    temperature: float = 0.0
    max_output_tokens: int = 1600
    request_timeout: int = 180
    max_clusters: int = 15
    min_cluster_importance: float = 0.10 #It was 0.25 earlier


class ClassifyConfig(BaseModel):
    framework_prefixes: list[str] = Field(default_factory=lambda: ["Ljava/"])
    library_prefixes: list[str] = Field(default_factory=list)
    bundled_ok_prefixes:  list[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    level: str = "INFO"
    androguard_level: str = "ERROR"


class ImportanceConfig(BaseModel):
    scorer: str = "pagerank"
    decay: float = 0.6
    iterations: int = 3
    pagerank_alpha: float = 0.85
    mix_base: float = 0.5


class ClusteringConfig(BaseModel):
    max_seeds: int = 30
    min_seed_score: float = 0.15
    max_hops: int = 2
    token_budget_per_cluster: int = 20000
    tokens_per_loc: float = 9.0
    tokens_per_bytecode_unit: float = 0.4
    max_total_seeds: int = 30
    manifest_seed_max: int = 10

class FactsheetConfig(BaseModel):
    prompt_version: str = "fs_v1"        # bump on ANY prompt edit; keys the cache
    temperature: float = 0.0
    char_budget: int = 12000             # per LLM call; larger classes are chunked
    min_quote_len: int = 12
    xcheck_stage2: bool = True

class FactpathsConfig(BaseModel):
    max_hops: int = 4                    # path length cutoff (nodes)
    max_paths_per_cluster: int = 12
    alias_names: bool = True              # C1..Cn instead of real class names (A/B flag)

class AdjudicateConfig(BaseModel):
  prompt_version: str = "adj_v1"
  temperature: float = 0.0

class ApkVerdictConfig(BaseModel):
  suspicious_cluster_threshold: int = 2   # >=N suspicious clusters -> APK suspicious


class Config(BaseModel):
    paths: PathsConfig = PathsConfig()
    ingest: IngestConfig = IngestConfig()
    classify: ClassifyConfig = ClassifyConfig()
    logging: LoggingConfig = LoggingConfig()
    features: FeaturesConfig = FeaturesConfig()
    importance: ImportanceConfig = ImportanceConfig()
    clustering: ClusteringConfig = ClusteringConfig()
    llm: LLMConfig = LLMConfig()
    report: ReportConfig = ReportConfig()
    factsheet: FactsheetConfig = FactsheetConfig()
    factpaths: FactpathsConfig = FactpathsConfig()
    adjudicate: AdjudicateConfig = AdjudicateConfig()
    apk_verdict: ApkVerdictConfig = ApkVerdictConfig()

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        if path is None:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}
        return cls.model_validate(raw)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        return cls.model_validate(d)





    