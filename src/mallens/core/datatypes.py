"""Shared datatypes. Every stage communicates through these — later stages
must type against them, never against Androguard objects (which never
leave the ingest child process)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ClassKind(str, Enum):
    APP = "app"            # application code (incl. obfuscated unknowns)
    LIBRARY = "library"    # embedded third-party (androidx, gms, ...)
    FRAMEWORK = "framework"  # android.*/java.* — never dex-resident


@dataclass
class ApkMetadata:
    sha256: str
    path: str
    file_size: int
    package_name: str = ""
    main_activity: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    dex_count: int = 0
    analysis_seconds: float = 0.0
    app_role: dict = field(default_factory=dict)


@dataclass
class RawClassRecord:
    """Everything stage-2 feature extraction needs about one class,
    harvested while the dex was open. Smali-name format: 'Lcom/foo/Bar;'"""
    name: str
    kind: ClassKind = ClassKind.APP
    superclass: str | None = None
    interfaces: list[str] = field(default_factory=list)
    access_flags: str = ""
    method_count: int = 0
    native_method_count: int = 0
    bytecode_size: int = 0                       # LOC proxy until jadx runs
    # framework method signature -> call count, e.g.
    # "Landroid/telephony/SmsManager;->sendTextMessage" -> 3
    api_calls: dict[str, int] = field(default_factory=dict)
    lib_call_count: int = 0                       # calls into embedded libs
    string_constants: list[str] = field(default_factory=list)
    spoofed_framework_name: bool = False



@dataclass
class Stage1Result:
    """Output of ingest: metadata + per-class records + class digraph.
    Graph nodes are class-name strings; node attrs: kind, method_count,
    bytecode_size; edge attrs: weight (# of method-level call pairs)."""
    apk: ApkMetadata
    class_records: dict[str, RawClassRecord]
    graph: "object"  # nx.DiGraph — untyped to keep this module import-light
    stats: dict = field(default_factory=dict)


# ------- forward schemas (stage 2+); defined now so modules type against them
@dataclass
class ClassFeatureRecord:
    """FeatureVector plus bookkeeping stage 3+ needs."""
    vector: FeatureVector
    jadx_ok: bool = False
    java_path: str | None = None      # decompiled source, if jadx succeeded
    api_categories: dict[str, int] = field(default_factory=dict)
    suspicion_naive: float = 0.0      # weighted category sum (sanity metric only)


@dataclass
class Stage2Result:
    apk_sha256: str
    feature_names: list[str]
    records: dict[str, ClassFeatureRecord]   # class_name -> record
    jadx_stats: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)


@dataclass
class FeatureVector:
    class_name: str
    feature_names: list[str]
    values: list[float]


# @dataclass
# class Cluster:
#     cluster_id: int
#     class_names: list[str]
#     seed_class: str = ""
#     importance: float = 0.0
#     est_tokens: int = 0
#     seed_classes: list[str]
#     member_classes: list[str]
#     importance_score: float
#     rationale: dict = field(default_factory=dict)


@dataclass
class Cluster:
    cluster_id: int
    class_names: list[str]
    seed_class: str = ""
    importance: float = 0.0
    est_tokens: int = 0


@dataclass
class AnalysisResult:
    apk_sha256: str
    verdict: str                  # "malicious" | "benign" | "suspicious"
    confidence: float
    implicated_classes: list[str]
    explanation: str
    tokens_used: int = 0
    model_name: str = ""


@dataclass
class Stage3Result:
    apk_sha256: str
    scorer_name: str
    scores: dict[str, float]          # class -> normalized [0,1]
    clusters: list[Cluster]           # sorted by importance, desc
    stats: dict = field(default_factory=dict)


@dataclass
class LLMAggregateVerdict:
    verdict: str
    confidence: float
    payload_clusters: list[int] = field(default_factory=list)
    payload_description: str | None = None
    benign_rationale: str | None = None
    key_evidence: list[str] = field(default_factory=list)
    family_hint: str | None = None
    malicious_classes: list[str] = field(default_factory=list)
    rules_fired: list[str] = field(default_factory=list)  # legacy-compat
    source: str = "llm"          # "llm" | "rule_fallback"
    raw: dict = field(default_factory=dict)
    shadow: dict | None = None   # legacy rule-engine verdict, for comparison




################# FACTSHEET IMPL ######################
# ---------------- fact-sheet pipeline ----------------
from dataclasses import dataclass, field

@dataclass
class FactEntry:
    type: str                    # enum value
    quote: str                   # verbatim from source
    method: str = ""
    endpoint: str = ""           # sinks only: literal | expression | "unresolved"

@dataclass
class ClassFactSheet:
    class_name: str
    src_hash: str
    prompt_version: str
    functional_summary: str = ""
    sources: list[FactEntry] = field(default_factory=list)
    sinks: list[FactEntry] = field(default_factory=list)
    transforms: list[FactEntry] = field(default_factory=list)
    triggers: list[FactEntry] = field(default_factory=list)
    notable_strings: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)   # verifier audit trail
    status: str = "ok"           # ok | no_source | llm_error

@dataclass
class CandidatePath:
    path_id: str
    cluster_id: int
    nodes: list[str]                       # class names, source→sink order
    edges: list[tuple[str, str, int]]      # (src, dst, call_count)
    source_type: str
    sink_type: str
    trigger_type: str = "NONE"
    has_transform: bool = False
    unresolved_hops: list[str] = field(default_factory=list)

@dataclass
class PathVerdict:
    path_id: str
    reading: str = ""
    legitimate_explanation: str = ""
    exceeds_legitimate_purpose: bool = False
    why: str = ""
    confidence: float = 0.0
    verified: bool = False       # set by verifier, never by LLM

@dataclass
class ClusterPathVerdict:
    cluster_id: int
    verdict: str                 # malicious|suspicious|benign|inconclusive
    hostile_paths: list[str] = field(default_factory=list)
    n_paths: int = 0
    n_unresolved_terminated: int = 0
    notes: str = ""

@dataclass
class ApkPathVerdict:
    apk_sha256: str
    verdict: str
    confidence: float
    source: str = "path_engine"
    malicious_classes: list[str] = field(default_factory=list)
    hostile_paths: list[dict] = field(default_factory=list)   # rendered evidence
    cluster_verdicts: dict[int, str] = field(default_factory=dict)
    family_hint: str | None = None
    rationale: str = ""
    shadow: dict | None = None   # old llm_aggregate + rule engine, for comparison
