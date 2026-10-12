from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ClassObservation:
    class_name: str
    # Facts directly grounded in Stage 1 / Stage 2
    observed_apis: list[str] = field(default_factory=list)
    observed_api_categories: list[str] = field(default_factory=list)
    # LLM interpretation of the observed behaviour.
    # These are NOT trusted until verifier checks the underlying evidence.
    behaviours: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    called_classes: list[str] = field(default_factory=list)
    # Short explanation
    interpretation: str = ""
    # Whether deterministic verification accepted the claims
    verified: bool = False
    verification_errors: list[str] = field(default_factory=list)


@dataclass
class InvestigationStep:
    step: int
    class_name: str
    observation: ClassObservation


@dataclass
class NavigationDecision:
    next_class: str | None
    reason: str
    stop: bool = False


@dataclass
class ClusterVerdict:
    cluster_id: int
    seed_class: str
    verdict: str
    confidence: float
    investigated_classes: list[str]
    evidence_paths: list[list[str]]
    verified_evidence: list[str]
    reasoning: str
    navigation_steps: int
    stop_reason: str = ""
    raw_judge_response: dict[str, Any] = field(default_factory=dict)