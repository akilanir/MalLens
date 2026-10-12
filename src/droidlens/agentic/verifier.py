from __future__ import annotations

from typing import Any

from droidlens.core.datatypes import Stage1Result, Stage2Result
from .schemas import ClassObservation

class EvidenceVerifier:
    def __init__(self, s1: Stage1Result, s2: Stage2Result,):
        self.s1 = s1
        self.s2 = s2

    def verify_observation(self, class_name: str, observation: ClassObservation,) -> ClassObservation:
        errors: list[str] = []
        if class_name not in self.s1.class_records:
            errors.append(
                f"class does not exist in Stage1: {class_name}"
            )
        raw = self.s1.class_records.get(class_name)
        if raw is not None:
            # ---------------------------------------------------------
            # Verify APIs
            # ---------------------------------------------------------
            real_apis = set(raw.api_calls.keys())
            for api in observation.observed_apis:
                if api not in real_apis:
                    # Allow a relaxed match because the LLM may omit
                    # parameters from the method signature.
                    matched = any(api in real_api or real_api in api for real_api in real_apis)
                    if not matched:
                        errors.append(f"API not present in class: {api}")
            # ---------------------------------------------------------
            # Verify called classes
            # ---------------------------------------------------------
            graph = self.s1.graph
            for target in observation.called_classes:
                if not graph.has_edge(class_name, target):
                    errors.append(f"graph edge missing: " f"{class_name} -> {target}")
            # ---------------------------------------------------------
            # Verify strings
            # ---------------------------------------------------------
            real_strings = set(raw.string_constants)
            for s in observation.strings:
                if s not in real_strings:
                    matched = any(
                        s in rs or rs in s
                        for rs in real_strings
                    )
                    if not matched:
                        errors.append(
                            f"string not present in class: {s}"
                        )

        observation.verified = len(errors) == 0
        observation.verification_errors = errors

        return observation

    def verify_path(self, path: list[str],) -> tuple[bool, str]:

        if len(path) < 2:
            return False, "path must contain at least two classes"
        graph = self.s1.graph
        for a, b in zip(path, path[1:]):
            if not graph.has_edge(a, b):
                return (
                    False,
                    f"missing graph edge: {a} -> {b}",
                )
        return True, "path verified"

    def verify_paths(self, paths: list[list[str]],) -> list[list[str]]:
        verified = []
        for path in paths:
            ok, _ = self.verify_path(path)
            if ok:
                verified.append(path)
        return verified

    def graph_neighbours(self, class_name: str,) -> list[str]:

        graph = self.s1.graph
        if not graph.has_node(class_name):
            return []

        neighbours = set(graph.successors(class_name))
        # Also allow incoming connections because behaviour can be
        # reached from either direction during investigation.
        neighbours.update(graph.predecessors(class_name))

        return list(neighbours)