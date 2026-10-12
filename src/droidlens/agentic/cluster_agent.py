from __future__ import annotations

import json
from typing import Any

from droidlens.core.datatypes import (Stage1Result, Stage2Result, Stage3Result,)

from .ollama_client import OllamaClient
from .prompts import (INTERPRETER_SYSTEM,NAVIGATOR_SYSTEM,JUDGE_SYSTEM,
                    make_interpreter_prompt,make_navigator_prompt,make_judge_prompt,)
from .schemas import (ClassObservation, InvestigationStep, ClusterVerdict,)
from .verifier import EvidenceVerifier

# =============== IMPLs =================#
class GraphGuidedClusterAgent:

    def __init__(
        self,
        s1: Stage1Result,
        s2: Stage2Result,
        s3: Stage3Result,
        ollama: OllamaClient,
        max_steps: int = 8,
        min_steps_before_judge: int = 2,
    ):

        self.s1 = s1
        self.s2 = s2
        self.s3 = s3
        self.ollama = ollama
        self.max_steps = max_steps
        self.min_steps_before_judge = min_steps_before_judge
        self.verifier = EvidenceVerifier(s1, s2)

    # ================================================================
    # STATIC INFORMATION
    # ================================================================
    def _class_raw_info(self, class_name: str,) -> dict[str, Any]:
        r = self.s1.class_records[class_name]
        return {
            "name": r.name,
            "kind": str(r.kind),
            "superclass": r.superclass,
            "interfaces": r.interfaces,
            "access_flags": r.access_flags,
            "method_count": r.method_count,
            "native_method_count": r.native_method_count,
            "bytecode_size": r.bytecode_size,
            "api_calls": r.api_calls,
            "lib_call_count": r.lib_call_count,
            "string_constants": r.string_constants[:100],
            "spoofed_framework_name": r.spoofed_framework_name,
        }

    def _class_feature_info(self, class_name: str,) -> dict[str, Any]:
        r = self.s2.records[class_name]
        return {
            "api_categories": r.api_categories,
            "suspicion_naive": r.suspicion_naive,
            "jadx_ok": r.jadx_ok,
            "java_path": r.java_path,
        }

    def _neighbour_info(self, class_name: str, cluster_classes: set[str],) -> list[dict]:
        graph = self.s1.graph
        neighbours = set()
        if graph.has_node(class_name):
            neighbours.update(graph.successors(class_name))
            neighbours.update(graph.predecessors(class_name))

        output = []

        for n in neighbours:
            if n not in cluster_classes:
                continue
            score = self.s3.scores.get(n, 0.0)
            raw = self.s1.class_records.get(n)
            feat = self.s2.records.get(n)
            output.append(
                {
                    "class_name": n,
                    "importance_score": round(score, 4),
                    "api_calls": (
                        list(raw.api_calls.keys())[:20]
                        if raw else []
                    ),
                    "api_categories": (
                        feat.api_categories
                        if feat else {}
                    ),
                }
            )
        output.sort(
            key=lambda x: -x["importance_score"]
        )

        return output

    # ================================================================
    # INTERPRETER
    # ================================================================
    def interpret_class(self, class_name: str, cluster_classes: set[str],) -> ClassObservation:
        raw_info = self._class_raw_info(class_name)
        feature_info = self._class_feature_info(class_name)
        neighbours = self._neighbour_info(class_name,cluster_classes,)
        prompt = make_interpreter_prompt(class_name,raw_info,feature_info,neighbours,)
        
        
        "next_class_relevance": {"type": "array","items": {"type": "object","properties": {"class_name": {"type": "string",},
                            "relevance": {"type": "string","enum": ["high","medium","low",],},
                            "reason": {"type": "string",},},
                        "required": ["class_name","relevance","reason",],
                    },
                },
        schema = {
            "type": "object",
            "properties": {
                "observed_apis": {"type": "array","items": {"type": "string"},},
                "observed_api_categories": {"type": "array","items": {"type": "string"},},
                "behaviours": {"type": "array","items": {"type": "string"},},
                "sources": {"type": "array","items": {"type": "string"},},
                "transformations": {"type": "array","items": {"type": "string"},},
                "sinks": {"type": "array","items": {"type": "string"},},
                "called_classes": {"type": "array","items": {"type": "string"},},
                "interpretation": {"type": "string",},
                "security_relevant_evidence": {"type": "array","items": {"type": "string"},},
                "investigation_hypotheses": {"type": "array","items": {"type": "string"},},
            },
            "required": [
                "observed_apis",
                "observed_api_categories",
                "behaviours",
                "sources",
                "transformations",
                "sinks",goal i
                "called_classes",
                "interpretation",
            ],
        }

        result = self.ollama.chat(system=INTERPRETER_SYSTEM,user=prompt,schema=schema,)

        obs = ClassObservation(
            class_name=class_name,
            observed_apis=result.get("observed_apis", []),
            observed_api_categories=result.get(
                "observed_api_categories", []
            ),
            behaviours=result.get("behaviours", []),
            sources=result.get("sources", []),
            transformations=result.get(
                "transformations", []
            ),
            sinks=result.get("sinks", []),
            strings=result.get("strings", []),
            called_classes=result.get(
                "called_classes", []
            ),
            interpretation=result.get(
                "interpretation", ""
            ),
        )

        # CRITICAL:
        # Verify every claim against static artifacts.
        return self.verifier.verify_observation(
            class_name,
            obs,
        )

    # ================================================================
    # NAVIGATOR
    # ================================================================
    def get_available_next_classes(self, current_class: str, cluster_classes: list[str], max_candidates: int = 8,) -> list[str]:
        """
        Return classes that the Navigator is legally allowed to select.
        The candidate set is determined entirely by the static class graph
        and the current cluster boundary.
        The LLM does NOT control this set.
        """
        cluster_set = set(cluster_classes)
        if not self.graph.has_node(current_class):
            return []
        candidates = []
        # ------------------------------------------------------------
        # Only follow outgoing graph edges for now.
        # ------------------------------------------------------------
        for neighbour in self.graph.successors(current_class):
            # Hard cluster boundary.
            if neighbour not in cluster_set:
                continue
            if neighbour == current_class:
                continue
            candidates.append(neighbour)
        # ------------------------------------------------------------
        # Remove classes already investigated.
        # ------------------------------------------------------------
        candidates = [c for c in candidates if c not in self.visited_classes]
        # ------------------------------------------------------------
        # Rank candidates by your existing Stage-3 importance score.
        # ------------------------------------------------------------
        candidates.sort(key=lambda c: self.scores.get(c, 0.0), reverse=True,) 
        return candidates[:max_candidates]

    def build_navigation_candidates(self,current_class: str,candidates: list[str],) -> list[dict]:
        result = []
        for cname in candidates:
            record = self.stage2.records.get(cname)
            item = {"class_name": cname,
                "edge_weight": (
                    self.graph[current_class][cname]
                    .get("weight", 1)
                    if self.graph.has_edge(
                        current_class,
                        cname,
                    )
                    else 0
                ),
                "importance": round(
                    self.scores.get(cname, 0.0),
                    4,
                ),
            }
            if record is not None:
                item["api_categories"] = (record.api_categories)
                item["suspicion_naive"] = (record.suspicion_naive)
                item["jadx_ok"] = (record.jadx_ok)
            result.append(item)
        return result

    def navigate(self, current_class: str, observation: ClassObservation, investigated: list[str], cluster_classes: set[str],):
        candidates = self._neighbour_info(current_class,cluster_classes,)
        candidates = [x for x in candidates if x["class_name"] not in investigated]
        if not candidates:
            return None, "No unexplored connected class remains.", True
        prompt = make_navigator_prompt(
            current_class=current_class,
            current_observation=observation.__dict__,
            candidates=self.build_navigation_candidates(current_class,candidates),
            investigated=investigated,
        )

        schema = {
            "type": "object",
            "properties": {
                "next_class": {
                    "type": ["string", "null"]
                },
                "reason": {
                    "type": "string"
                },
                "action": {
                    "type": "string"
                },
            },
            "required": [
                "action",
                "next_class",
                "reason",
            ],
        }
        result = self.ollama.chat(system=NAVIGATOR_SYSTEM,user=prompt,schema=schema,)
        print(f"IMPORTANT NEXT CLASS:-------- {result}")
        action = result.get("action")
        next_class = result.get("next_class", "").strip()
        allowed = set(candidates)
        if action == "STOP":
            return {"action": "STOP","next_class": None,"reason": result.get("reason", ""),}
        if action != "INVESTIGATE":
            raise RuntimeError(f"Invalid Navigator action: {action}")
        if next_class not in allowed:
            raise RuntimeError("Navigator selected an illegal class: " f"{next_class!r}. " f"Allowed: {sorted(allowed)}")

        return {"action": "INVESTIGATE", "next_class": next_class, "reason": result.get("reason", ""),}


        # print(f"IMPROTANT: Next Class decider response: {result}")
        # next_class = result.get("next_class")
        # print(f"!!!! Next Class Decided bu Navigator: {next_class}")
        # if result.get("stop", False):
        #     return (None, result.get("reason", ""), True,)
        # # Hard safety check.
        # if next_class not in {x["class_name"] for x in candidates}:
        #     return (None,"Navigator selected an invalid class.",True,)
        # return (next_class, result.get("reason", ""), False,)

    # ================================================================
    # BUILD VERIFIED PATHS
    # ================================================================
    def build_verified_paths(self,steps: list[InvestigationStep],) -> list[list[str]]:
        if len(steps) < 2:
            return []

        graph = self.s1.graph
        paths = []
        current = [step.class_name for step in steps]

        # We only treat consecutive investigated classes
        # as an asserted path if the graph actually connects them.
        for i in range(len(current) - 1):
            a = current[i]
            b = current[i + 1]
            if graph.has_edge(a, b):
                paths.append([a, b])
            elif graph.has_edge(b, a):
                paths.append([b, a])
        return self.verifier.verify_paths(paths)

    # ================================================================
    # JUDGE
    # ================================================================
    def judge(self, cluster_id: int, seed_class: str, steps: list[InvestigationStep], stop_reason: str,) -> ClusterVerdict:
        observations = [
            {
                "class_name": x.class_name,
                "verified": x.observation.verified,
                "behaviours": x.observation.behaviours,
                "sources": x.observation.sources,
                "transformations": x.observation.transformations,
                "sinks": x.observation.sinks,
                "observed_apis": x.observation.observed_apis,
                "api_categories": (
                    x.observation.observed_api_categories
                ),
                "verification_errors": (
                    x.observation.verification_errors
                ),
                "interpretation": (
                    x.observation.interpretation
                ),
            }
            for x in steps
        ]
        verified_paths = self.build_verified_paths(steps)
        graph_edges = []
        graph = self.s1.graph
        investigated = {x.class_name for x in steps}

        for a in investigated:
            for b in investigated:
                if a == b:
                    continue
                if graph.has_edge(a, b):
                    graph_edges.append(
                        {
                            "source": a,
                            "target": b,
                            "weight": graph[a][b].get(
                                "weight",
                                1,
                            ),
                        }
                    )

        prompt = make_judge_prompt(
            cluster_id=cluster_id,
            seed_class=seed_class,
            observations=observations,
            verified_paths=verified_paths,
            graph_edges=graph_edges,
        )

        schema = {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": [
                        "BENIGN",
                        "MALWARE",
                    ],
                },
                "confidence": {
                    "type": "number",
                },
                "evidence_paths": {
                    "type": "array",
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "string",
                        },
                    },
                },
                "verified_evidence": {
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "reasoning": {
                    "type": "string",
                },
            },
            "required": [
                "verdict",
                "confidence",
                "evidence_paths",
                "verified_evidence",
                "reasoning",
            ],
        }
        #LLM Call
        result = self.ollama.chat(system=JUDGE_SYSTEM, user=prompt,schema=schema,)

        # ------------------------------------------------------------
        # HARD VERIFICATION OF JUDGE PATHS
        # ------------------------------------------------------------
        claimed_paths = result.get("evidence_paths",[],)

        verified_claimed_paths = (
            self.verifier.verify_paths(
                claimed_paths
            )
        )

        # If judge claims malware but has NO verified path,
        # we conservatively downgrade to BENIGN.
        verdict = result.get("verdict","BENIGN",)

        if verdict == "MALWARE":
            if not verified_claimed_paths:
                verdict = "BENIGN"

        return ClusterVerdict(
            cluster_id=cluster_id,
            seed_class=seed_class,
            verdict=verdict,
            confidence=float(
                result.get("confidence", 0.0)
            ),
            investigated_classes=[
                x.class_name
                for x in steps
            ],
            evidence_paths=verified_claimed_paths,
            verified_evidence=result.get(
                "verified_evidence",
                [],
            ),
            reasoning=result.get(
                "reasoning",
                "",
            ),
            navigation_steps=len(steps),
            stop_reason=stop_reason,
            raw_judge_response=result,
        )

    # ================================================================
    # RUN ONE CLUSTER
    # ================================================================
    def run_cluster(self, cluster,) -> ClusterVerdict:
        cluster_classes = set(cluster.class_names)
        current = cluster.seed_class
        investigated: list[str] = []
        steps: list[InvestigationStep] = []
        stop_reason = ""
        for step_number in range(self.max_steps):
            if current in investigated:
                stop_reason = ("class already investigated")
                break
            investigated.append(current)
            print(f"[Interpreter] " f"{step_number + 1}: {current}")
            observation = self.interpret_class(current, cluster_classes,) #Interpreter call and verifying
            print(f"Verified??? ->" f"{observation.verified}")

            if observation.verification_errors:
                for err in observation.verification_errors:
                    print(f"!!!!! Observation Verfication Error: {err}")

            steps.append(InvestigationStep(step=step_number, class_name=current, observation=observation,))
            # Don't judge after a single class unless
            # the max budget is one.
            if (len(steps) >= self.min_steps_before_judge):
                action, next_class, reason = (self.navigate(
                        current_class=current,
                        observation=observation,
                        investigated=investigated,
                        cluster_classes=cluster_classes,
                    )
                )
                print(f"[Navigator] " f"next={next_class} " f"stop={action}")
                if action == "STOP":
                    stop_reason = reason
                    break
                current = next_class
            else:
                # Force graph traversal after initial seed.
                neighbours = self._neighbour_info(current, cluster_classes,)
                next_candidates = [x["class_name"] for x in neighbours if x["class_name"] not in investigated]
                if not next_candidates:
                    print("Breaking!!!!: NO CONNECTED CLASS AVAILABLE")
                    stop_reason = ("no connected class available")
                    break
                current = next_candidates[0]
        if not stop_reason:
            stop_reason = ("maximum investigation budget reached")
        print(f"[Judge] " f"investigated={len(steps)}")
        verdict = self.judge(cluster_id=cluster.cluster_id,seed_class=cluster.seed_class,steps=steps,stop_reason=stop_reason,)
        return verdict