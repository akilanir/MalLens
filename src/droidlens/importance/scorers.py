"""Importance scorers. All return {class_name: score in [0,1]}.
The registry doubles as the ablation axis for the paper."""
from __future__ import annotations

from abc import ABC, abstractmethod

import networkx as nx
from loguru import logger

from droidlens.config import Config
from droidlens.core.datatypes import Stage1Result, Stage2Result


def _base_scores(s2: Stage2Result) -> dict[str, float]:
    return {c: r.suspicion_naive for c, r in s2.records.items()}


def _normalize(d: dict[str, float]) -> dict[str, float]:
    if not d:
        return {}
    hi = max(d.values())
    if hi <= 0:
        return {k: 0.0 for k in d}
    return {k: v / hi for k, v in d.items()}


class ImportanceScorer(ABC):
    name: str = "base"

    @abstractmethod
    def score(self, s1: Stage1Result, s2: Stage2Result,
              cfg: Config) -> dict[str, float]: ...


class NaiveScorer(ImportanceScorer):
    """Ablation baseline: per-class suspicion only, no graph."""
    name = "naive"

    def score(self, s1, s2, cfg):
        return _normalize(_base_scores(s2))


class PageRankScorer(ImportanceScorer):
    """Personalized PageRank with suspicion as the personalization vector,
    on an undirected view so importance flows caller<->callee.
    Final = mix_base * base + (1 - mix_base) * PPR."""
    name = "pagerank"

    def score(self, s1, s2, cfg):
        base = _normalize(_base_scores(s2))
        g = s1.graph.to_undirected(as_view=False)
        pers = {n: base.get(n, 0.0) for n in g}
        if sum(pers.values()) <= 0:
            logger.warning("pagerank: all-zero personalization, "
                           "falling back to naive")
            return base
        try:
            pr = nx.pagerank(g, alpha=cfg.importance.pagerank_alpha,
                             personalization=pers, weight="weight")
        except nx.PowerIterationFailedConvergence:
            logger.warning("pagerank failed to converge, falling back to naive")
            return base
        pr = _normalize(pr)
        m = cfg.importance.mix_base
        out = {n: m * base.get(n, 0.0) + (1 - m) * pr.get(n, 0.0) for n in g}
        # classes not in the graph (isolated after edge drops) keep base score
        for n in base:
            out.setdefault(n, m * base[n])
        # print("Point 8")
        return _normalize(out)


class PropagationScorer(ImportanceScorer):
    """Decayed max-diffusion: score(v) = max(base(v),
    max over neighbors u of decay * score(u)), iterated `iterations` times
    over the undirected view. Explainable by construction: every score is
    traceable to one source class at a known hop distance."""
    name = "propagation"

    def score(self, s1, s2, cfg):
        base = _normalize(_base_scores(s2))
        g = s1.graph.to_undirected(as_view=False)
        decay = cfg.importance.decay
        cur = {n: base.get(n, 0.0) for n in g}
        for it in range(cfg.importance.iterations):
            nxt = dict(cur)
            changed = 0
            for u, score_u in cur.items():
                if score_u <= 0:
                    continue
                push = decay * score_u
                for v in g.neighbors(u):
                    if push > nxt[v]:
                        nxt[v] = push
                        changed += 1
            cur = nxt
            if changed == 0:
                logger.debug(f"propagation converged at iter {it + 1}")
                break
        m = cfg.importance.mix_base
        out = {n: m * base.get(n, 0.0) + (1 - m) * cur.get(n, 0.0)
               for n in set(base) | set(cur)}
        return _normalize(out)


# Directed Graph rank scores
# class PageRankScorer(ImportanceScorer):
#     """Personalized PageRank on the DIRECTED call graph.
#     Suspicion flows caller -> callee, not backwards.
#     Final score = max(base, mix_base*base + (1-mix_base)*PR)
#     so a suspicious class cannot lose its importance due to benign neighbours.
#     """
#     name = "pagerank"

#     def score(self, s1, s2, cfg):
#         # base suspicion from Stage2 (per-class naive score)
#         base = _normalize(_base_scores(s2))

#         # Use the directed call graph (no to_undirected!)
#         g = s1.graph  # NetworkX DiGraph

#         # Personalization vector: per-node base suspicion
#         pers = {n: base.get(n, 0.0) for n in g}
#         if sum(pers.values()) <= 0:
#             logger.warning("pagerank: all-zero personalization, falling back to naive")
#             return base

#         try:
#             # Directed PageRank: suspicion propagates along outgoing edges (caller->callee)
#             pr = nx.pagerank(g, alpha=cfg.importance.pagerank_alpha,
#                              personalization=pers, weight="weight")
#         except nx.PowerIterationFailedConvergence:
#             logger.warning("pagerank failed to converge, falling back to naive")
#             return base

#         pr = _normalize(pr)

#         # Blend, but **do not go below the base suspicion**
#         m = cfg.importance.mix_base
#         out = {}
#         for n in set(base) | set(pr):
#             blended = m * base.get(n, 0.0) + (1 - m) * pr.get(n, 0.0)
#             out[n] = max(base.get(n, 0.0), blended)   # floor at base

#         # Classes not in the graph (isolated) keep base score
#         for n in base:
#             out.setdefault(n, base[n])

#         return _normalize(out)


# class PropagationScorer(ImportanceScorer):
#     """Decayed max-diffusion on the DIRECTED call graph.
#     Suspicion flows from a suspicious caller to its callees.
#     Each push is divided by the callee's in-degree to penalize hubs
#     (a benign utility called by many should not become suspicious).
#     Final score = max(base, m*base + (1-m)*propagated)
#     """
#     name = "propagation"

#     def score(self, s1, s2, cfg):
#         base = _normalize(_base_scores(s2))
#         g = s1.graph  # directed DiGraph

#         decay = cfg.importance.decay
#         cur = {n: base.get(n, 0.0) for n in g}

#         for it in range(cfg.importance.iterations):
#             nxt = dict(cur)
#             changed = 0
#             for u, score_u in cur.items():
#                 if score_u <= 0:
#                     continue
#                 # For each callee v of u, propagate suspicion scaled by decay
#                 for v in g.successors(u):
#                     # Hub penalty: divide by in-degree of v
#                     # (number of callers) so a widely-used utility doesn't blow up.
#                     in_deg = g.in_degree(v)
#                     push = (decay * score_u) / max(1, in_deg)

#                     if push > nxt[v]:
#                         nxt[v] = push
#                         changed += 1
#             cur = nxt
#             if changed == 0:
#                 logger.debug(f"propagation converged at iter {it + 1}")
#                 break

#         # Blend but never go below the original suspicion
#         m = cfg.importance.mix_base
#         out = {}
#         for n in set(base) | set(cur):
#             blended = m * base.get(n, 0.0) + (1 - m) * cur.get(n, 0.0)
#             out[n] = max(base.get(n, 0.0), blended)

#         return _normalize(out)



_REGISTRY: dict[str, type[ImportanceScorer]] = {
    NaiveScorer.name: NaiveScorer,
    PageRankScorer.name: PageRankScorer,
    PropagationScorer.name: PropagationScorer,
}


def get_scorer(name: str) -> ImportanceScorer:
    try:
        return _REGISTRY[name]()
    except KeyError:
        raise ValueError(f"unknown scorer '{name}', "
                         f"available: {sorted(_REGISTRY)}") from None
