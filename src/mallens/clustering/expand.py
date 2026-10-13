"""Seed selection and budgeted cluster expansion.

Design choices (documented for the paper):
- Exclusive membership: seeds are processed in descending score order and
  each class joins at most one cluster. Deterministic, no merge step;
  a class reachable from two seeds goes to the stronger one.
- Budget is in estimated LLM tokens, not class count — cluster size is
  denominated in the currency that constrains Stage 4.
- Expansion is best-first (highest-scoring frontier node next), bounded
  by max_hops and the token budget.
"""
from __future__ import annotations

import heapq
import itertools
from collections import defaultdict
from loguru import logger

from mallens.config import Config
from mallens.core.datatypes import Cluster, Stage1Result, Stage2Result, Stage3Result
from mallens.importance.scorers import get_scorer


def _est_tokens(cname: str, s2: Stage2Result, cfg: Config) -> float:
    rec = s2.records.get(cname)
    if rec is None:
        return 200.0
    names = s2.feature_names
    loc = rec.vector.values[names.index("loc")]
    if rec.jadx_ok and loc > 0:
        return max(50.0, loc * cfg.clustering.tokens_per_loc)
    size = rec.vector.values[names.index("bytecode_size")]
    return max(50.0, size * cfg.clustering.tokens_per_bytecode_unit)


# def rank_clusters(s1: Stage1Result, s2: Stage2Result,
#                   cfg: Config) -> Stage3Result:
#     scorer = get_scorer(cfg.importance.scorer)
#     scores = scorer.score(s1, s2, cfg) # What we get as scores here python dict {class1:rank,myclass:0.82} pagerank : [0,1]
#     g = s1.graph.to_undirected(as_view=False)

#     # ---- seed selection ---------------------------------------------------
#     # Here we select the top ranked classes (After pageranked scores: min_seed_score=0.15, max_seeds=30) 
#     seeds = [c for c, sc in sorted(scores.items(), key=lambda kv: -kv[1])
#              if sc >= cfg.clustering.min_seed_score][:cfg.clustering.max_seeds]

#     claimed: set[str] = set()
#     clusters: list[Cluster] = []
#     tiebreak = itertools.count()

#     # Here if the first cluster got majority of the rest of the seeds we will not have 30 seeded clusters. so seeding should be done dunamically
#     # We select the first seed -> cluster 1 -> Select 2nd seed from rest -> cluster 2 and ..... N number of clusters
#     for seed in seeds:
#         if seed in claimed:
#             continue                       # already absorbed by a stronger seed
#         budget = cfg.clustering.token_budget_per_cluster # Here we set the llm token budget per cluster
#         members: list[str] = []
#         # best-first frontier: (-score, tiebreak, class, hops)
#         heap = [(-scores.get(seed, 0.0), next(tiebreak), seed, 0)]
#         seen = {seed}
#         spent = 0.0
#         while heap:
#             neg, _, cname, hops = heapq.heappop(heap)
#             cost = _est_tokens(cname, s2, cfg) # We estimate the token count for each class by bytecode size (Not by reading the java code)
#             if members and spent + cost > budget:
#                 continue                   # seed itself always admitted
#             members.append(cname)
#             claimed.add(cname)
#             spent += cost
#             if hops >= cfg.clustering.max_hops or not g.has_node(cname):
#                 continue
#             for nb in g.neighbors(cname):
#                 if nb in seen or nb in claimed:
#                     continue
#                 seen.add(nb)
#                 heapq.heappush(heap, (-scores.get(nb, 0.0),
#                                       next(tiebreak), nb, hops + 1))
#         importance = max(scores.get(m, 0.0) for m in members)
#         clusters.append(Cluster(
#             cluster_id=len(clusters),
#             class_names=members,
#             seed_class=seed,
#             importance=round(importance, 4),
#             est_tokens=int(spent),
#         ))

#     clusters.sort(key=lambda c: -c.importance)
#     for i, c in enumerate(clusters):
#         c.cluster_id = i

#     covered = {m for c in clusters for m in c.class_names}
#     stats = {
#         "scorer": scorer.name,
#         "seeds_selected": len(seeds),
#         "clusters": len(clusters),
#         "classes_covered": len(covered),
#         "coverage_ratio": round(len(covered) / max(1, len(s2.records)), 4),
#         "total_est_tokens": sum(c.est_tokens for c in clusters),
#         "mean_cluster_size": round(
#             sum(len(c.class_names) for c in clusters) / max(1, len(clusters)), 1),
#     }
#     logger.info(f"stage3 done: {stats}")
#     return Stage3Result(apk_sha256=s1.apk.sha256, scorer_name=scorer.name,
#                         scores=scores, clusters=clusters, stats=stats)



# Dynamic Clustering (We capture 30 seeds)
def rank_clusters_undirected(s1: Stage1Result, s2: Stage2Result, cfg: Config) -> Stage3Result:
    scorer = get_scorer(cfg.importance.scorer)
    scores = scorer.score(s1, s2, cfg)
    g = s1.graph.to_undirected(as_view=False) # Caveat: making the graph undirected loose the Caller -> Callee feature, so the pagerank from score diluted to both connected nodes
                                                        # Callee can be benign code or not.

    # 1. Filter and sort ALL candidates above min_seed_score (NO [:max_seeds] slice yet!)
    candidate_seeds = [c for c, sc in sorted(scores.items(), key=lambda kv: -kv[1]) if sc >= cfg.clustering.min_seed_score]

    claimed: set[str] = set()
    clusters: list[Cluster] = []
    tiebreak = itertools.count()

    # 2. Iterate dynamically through candidates
    for seed in candidate_seeds:
        # Stop once we've reached the maximum desired cluster count
        logger.info(f"DEBUG: Top Seed: {seed}")
        if len(clusters) >= cfg.clustering.max_seeds:
            break

        # Skip if this candidate was already absorbed into an earlier cluster (Caveat: If this claimed class is important to explain the cluster 2 malicious state??)
        if seed in claimed:
            continue

        budget = cfg.clustering.token_budget_per_cluster
        members: list[str] = []
        heap = [(-scores.get(seed, 0.0), next(tiebreak), seed, 0)]
        seen = {seed}
        spent = 0.0

        while heap:
            neg, _, cname, hops = heapq.heappop(heap)
            cost = _est_tokens(cname, s2, cfg)
            
            if members and spent + cost > budget: # Caveat: If the malicious class is out of budget it will ommit here, instead a smaller, unwanted class will be plugged
                continue

            members.append(cname)
            claimed.add(cname)
            spent += cost

            if hops >= cfg.clustering.max_hops or not g.has_node(cname):
                continue

            for nb in g.neighbors(cname):
                if nb in seen or nb in claimed:
                    continue
                seen.add(nb)
                heapq.heappush(
                    heap, (-scores.get(nb, 0.0), next(tiebreak), nb, hops + 1)
                )

        importance = max(scores.get(m, 0.0) for m in members)
        clusters.append(
            Cluster(
                cluster_id=len(clusters),
                class_names=members,
                seed_class=seed,
                importance=round(importance, 4),
                est_tokens=int(spent),
            )
        )

    # Sort final clusters by overall importance
    clusters.sort(key=lambda c: -c.importance)
    for i, c in enumerate(clusters):
        c.cluster_id = i

    covered = {m for c in clusters for m in c.class_names}
    stats = {
        "scorer": scorer.name,
        "seeds_evaluated": len(candidate_seeds),
        "clusters_formed": len(clusters),
        "classes_covered": len(covered),
        "coverage_ratio": round(len(covered) / max(1, len(s2.records)), 4),
        "total_est_tokens": sum(c.est_tokens for c in clusters),
        "mean_cluster_size": round(
            sum(len(c.class_names) for c in clusters) / max(1, len(clusters)), 1
        ),
    }
    logger.info(f"stage3 done: {stats}")
    return Stage3Result(
        apk_sha256=s1.apk.sha256,
        scorer_name=scorer.name,
        scores=scores,
        clusters=clusters,
        stats=stats,
    )


# No manifest classes included
def rank_clusters_directed_v1(s1: Stage1Result, s2: Stage2Result, cfg: Config) -> Stage3Result:
    """
    Build clusters using directed suspicion flow and original suspicion floors.
    Two-phase expansion:
      1. Core: high raw-suspicion neighbours (budget overrun allowed).
      2. Context: low suspicion neighbours to fill remaining budget (optional).
    Limited overlap: a class can be in at most max_membership clusters.
    """
    scorer = get_scorer(cfg.importance.scorer)
    final_scores = scorer.score(s1, s2, cfg)

    # Original per-class suspicion from Stage2 (used as seed floor and core threshold)
    s0 = {cname: record.suspicion_naive for cname, record in s2.records.items()}

    # Directed call graph – we only traverse successors (callees) during expansion
    g = s1.graph  # DiGraph

    # ---- Parameters from config (with defaults if not present) ----
    min_seed_suspicion = getattr(cfg.clustering, "min_seed_suspicion", 0.1)
    context_min_suspicion = getattr(cfg.clustering, "context_min_suspicion", 0.05)
    max_membership = getattr(cfg.clustering, "max_membership", 2)
    budget_overrun_factor = getattr(cfg.clustering, "budget_overrun_factor", 0.2)

    # ---- Seed selection: require high ORIGINAL suspicion ----
    candidate_seeds = [c for c in s0 if s0[c] >= min_seed_suspicion]
    # Sort by final propagated/blended score (descending)
    candidate_seeds.sort(key=lambda c: -final_scores.get(c, 0.0))

    logger.info("TOP 10 Candidate Seeds.....")
    for i, s in enumerate(candidate_seeds[:10], 1):
        logger.info(f"#{i}: {s} | score={final_scores.get(s, 0.0):.4f}")

    # Track how many clusters each class belongs to (allow limited overlap)
    node_cluster_count = defaultdict(int)
    seed_used = set()           # classes that have already been a seed
    clusters: list[Cluster] = []
    tiebreak = itertools.count()

    for seed in candidate_seeds:
        if len(clusters) >= cfg.clustering.max_seeds:
            break

        # A class can be a seed only once (but may appear as member later)
        if seed in seed_used:
            continue
        seed_used.add(seed)

        budget = cfg.clustering.token_budget_per_cluster
        members: list[str] = []
        spent = 0.0

        # Add seed (always, regardless of budget)
        cost = _est_tokens(seed, s2, cfg)
        members.append(seed)
        spent += cost
        node_cluster_count[seed] += 1

        # ---------- Phase 1: CORE expansion ----------
        # Add neighbours with original suspicion >= context_min_suspicion
        # Budget may be exceeded by up to budget_overrun_factor for core nodes.
        heap = []
        seen_core = {seed}

        # Get initial neighbours (callees)
        if g.has_node(seed):
            for nb in g.successors(seed):
                if nb in seen_core or node_cluster_count.get(nb, 0) >= max_membership:
                    continue
                seen_core.add(nb)
                heapq.heappush(heap, (-final_scores.get(nb, 0.0), next(tiebreak), nb, 1))

        while heap:
            neg, _, cname, hops = heapq.heappop(heap)

            # Skip if already in enough clusters
            if node_cluster_count.get(cname, 0) >= max_membership:
                continue

            # Only include nodes that meet the core suspicion threshold
            if s0.get(cname, 0.0) < context_min_suspicion:
                continue

            cost = _est_tokens(cname, s2, cfg)
            max_allowed = budget * (1.0 + budget_overrun_factor)

            if spent + cost > max_allowed:
                # Budget overrun beyond limit -> skip this node
                continue

            # Add node to cluster
            members.append(cname)
            spent += cost
            node_cluster_count[cname] += 1

            # Expand further (only successors = callees)
            if hops >= cfg.clustering.max_hops or not g.has_node(cname):
                continue
            for nb in g.successors(cname):
                if nb in seen_core or node_cluster_count.get(nb, 0) >= max_membership:
                    continue
                seen_core.add(nb)
                heapq.heappush(heap, (-final_scores.get(nb, 0.0), next(tiebreak), nb, hops + 1))

        # ---------- Phase 2: CONTEXT expansion (optional) ----------
        # If budget remains, add lower-suspicion neighbours to fill up the cluster.
        # These are added with strict budget (no overrun).
        if spent < budget:
            heap2 = []
            seen_context = set(members)  # avoid re-adding core members

            # Start from all current members' successors
            for m in members:
                if g.has_node(m):
                    for nb in g.successors(m):
                        if nb in seen_context or node_cluster_count.get(nb, 0) >= max_membership:
                            continue
                        seen_context.add(nb)
                        heapq.heappush(heap2, (-final_scores.get(nb, 0.0), next(tiebreak), nb, 1))

            while heap2 and spent < budget:
                neg, _, cname, hops = heapq.heappop(heap2)
                if node_cluster_count.get(cname, 0) >= max_membership:
                    continue

                cost = _est_tokens(cname, s2, cfg)
                if spent + cost > budget:  # strict budget for context
                    continue

                members.append(cname)
                spent += cost
                node_cluster_count[cname] += 1

                if hops < cfg.clustering.max_hops and g.has_node(cname):
                    for nb in g.successors(cname):
                        if nb in seen_context or node_cluster_count.get(nb, 0) >= max_membership:
                            continue
                        seen_context.add(nb)
                        heapq.heappush(heap2, (-final_scores.get(nb, 0.0), next(tiebreak), nb, hops + 1))

        # Build Cluster object
        importance = max(final_scores.get(m, 0.0) for m in members)
        clusters.append(
            Cluster(
                cluster_id=len(clusters),
                class_names=members,
                seed_class=seed,
                importance=round(importance, 4),
                est_tokens=int(spent),
            )
        )

    # Sort clusters by overall importance (descending)
    clusters.sort(key=lambda c: -c.importance)
    for i, c in enumerate(clusters):
        c.cluster_id = i

    # Compute coverage stats
    covered = {m for c in clusters for m in c.class_names}
    stats = {
        "scorer": scorer.name,
        "seeds_evaluated": len(candidate_seeds),
        "clusters_formed": len(clusters),
        "classes_covered": len(covered),
        "coverage_ratio": round(len(covered) / max(1, len(s2.records)), 4),
        "total_est_tokens": sum(c.est_tokens for c in clusters),
        "mean_cluster_size": round(
            sum(len(c.class_names) for c in clusters) / max(1, len(clusters)), 1
        ),
    }
    logger.info(f"stage3 done: {stats}")
    return Stage3Result(
        apk_sha256=s1.apk.sha256,
        scorer_name=scorer.name,
        scores=final_scores,
        clusters=clusters,
        stats=stats,
    )


##### Important: Due to errors/mismatches/unavailabilty of susp/permission based apis in classes we might have low sus score for malicious classes
##### We can include 10 classes from android manifest activities, services, receivers, and providers
### Each following will give list[str] of class names: eg., ['com.andriy.yankovskyy.ctg.texaspoker.CTGActivity', 'com.google.android.gms.ads.AdActivity']
# activities = s1.apk.activities 
# services = s1.apk.services
# receivers = s1.apk.receivers
# providers = s1.apk.providers
### If in below selected clusters, the seed of that cluster is from any of the above we dont need to add that as a seed. if not upto 10 max (make this as a variable) of this will be added and we will increase the analysing clusters to 20
### 10 clusters from sus score 10 clusters from manifest. But if there are only 5 classes in manifest and all 5 are in the clusters within top 10 we dont need to add any I think. but we need to handle it carefully.
#### Increasing clusters to analyse means increase of malware detection time and for benign it will increase the FP as well.

# manifest classes included to the intersted cluster
def rank_clusters(s1: Stage1Result, s2: Stage2Result, cfg: Config) -> Stage3Result:
    """
    Build clusters using directed suspicion flow and original suspicion floors.
    Two‑phase expansion per cluster:
      1. Core: high raw‑suspicion neighbours (budget overrun allowed).
      2. Context: low suspicion neighbours if budget remains (strict budget).
    After suspicion‑based clusters (up to cfg.clustering.max_seeds) are formed,
    manifest components (activities, services, receivers, providers) that are
    not already covered are used as additional seeds, up to a total of
    cfg.clustering.max_total_seeds clusters (default 20).
    Limited overlap: a class can be in at most max_membership clusters.
    """
    scorer = get_scorer(cfg.importance.scorer)
    final_scores = scorer.score(s1, s2, cfg)

    # Original per‑class suspicion from Stage2 (used as seed floor and core threshold)
    s0 = {cname: record.suspicion_naive for cname, record in s2.records.items()}

    # Directed call graph – we only traverse successors (callees) during expansion
    g = s1.graph  # DiGraph

    # ---- Parameters from config (with defaults if not present) ----
    min_seed_suspicion = getattr(cfg.clustering, "min_seed_suspicion", 0.1) #Not in default.yaml
    context_min_suspicion = getattr(cfg.clustering, "context_min_suspicion", 0.05) #Not in default.yaml
    max_membership = getattr(cfg.clustering, "max_membership", 2)
    budget_overrun_factor = getattr(cfg.clustering, "budget_overrun_factor", 0.2)
    max_suspicion_seeds = getattr(cfg.clustering, "max_seeds", 10)          # suspicion‑only limit
    max_total_seeds = getattr(cfg.clustering, "max_total_seeds", 20)        # total clusters (suspicion + manifest)
    manifest_seed_max = getattr(cfg.clustering, "manifest_seed_max", None)  # optional separate cap

    # ---- Collect all manifest components ----
    manifest_components = []
    for comp in s1.apk.activities + s1.apk.services + s1.apk.receivers + s1.apk.providers:
        comp = "L" + comp.replace(".", "/") + ";"
        if comp not in manifest_components:  # deduplicate
            manifest_components.append(comp)

    # ---- Seed selection from suspicion ----
    candidate_seeds = [c for c in s0 if s0[c] >= min_seed_suspicion]
    candidate_seeds.sort(key=lambda c: -final_scores.get(c, 0.0))

    logger.info("TOP suspicion Candidate Seeds.....")
    for i, s in enumerate(candidate_seeds[:max_suspicion_seeds], 1):
        logger.info(f"#{i}: {s} | score={final_scores.get(s, 0.0):.4f}")

    # Track how many clusters each class belongs to (allow limited overlap)
    node_cluster_count = defaultdict(int)
    seed_used = set()           # classes that have already been a seed
    clusters: list[Cluster] = []
    tiebreak = itertools.count()

    # ---------- Helper function to build a cluster around a seed ----------
    def build_cluster(seed: str) -> Cluster:
        """Create a cluster with the given seed using the current global state.
        Updates node_cluster_count, seed_used, and returns the Cluster object.
        """
        budget = cfg.clustering.token_budget_per_cluster
        members: list[str] = []
        spent = 0.0

        # Add seed (always, regardless of budget)
        cost = _est_tokens(seed, s2, cfg)
        members.append(seed)
        spent += cost
        node_cluster_count[seed] += 1

        # ---------- Phase 1: CORE expansion ----------
        heap = []
        seen_core = {seed}
        if g.has_node(seed):
            for nb in g.successors(seed):
                if nb in seen_core or node_cluster_count.get(nb, 0) >= max_membership:
                    continue
                seen_core.add(nb)
                heapq.heappush(heap, (-final_scores.get(nb, 0.0), next(tiebreak), nb, 1))

        while heap:
            neg, _, cname, hops = heapq.heappop(heap)
            if node_cluster_count.get(cname, 0) >= max_membership:
                continue
            # Only include nodes meeting core suspicion threshold
            if s0.get(cname, 0.0) < context_min_suspicion:
                continue
            cost = _est_tokens(cname, s2, cfg)
            max_allowed = budget * (1.0 + budget_overrun_factor)
            if spent + cost > max_allowed:
                continue
            members.append(cname)
            spent += cost
            node_cluster_count[cname] += 1

            if hops >= cfg.clustering.max_hops or not g.has_node(cname):
                continue
            for nb in g.successors(cname):
                if nb in seen_core or node_cluster_count.get(nb, 0) >= max_membership:
                    continue
                seen_core.add(nb)
                heapq.heappush(heap, (-final_scores.get(nb, 0.0), next(tiebreak), nb, hops + 1))

        # ---------- Phase 2: CONTEXT expansion (optional) ----------
        if spent < budget:
            heap2 = []
            seen_context = set(members)
            for m in members:
                if g.has_node(m):
                    for nb in g.successors(m):
                        if nb in seen_context or node_cluster_count.get(nb, 0) >= max_membership:
                            continue
                        seen_context.add(nb)
                        heapq.heappush(heap2, (-final_scores.get(nb, 0.0), next(tiebreak), nb, 1))

            while heap2 and spent < budget:
                neg, _, cname, hops = heapq.heappop(heap2)
                if node_cluster_count.get(cname, 0) >= max_membership:
                    continue
                cost = _est_tokens(cname, s2, cfg)
                if spent + cost > budget:
                    continue
                members.append(cname)
                spent += cost
                node_cluster_count[cname] += 1

                if hops < cfg.clustering.max_hops and g.has_node(cname):
                    for nb in g.successors(cname):
                        if nb in seen_context or node_cluster_count.get(nb, 0) >= max_membership:
                            continue
                        seen_context.add(nb)
                        heapq.heappush(heap2, (-final_scores.get(nb, 0.0), next(tiebreak), nb, hops + 1))

        importance = max(final_scores.get(m, 0.0) for m in members)
        return Cluster(
            cluster_id=len(clusters),
            class_names=members,
            seed_class=seed,
            importance=round(importance, 4),
            est_tokens=int(spent),
        )

    # ---------- 1) Suspicion‑based clusters ----------
    for seed in candidate_seeds:
        if len(clusters) >= max_suspicion_seeds or len(clusters) >= max_total_seeds:
            break
        if seed in seed_used:
            continue
        seed_used.add(seed)
        cluster = build_cluster(seed)
        clusters.append(cluster)

    logger.info(f"After suspicion seeds: {len(clusters)} clusters formed.")


    # ---------- 2) Manifest component clusters (fill remaining slots) ----------
    remaining_slots = max_total_seeds - len(clusters)

    logger.info(f"Filling rest {remaining_slots} by Manifest Classes.....")
    if remaining_slots > 0 and manifest_components:
        # If a separate cap on manifest seeds is set, use it to limit the number we add
        if manifest_seed_max is not None:
            remaining_slots = min(remaining_slots, manifest_seed_max)

        # Filter manifest components that are already covered (in any cluster)
        # We consider a component covered if it appears in node_cluster_count (i.e., member of any cluster)
        uncovered_manifest = [
            comp for comp in manifest_components
            if node_cluster_count.get(comp, 0) == 0 and comp not in seed_used
        ]


        # Order manifest components: by final_score, then original order if score unavailable
        uncovered_manifest.sort(key=lambda c: -final_scores.get(c, 0.0))

        logger.info("TOP Manifest Candidate Seeds.....")
        for i, s in enumerate(uncovered_manifest[:10], 1):
            logger.info(f"#{i}: {s} | score={final_scores.get(s, 0.0):.4f}")

        added_manifest = 0
        for comp in uncovered_manifest:
            if len(clusters) >= max_total_seeds or added_manifest >= remaining_slots:
                break
            # Some manifest components might not be in s2.records (e.g., no code found).
            # We still allow them as seeds; build_cluster will handle absence gracefully.
            seed_used.add(comp)
            cluster = build_cluster(comp)
            clusters.append(cluster)
            added_manifest += 1
            logger.info(f"Added manifest seed: {comp} (total clusters now {len(clusters)})")

    # ---------- Final sorting & stats ----------
    clusters.sort(key=lambda c: -c.importance)
    for i, c in enumerate(clusters):
        c.cluster_id = i

    covered = {m for c in clusters for m in c.class_names}
    stats = {
        "scorer": scorer.name,
        "seeds_evaluated": len(candidate_seeds),
        "manifest_seeds_added": added_manifest if 'added_manifest' in locals() else 0,
        "clusters_formed": len(clusters),
        "classes_covered": len(covered),
        "coverage_ratio": round(len(covered) / max(1, len(s2.records)), 4),
        "total_est_tokens": sum(c.est_tokens for c in clusters),
        "mean_cluster_size": round(
            sum(len(c.class_names) for c in clusters) / max(1, len(clusters)), 1
        ),
    }
    logger.info(f"stage3 done: {stats}")
    return Stage3Result(
        apk_sha256=s1.apk.sha256,
        scorer_name=scorer.name,
        scores=final_scores,
        clusters=clusters,
        stats=stats,
    )
