import networkx as nx
from droidlens.core.datatypes import CandidatePath, ClassFactSheet

def enumerate_paths(cluster, sheets: dict[str, ClassFactSheet],
                    graph: nx.DiGraph, cfg) -> list[CandidatePath]:
    names = [c for c in cluster.class_names if c in sheets]
    sub = graph.subgraph(names)

    src_nodes = {n: [e.type for e in sheets[n].sources] for n in names
                 if sheets[n].sources}
    sink_nodes = {n: [e.type for e in sheets[n].sinks] for n in names
                  if sheets[n].sinks}
    trig = {n: sheets[n].triggers[0].type for n in names if sheets[n].triggers}

    raw = []
    for s in src_nodes:
        for t in sink_nodes:
            if s == t:                                   # intra-class flow
                raw.append([s])
                continue
            raw.extend(nx.all_simple_paths(sub, s, t, cutoff=cfg.factpaths.max_hops - 1))

    cands, seen = [], set()
    for p in raw:
        for st in src_nodes[p[0]]:
            for kt in sink_nodes[p[-1]]:
                key = (st, kt, frozenset(p))             # dedupe by typed flow
                if key in seen:
                    continue
                seen.add(key)
                cands.append(CandidatePath(
                    path_id=f"c{cluster.cluster_id}_p{len(cands)}",
                    cluster_id=cluster.cluster_id,
                    nodes=list(p),
                    edges=[(a, b, int(sub[a][b].get("weight", 1)))
                           for a, b in zip(p, p[1:])],
                    source_type=st, sink_type=kt,
                    trigger_type=trig.get(p[0], "NONE"),
                    has_transform=any(sheets[n].transforms for n in p),
                    unresolved_hops=[n for n in p if sheets[n].unresolved],
                ))
    # deterministic cap: shortest first, then unique (source,sink) pairs first
    cands.sort(key=lambda c: (len(c.nodes),
                              c.source_type + c.sink_type))
    if len(cands) > cfg.factpaths.max_paths_per_cluster:
        by_pair, rest = {}, []
        for c in cands:
            (by_pair.setdefault((c.source_type, c.sink_type), []) or rest).append(c) \
                if (c.source_type, c.sink_type) in by_pair else \
                by_pair.setdefault((c.source_type, c.sink_type), []).append(c)
        keep = [v[0] for v in by_pair.values()]
        keep += [c for c in cands if c not in keep]
        cands = keep[:cfg.factpaths.max_paths_per_cluster]
    return cands
