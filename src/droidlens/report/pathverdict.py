from droidlens.core.datatypes import (ClusterPathVerdict, ApkPathVerdict,
                                      CandidatePath, PathVerdict)

def cluster_verdict(cluster_id: int, paths: list[CandidatePath],
                    verdicts: dict[str, PathVerdict],
                    any_sheets: bool) -> ClusterPathVerdict:
    if not any_sheets:
        return ClusterPathVerdict(cluster_id, "inconclusive",
                                  notes="no usable fact sheets")
    hostile = [p.path_id for p in paths
               if (v := verdicts.get(p.path_id)) and v.verified
               and v.exceeds_legitimate_purpose]
    unresolved_term = sum(1 for p in paths
                          if p.unresolved_hops and p.path_id not in hostile)
    if hostile:
        verdict = "malicious"
    elif unresolved_term:
        verdict = "suspicious"      # flows terminate in code we cannot see
    elif paths:
        verdict = "benign"          # flows exist, all adjudicated legitimate
    else:
        verdict = "benign"          # no source->sink flow at all
    return ClusterPathVerdict(cluster_id, verdict, hostile_paths=hostile,
                              n_paths=len(paths),
                              n_unresolved_terminated=unresolved_term)

def apk_verdict(sha: str, cvs: list[ClusterPathVerdict],
                paths_by_id: dict[str, CandidatePath],
                pvs: dict[str, PathVerdict], cfg) -> ApkPathVerdict:
    mal = [c for c in cvs if c.verdict == "malicious"]
    susp = [c for c in cvs if c.verdict == "suspicious"]
    if mal:
        hostile = [pid for c in mal for pid in c.hostile_paths]
        classes = sorted({n for pid in hostile for n in paths_by_id[pid].nodes})
        conf = max(pvs[pid].confidence for pid in hostile)
        ev = [{"path": pid,
               "flow": f"{paths_by_id[pid].source_type}->{paths_by_id[pid].sink_type}",
               "classes": paths_by_id[pid].nodes,
               "why": pvs[pid].why} for pid in hostile]
        return ApkPathVerdict(sha, "malicious", round(conf, 2),
                              malicious_classes=classes, hostile_paths=ev,
                              cluster_verdicts={c.cluster_id: c.verdict for c in cvs},
                              rationale=f"{len(hostile)} verified hostile data-flow path(s)")
    if len(susp) >= cfg.apk_verdict.suspicious_cluster_threshold:
        return ApkPathVerdict(sha, "suspicious", 0.5,
                              cluster_verdicts={c.cluster_id: c.verdict for c in cvs},
                              rationale=f"{len(susp)} clusters with flows into unresolved code")
    return ApkPathVerdict(sha, "benign", 0.8,
                          cluster_verdicts={c.cluster_id: c.verdict for c in cvs},
                          rationale="no source->sink flow exceeded legitimate purpose")
