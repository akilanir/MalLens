from __future__ import annotations
import argparse,csv,hashlib,math,pickle,sys
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scripts.misc.scripts_common import run_stages_1_to_3 
from mallens.utils.cache import ArtifactCache, sha256_of_file

plt.rcParams.update({
    "font.family":"serif","font.size":11,"axes.labelsize":12,
    "axes.titlesize":13,"xtick.labelsize":10,"ytick.labelsize":10,
    "legend.fontsize":10,"figure.titlesize":15,"lines.linewidth":2.0,
    "lines.markersize":6.5,"axes.spines.top":False,"axes.spines.right":False
})

SCORERS=["pagerank"]
TOPK=(1,5,10,15,20)
PRIMARY_K=10

def sha256_file(path:Path,chunk_size:int=1024*1024)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        while chunk:=f.read(chunk_size): h.update(chunk)
    return h.hexdigest()

def load_pickle(path:Path):
    if not path.exists(): raise FileNotFoundError(f"Cache file not found: {path}")
    with path.open("rb") as f: return pickle.load(f)

def load_cached_stages(apk:Path,cache_root:Path):
    # IMPORTANT: the APK filename is used only to identify the APK. S1/S2/S3
    # are cached using SHA-256: cache/<sha256>/stage1.pkl, stage2.pkl, stage3.pkl.
    # We therefore hash the actual APK and use that hash to retrieve its cache.
    apk_hash=sha256_file(apk)
    cache_dir=cache_root/apk_hash
    return (load_pickle(cache_dir/"stage1.pkl"),
            load_pickle(cache_dir/"stage2.pkl"),
            load_pickle(cache_dir/"stage3.pkl"),
            apk_hash)

def load_ground_truth(apk:Path,gt_root:Path)->set[str]:
    # IMPORTANT: GT is mapped using the ORIGINAL APK GIVEN NAME, not SHA-256.
    # APKS/APK-foo.apk -> GT/APK-foo.txt. This is intentionally independent
    # from cache mapping because cache uses the APK hash while GT uses its name.
    apk_name_full=apk.stem
    gt_name_pref = apk_name_full.split("-release")[0]
    gt_file = gt_root / f"{gt_name_pref}.conf.gt.txt"
    if not gt_file.exists(): raise FileNotFoundError(f"Ground-truth file not found: {gt_file}")
    payload=set()
    for n,line in enumerate(gt_file.read_text(encoding="utf-8",errors="replace").splitlines(),1):
        line=line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("L"): 
            line = line + ";"
            payload.add(line)
        else: print(f"WARNING: malformed GT {gt_file}:{n}: {line}",file=sys.stderr)
    return payload

def cluster_classes(c)->set[str]:
    names=getattr(c,"class_names",[]) or []
    if isinstance(names,str): names=[names]
    return {str(x).strip() for x in names if str(x).strip()}

def cluster_importance(c)->float:
    try:
        x=float(getattr(c,"importance",0.0))
        return x if math.isfinite(x) else 0.0
    except (TypeError,ValueError): return 0.0

def cluster_seed(c):
    x=getattr(c,"seed_class",None)
    return str(x).strip() if x else None

def compute_scores(s1,s2,cfg,name):
    from mallens.importance.scorers import get_scorer
    raw=get_scorer(name).score(s1,s2,cfg) or {}
    out={}
    for c,v in raw.items():
        try:
            v=float(v)
            if math.isfinite(v): out[str(c)]=v
        except (TypeError,ValueError): pass
    return out

def payload_percentile(scores,classes,payload):
    valid=[c for c in classes if c in scores]
    if not valid or not payload: return float("nan")
    values=np.asarray([scores[c] for c in valid],float)
    order=np.argsort(values,kind="stable")
    ranks=np.empty(len(values))
    ranks[order]=np.arange(len(values))
    ranks=np.ones(1) if len(values)==1 else ranks/(len(values)-1)
    vals=[dict(zip(valid,ranks))[c] for c in payload if c in dict(zip(valid,ranks))]
    return float(np.median(vals)) if vals else float("nan")

def analyse_apk(apk,cache_root,gt_root,cfg):
    ######### IM
    apk_hash = sha256_of_file(apk)
    s1, s2, s3 = run_stages_1_to_3(apk, cfg, force=False)
    gt=load_ground_truth(apk,gt_root)
    classes=[str(c).strip() for c in getattr(s2,"records",{}).keys()]
    payload=gt&set(classes)
    clusters=sorted(list(getattr(s3,"clusters",[]) or []),key=cluster_importance,reverse=True)
    cluster_sets=[cluster_classes(c) for c in clusters]
    hits=np.asarray([len(payload&s) for s in cluster_sets],float)
    sizes=np.asarray([len(s) for s in cluster_sets],float)
    coverage={}
    for k in TOPK:
        union=set().union(*cluster_sets[:k]) if cluster_sets[:k] else set()
        coverage[k]=len(payload&union)/len(payload) if payload else np.nan
    first_hit=next((i for i,h in enumerate(hits,1) if h>0),None)
    seed_hits=sum(1 for c in clusters if cluster_seed(c) in payload)
    scores=compute_scores(s1,s2,cfg,SCORERS[0])
    pctl=payload_percentile(scores,classes,payload)
    return {
        "apk":apk.name,"family":apk.parent.name,"sha256":apk_hash,
        "n_app":len(classes),"n_payload_gt":len(gt),"n_payload_found":len(payload),
        "n_payload_missing":len(gt-payload),"n_clusters":len(clusters),
        "seed_hits":seed_hits,"first_hit_rank":first_hit if first_hit else np.nan,
        "payload_percentile":pctl,"coverage":coverage,"hits":hits,"sizes":sizes
    }

def write_summary(results,path):
    fields=["family","apk","sha256","n_app","n_payload_gt","n_payload_found",
             "n_payload_missing","n_clusters","seed_hits","first_hit_rank",
             "payload_percentile"]+[f"coverage@{k}" for k in TOPK]
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in results:
            row={k:r[k] for k in fields if not k.startswith("coverage@")}
            row.update({f"coverage@{k}":r["coverage"][k] for k in TOPK})
            w.writerow(row)

def plot_main(results,out):
    fig,axes=plt.subplots(2,2,figsize=(13.5,9.2))
    plt.subplots_adjust(left=.08,right=.97,bottom=.08,top=.91,wspace=.27,hspace=.32)

    # (a) Aggregate cumulative payload coverage. Unlike the old heatmap, this
    # collapses 2,957 APKs into a single readable localisation curve.
    ax=axes[0,0]
    means=[];medians=[];q25=[];q75=[]
    for k in TOPK:
        v=np.asarray([r["coverage"][k] for r in results if np.isfinite(r["coverage"][k])])
        means.append(np.mean(v) if len(v) else np.nan)
        medians.append(np.median(v) if len(v) else np.nan)
        q25.append(np.percentile(v,25) if len(v) else np.nan)
        q75.append(np.percentile(v,75) if len(v) else np.nan)
    x=np.arange(len(TOPK))
    ax.plot(x,means,"o-",label="Mean")
    ax.plot(x,medians,"s--",label="Median")
    ax.fill_between(x,q25,q75,alpha=.18,label="25th–75th percentile")
    ax.set_xticks(x,[str(k) for k in TOPK]);ax.set_ylim(0,1.05)
    ax.set_xlabel("Top-ranked clusters inspected");ax.set_ylabel("Payload coverage")
    ax.set_title("(a) Cumulative payload localisation")
    ax.grid(True,linestyle=":",alpha=.6);ax.legend(loc="lower right")

    # (b) Percentage of APKs for which ALL known payload classes are recovered.
    # This directly measures complete localisation, rather than average recall.
    ax=axes[0,1]
    complete=[np.mean([r["coverage"][k]>=.999999 for r in results])*100 for k in TOPK]
    ax.plot(TOPK,complete,"o-",linewidth=2.5)
    for k,v in zip(TOPK,complete): ax.annotate(f"{v:.1f}%",(k,v),xytext=(0,8),textcoords="offset points",ha="center")
    ax.set_ylim(0,105);ax.set_xlabel("Top-ranked clusters inspected")
    ax.set_ylabel("APKs with complete payload localisation (%)")
    ax.set_title("(b) Complete payload localisation")
    ax.grid(True,linestyle=":",alpha=.6)

    # (c) First payload-containing cluster. This shows how early the ranking
    # reaches the known malicious payload without plotting every APK separately.
    ax=axes[1,0]
    first=np.asarray([r["first_hit_rank"] for r in results if np.isfinite(r["first_hit_rank"])])
    if len(first):
        max_rank=min(max(int(first.max()),PRIMARY_K),20)
        counts=np.bincount(first.astype(int),minlength=max_rank+1)[1:max_rank+1]
        ax.bar(np.arange(1,max_rank+1),counts,edgecolor="black",alpha=.8)
        ax.axvline(PRIMARY_K,ls="--",lw=1.5,label=f"Top-{PRIMARY_K} budget")
        ax.legend(loc="upper right")
    ax.set_xlabel("Rank of first payload-containing cluster");ax.set_ylabel("Number of APKs")
    ax.set_title("(c) Early payload discovery");ax.grid(True,axis="y",linestyle=":",alpha=.6)

    # (d) Aggregate cluster isolation. Each point is a cluster-rank summary
    # across all APKs, replacing the previous 2,957-row APK-level figure.
    ax=axes[1,1]
    rank_data=[]
    for rank in range(PRIMARY_K):
        vals=[]
        for r in results:
            if rank<len(r["sizes"]) and r["sizes"][rank]>0:
                vals.append(r["hits"][rank]/r["sizes"][rank])
        rank_data.append(vals)
    positions=np.arange(1,PRIMARY_K+1)
    bp=ax.boxplot(rank_data,positions=positions,widths=.55,showfliers=False,patch_artist=True)
    for box in bp["boxes"]: box.set_alpha(.55)
    med=[np.median(v) if len(v) else np.nan for v in rank_data]
    ax.plot(positions,med,"o-",label="Median")
    ax.set_xlabel("Cluster rank");ax.set_ylabel("Payload classes / cluster classes")
    ax.set_ylim(0,1.05);ax.set_xticks(positions)
    ax.set_title("(d) Aggregate payload concentration")
    ax.grid(True,axis="y",linestyle=":",alpha=.6);ax.legend(loc="upper right")

    fig.suptitle("Evaluation of Malicious Payload Localisation",fontsize=15)
    fig.savefig(out/"payload_localisation_evaluation.pdf",dpi=300,bbox_inches="tight")
    fig.savefig(out/"payload_localisation_evaluation.png",dpi=300,bbox_inches="tight")
    plt.close(fig)

def print_statistics(results):
    print("\n"+"="*80+"\nOVERALL PAYLOAD LOCALISATION RESULTS\n"+"="*80)
    print(f"APKs analysed       : {len(results)}")
    for k in TOPK:
        v=np.asarray([r["coverage"][k] for r in results if np.isfinite(r["coverage"][k])])
        if len(v): print(f"Coverage@{k:<2}          : mean={v.mean():.2%}, median={np.median(v):.2%}, min={v.min():.2%}, max={v.max():.2%}")
    first=np.asarray([r["first_hit_rank"] for r in results if np.isfinite(r["first_hit_rank"])])
    if len(first):
        print(f"First payload <= {PRIMARY_K}: {np.mean(first<=PRIMARY_K):.2%} of APKs")
        print(f"Median first-hit rank : {np.median(first):.1f}")
    p=np.asarray([r["payload_percentile"] for r in results if np.isfinite(r["payload_percentile"])])
    if len(p): print(f"Median payload importance percentile: {np.median(p):.2%}")
    print("="*80)

def main():
    # ap=argparse.ArgumentParser(description="Evaluate payload localisation using cached S1/S2/S3.")
    parser = argparse.ArgumentParser(description="Evaluate payload localisation using cached S1/S2/S3.")
    parser.add_argument("--apks", required=True, help="Directory containing APK-given_name.apk files.")
    parser.add_argument("--cache", required=True, help="Cache directory containing <sha256>/stage1.pkl, stage2.pkl, stage3.pkl.")
    parser.add_argument("--gt", required=True, help="Directory containing APK-given_name.txt ground-truth files.")
    parser.add_argument("--config", required=True, help="DroidLens configuration file.")
    parser.add_argument("--out", default="payload_localisation_probe")
    args = parser.parse_args()
    
    apk_root, cache_root, gt_root, out = map(Path, (args.apks, args.cache, args.gt, args.out))
    
    out.mkdir(parents=True,exist_ok=True)
    from mallens.config import Config
    cfg=Config.load(args.config)
    apks=sorted(apk_root.glob("*.apk"))
    if not apks: raise RuntimeError(f"No APKs found in {apk_root}")
    results=[]
    for apk in apks:
        try:
            results.append(analyse_apk(apk,cache_root,gt_root,cfg))
        except Exception as e:
            print(f"FAIL {apk.name}: {type(e).__name__}: {e}",file=sys.stderr)
    if not results: raise RuntimeError("No APKs were successfully analysed.")
    write_summary(results,out/"payload_localisation_summary.csv")
    plot_main(results,out)
    print_statistics(results)
    print(f"\nResults written to: {out.resolve()}")

if __name__=="__main__":
    main()