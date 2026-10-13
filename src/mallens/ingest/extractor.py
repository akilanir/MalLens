"""Runs INSIDE the sandboxed child process (see runner.py). This is the
only module allowed to touch Androguard objects. Everything it returns
must be plain-Python / networkx picklable.

Androguard 4.x notes baked in:
  * We iterate ClassAnalysis xrefs directly instead of dx.get_call_graph():
    less memory, and we control external/framework handling explicitly.
  * xref tuples and Method objects vary (MethodAnalysis vs ExternalMethod,
    2- vs 3-tuples across minor versions) -> all access is defensive.
"""
from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Dict, Optional, Tuple

import networkx as nx
from loguru import logger

from mallens.config import Config
from mallens.core.datatypes import (ApkMetadata, ClassKind, RawClassRecord,
                                      Stage1Result)
from mallens.core.exceptions import IngestError
from mallens.ingest.classify import ClassClassifier
from mallens.utils.cache import sha256_of_file

_NATIVE_FLAG = 0x100

def _cls_name(obj) -> str | None:
    """Class name from ClassAnalysis / MethodAnalysis / ExternalMethod."""
    v = getattr(obj, "class_name", None) or getattr(obj, "name", None)
    return str(v) if v is not None else None


def _method_sig(m) -> str:
    cn = _cls_name(m) or "?"
    name = str(getattr(m, "name", "?"))
    return f"{cn}->{name}"


def _safe_int(fn, default=0):
    try:
        v = fn()
        return int(v) if v is not None else default
    except Exception:
        return default


def extract(apk_path: str | Path, cfg: Config) -> Stage1Result:
    from androguard.misc import AnalyzeAPK  # deferred: import cost + child-only
    
    apk_path = Path(apk_path)
    t0 = time.monotonic()
    logger.info(f"AnalyzeAPK: {apk_path.name}")
    try:
        a, dex_list, dx = AnalyzeAPK(str(apk_path))
    except Exception as exc:  # malformed zip/dex/manifest — all fatal here
        raise IngestError(f"AnalyzeAPK failed for {apk_path}: {exc}") from exc

    meta = _extract_metadata(a, apk_path, dex_list) # Extract apk metadata

    # Pre-listed framework, library, bundled ok package prefixes: This is very naive....
    clf = ClassClassifier(cfg.classify.framework_prefixes, cfg.classify.library_prefixes, cfg.classify.bundled_ok_prefixes,)

    records: dict[str, RawClassRecord] = {}
    graph = nx.DiGraph()
    edge_w: Counter[tuple[str, str]] = Counter()
    n_methods_seen = 0

    # ---- pass 0: which classes actually live in the dex? --------------
    # Added to capture spoofed packages (android/system/sa: Milkydoor)
    # Internal classes help us to detect classes provided by the Android OS runtime (Android Framework/JRE)
    internal_names: set[str] = set()
    no_original_classes = 0
    no_removed_classes = 0
    no_external_classes = 0
    no_left_classes = 0
    no_lib_classes = 0
    for ca in dx.get_classes():
        no_original_classes += 1
        try:
            if not ca.is_external():
                n = _cls_name(ca)
                if n:
                    internal_names.add(n)
        except Exception:
            continue

    if no_original_classes < 100:
        logger.info(f"This APK is small and we won't remove libs/frameworks: {no_original_classes}")

    clf = ClassClassifier(cfg.classify.framework_prefixes,
                              cfg.classify.library_prefixes,
                              cfg.classify.bundled_ok_prefixes,
                              internal_names=internal_names)

    # ---- pass 1: classes, methods, call edges, api calls -------------
    for ca in dx.get_classes():
        try:
            if ca.is_external():
                # if no_original_classes < 100:
                #     cname = _cls_name(ca)
                #     logger.info(f"External class {cname} removed......")
                no_external_classes += 1
                continue
            cname = _cls_name(ca)
            if cname is None:
                # if no_original_classes < 100:
                #     logger.info("No class name: {cname}......")
                no_external_classes += 1
                continue
            # THIS IS HIGHLY BIASED TOWARED MILKY DOOR
            # With hardcoded fw,lib, and ok_to_bundle lists won't act as the best filters (Rule based prefix classifiers)
            kind, spoofed = clf.kind_of(cname) # Added to capture spoofed packages (android/syste/sa: Milkydoor)
            # eg. if android/system/sa is an internal, hence it is a framework package kind will be overwritten to APP, and will flagged as spoofed
            if kind is ClassKind.FRAMEWORK and no_original_classes > 100:
                no_removed_classes += 1
                continue
            if kind is ClassKind.LIBRARY and not cfg.ingest.include_library_nodes and no_original_classes > 100:
                no_removed_classes += 1
                continue

            no_left_classes += 1
            rec = records.get(cname) or RawClassRecord(name=cname, kind=kind)
            rec.spoofed_framework_name = spoofed # Added to capture spoofed packages (android/system/sa: Milkydoor)
            records[cname] = rec
            rec.superclass = str(getattr(ca, "extends", None) or "") or None #extends: Returns the parent class
            try:
                rec.interfaces = [str(i) for i in (getattr(ca, "implements", None) or [])] #implements: Returns a list of interface names which are implemented by this class
            except Exception:
                pass

            for ma in ca.get_methods():
                n_methods_seen += 1
                rec.method_count += 1
                enc = getattr(ma, "method", None)  # EncodedMethod for internals
                if enc is not None:
                    flags = _safe_int(enc.get_access_flags) #access modifiers: public, private, static, final, abstract, native 
                    if flags & _NATIVE_FLAG: # bitwise AND is non-zero -> method is Native Method implemented in C or C++ with JNI
                        rec.native_method_count += 1
                    try:
                        code = enc.get_code()
                        if code is not None:
                            rec.bytecode_size += _safe_int(code.get_bc().get_length)
                    except Exception:
                        pass

                # ---- outgoing xrefs -------------------------------
                try:
                    xrefs = ma.get_xref_to()
                except Exception:
                    continue
                for x in xrefs:
                    callee = x[1] if len(x) >= 2 else None  # (CA, MA, off)
                    if callee is None:
                        continue
                    callee_cls = _cls_name(callee)
                    if not callee_cls or callee_cls == cname: # Ignore intra-class Calls
                        continue
                    ckind, c_poofed = clf.kind_of(callee_cls) # Added c_poofed to capture spoofed packages (android/syste/sa: Milkydoor), but it is not used here
                    if ckind is ClassKind.FRAMEWORK: #OS Framework
                        sig = _method_sig(callee) # exact method signature: e.g., Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;
                        # logger.info(f"ORIGINAL API SIGNAL: {sig}" )
                        rec.api_calls[sig] = rec.api_calls.get(sig, 0) + 1
                    elif ckind is ClassKind.LIBRARY and not cfg.ingest.include_library_nodes:
                        rec.lib_call_count += 1 #If our lib detection: the rule basesd one fails, this logic fails here
                    else: #ClassKind.App
                        edge_w[(cname, callee_cls)] += 1
        except Exception as exc:
            # logger.warning(f"class-level failure on {_cls_name(ca)}: {exc}")
            continue

    # ---- pass 2: string constants -> owning classes -------------------
    max_s, max_len = cfg.ingest.max_strings_per_class, cfg.ingest.max_string_length
    try:
        for sa in dx.get_strings():
            try:
                val = str(sa.get_orig_value())[:max_len] #Are we restricting the string??
                if len(val) < 4:
                    continue
                for ref in sa.get_xref_from():
                    owner = _cls_name(ref[0] if isinstance(ref, tuple) else ref)
                    rec = records.get(owner) if owner else None
                    if rec is not None and len(rec.string_constants) < max_s:
                        rec.string_constants.append(val)
            except Exception:
                continue
    except Exception as exc:
        logger.warning(f"string extraction failed entirely: {exc}")

    # ---- assemble graph -----------------------------------------------
    # We can add method importance here: but we calculate it in stage 2
    for cname, rec in records.items():
        graph.add_node(cname, kind=rec.kind.value,
                       method_count=rec.method_count,
                       bytecode_size=rec.bytecode_size)
    for (src, dst), w in edge_w.items():
        # dst may be an internal class we skipped (library) or a stub class
        # missing from a split apk -> only add edges between known nodes,
        # but remember drops in stats.
        if graph.has_node(src) and graph.has_node(dst):
            graph.add_edge(src, dst, weight=w)

    meta.analysis_seconds = round(time.monotonic() - t0, 2)
    stats = {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "methods_seen": n_methods_seen,
        "dropped_edge_endpoints": len(edge_w) - graph.number_of_edges(),
        "isolated_nodes": sum(1 for n in graph if graph.degree(n) == 0),
        "classes_with_api_calls": sum(1 for r in records.values() if r.api_calls),
        "native_classes": sum(1 for r in records.values() if r.native_method_count),
        "spoofed_framework_classes": sum(1 for r in records.values() if r.spoofed_framework_name),

    }
    logger.info(f"stage1 done in {meta.analysis_seconds}s: {stats}")
    logger.info(f"Class Stats: -------------\nTotal Classes: {no_original_classes}\nTPL Detected Classes: {no_lib_classes}\nExternal Classes: {no_external_classes}\nRemoved Classes: {no_removed_classes}\nLeft Classes: {no_left_classes}")
    return Stage1Result(apk=meta, class_records=records, graph=graph, stats=stats)

def ex_perm2(a):
    manifest = a.get_android_manifest_xml()
    no_perm = 0

    # Find all <uses-permission> tags
    # Note: The attribute key uses the Android namespace syntax
    android_ns = "{http://android.com}name"

    for perm_element in manifest.findall(".//uses-permission"):
        permission_name = perm_element.attrib.get(android_ns)
        if permission_name:
            no_perm +=1
            print(permission_name)
    print(f"Extracted permissions: {no_perm}")

def ex_perm(a):
    # 2. Extract the Manifest as an ElementTree object
    manifest = a.get_android_manifest_xml()
    no_perm = 0

    # 3. Define the standard Android Namespace string 
    #    This replaces the 'android:' prefix in raw XML
    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

    # 4. Find all <uses-permission> tags and print their names
    for permission in manifest.findall(".//uses-permission"):
        name_attr = f"{ANDROID_NS}name"
        permission_name = permission.attrib.get(name_attr)
        if permission_name:
            no_perm+=1
            print(f"Requested Permission: {permission_name}")
    print(f"Extracted permissions: {no_perm}")

def _extract_metadata(a, apk_path: Path, dex_list) -> ApkMetadata:
    def _try(fn, default):
        try:
            v = fn()
            return v if v is not None else default
        except Exception:
            return default

    from mallens.features.app_role_gen import extract_role_evidence
    app_role_evidence = extract_role_evidence(apk=a)

    # if "09e39391b0e99f5f6751daa802d9271c08faa0ffa36fa87f20d5d1eecbe03a8f" in apk_path:
    #     logger.info("We are analysing activities,receivers... :")
    #     logger.info("1- Activities ----")
    #     logger.info(a.get_activities)
    #     logger.info("2- Services ----")
    #     logger.info(a.get_services)
    #     logger.info("3- Receivers ----")
    #     logger.info(a.get_receivers)
    #     logger.info("4- Providers ----")
    #     logger.info(a.get_providers)


    return ApkMetadata(
        sha256=sha256_of_file(apk_path),
        path=str(apk_path),
        file_size=apk_path.stat().st_size,
        package_name=str(_try(a.get_package, "")),
        main_activity=_try(a.get_main_activity, None),
        min_sdk=_safe_int(a.get_min_sdk_version, None) if hasattr(a, "get_min_sdk_version") else None,
        target_sdk=_safe_int(a.get_target_sdk_version, None) if hasattr(a, "get_target_sdk_version") else None,
        permissions=[str(p) for p in _try(a.get_permissions, [])],
        activities=[str(x) for x in _try(a.get_activities, [])],
        services=[str(x) for x in _try(a.get_services, [])],
        receivers=[str(x) for x in _try(a.get_receivers, [])],
        providers=[str(x) for x in _try(a.get_providers, [])],
        dex_count=len(dex_list) if dex_list else 0,
        app_role=app_role_evidence,
    )

