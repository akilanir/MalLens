"""Manifest -> class mapping: which classes are components, are they
exported, how many intent filters. Handles the pre-API-31 implicit-export
rule (intent-filter present + no explicit android:exported =&gt; exported)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_COMPONENT_TAGS = {"activity": "activity", "service": "service",
                   "receiver": "receiver", "provider": "provider",
                   "activity-alias": "activity"}


@dataclass
class ComponentInfo:
    class_name: str            # smali format
    component_type: str
    exported: bool = False
    intent_filter_count: int = 0
    intent_actions: list[str] = field(default_factory=list)


def _dotted_to_smali(name: str) -> str:
    return "L" + name.replace(".", "/") + ";"


def _resolve_name(raw: str, package: str) -> str | None:
    if not raw:
        return None
    if raw.startswith("."):
        return package + raw
    if "." not in raw:                      # bare name, relative to package
        return f"{package}.{raw}"
    return raw


def extract_components(apk_path: str | Path) -> dict[str, ComponentInfo]:
    """Cheap re-open: AXML only, no dex. Returns smali-name -> info."""
    from androguard.core.apk import APK
    try:
        a = APK(str(apk_path))
        root = a.get_android_manifest_xml()
        package = a.get_package() or ""
    except Exception as exc:
        logger.warning(f"manifest parse failed for {apk_path}: {exc}")
        return {}

    out: dict[str, ComponentInfo] = {}
    try:
        app = root.find("application")
        if app is None:
            return {}
        for el in app:
            ctype = _COMPONENT_TAGS.get(el.tag)
            if ctype is None:
                continue
            raw = el.get(_ANDROID_NS + "name") or el.get(_ANDROID_NS + "targetActivity")
            dotted = _resolve_name(raw, package)
            if dotted is None:
                continue
            filters = el.findall("intent-filter")
            actions = [a2.get(_ANDROID_NS + "name") or ""
                       for f in filters for a2 in f.findall("action")]
            exported_attr = el.get(_ANDROID_NS + "exported")
            if exported_attr is not None:
                exported = exported_attr.lower() == "true"
            else:
                exported = len(filters) > 0   # implicit export, pre-API-31
            smali = _dotted_to_smali(dotted)
            info = out.get(smali)
            if info is None:
                info = ComponentInfo(class_name=smali, component_type=ctype)
                out[smali] = info
            info.exported = info.exported or exported
            info.intent_filter_count += len(filters)
            info.intent_actions.extend(a3 for a3 in actions if a3)
    except Exception as exc:
        logger.warning(f"component walk failed: {exc}")
    return out
