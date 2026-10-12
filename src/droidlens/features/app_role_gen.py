from loguru import logger
from droidlens.utils.logsetup import setup_logging
from droidlens.config import Config
cfg = Config.load("configs/default.yaml")
setup_logging(cfg.logging.level, cfg.logging.androguard_level)

import xml.etree.ElementTree as ET

def _extract_resource_names(resources, package_name, resource_type):
    names = []
    try:
        method = getattr(resources, f"get_{resource_type}_resources")
        raw = method(package_name)
        if not raw:
            return names
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        root = ET.fromstring(raw)
        for elem in root:
            name = elem.get("name")
            if name:
                names.append(name)
    except Exception:
        pass
    return sorted(set(names))

def _extract_string_resource_names(resources, package_name):
    names = []
    try:
        raw = resources.get_string_resources(package_name)
        if not raw:
            return names
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        root = ET.fromstring(raw)
        for elem in root.findall("string"):
            name = elem.get("name")
            if name:
                names.append(name)
    except Exception:
        pass
    return sorted(set(names))

def _clean_class_name(name):
    if not name:
        return name
    name = name.replace("/", ".")
    if name.startswith("."):
        return name
    return name

def extract_role_evidence(apk):
    """
    Extracts ONLY application-role evidence.
    Deliberately excludes:
      - permissions
      - API calls
      - sensitive APIs
      - intent actions
      - receivers
      - services
      - URLs/IPs
      - network behavior
      - SMS/contacts/location/camera capabilities
    """
    
    package_name = apk.get_package()
    app_name = apk.get_app_name()

    # ---------------------------------------------------------
    # 1. BASIC APPLICATION IDENTITY
    # ---------------------------------------------------------
    main_activities = sorted(apk.get_main_activities())
    activities = sorted(apk.get_activities())

    # ---------------------------------------------------------
    # 2. ANDROID RESOURCES
    # ---------------------------------------------------------
    resource_names = {
        "layouts": [],
        "menus": [],
        "drawables": [],
        "strings": [],
        "ids": [],
        "xml": []
    }

    resources = apk.get_android_resources()

    if resources:
        resource_names["layouts"] = _extract_resource_names(
            resources, package_name, "layout"
        )
        resource_names["menus"] = _extract_resource_names(
            resources, package_name, "menu"
        )
        resource_names["drawables"] = _extract_resource_names(
            resources, package_name, "drawable"
        )
        resource_names["strings"] = _extract_string_resource_names(
            resources, package_name
        )
        resource_names["ids"] = _extract_resource_names(
            resources, package_name, "id"
        )
        resource_names["xml"] = _extract_resource_names(
            resources, package_name, "xml"
        )

    # ---------------------------------------------------------
    # 3. APPLICATION STRUCTURE
    # ---------------------------------------------------------
    application_structure = {
        "activity_count": len(activities),
        "main_activity_count": len(main_activities),
        "activities": activities[:50]
    }

    # ---------------------------------------------------------
    # 4. FINAL ROLE-EVIDENCE PAYLOAD
    # ---------------------------------------------------------
    payload = {
        "app_identity": {
            "app_name": app_name,
            "package_name": package_name,
            "main_activities": main_activities
        },
        "application_structure": application_structure,
        "presentation_evidence": {
            "layout_names": resource_names["layouts"][:20],
            "menu_names": resource_names["menus"][:20],
            "drawable_names": resource_names["drawables"][:20],
            "string_resource_names": resource_names["strings"][:20],
            "id_names": resource_names["ids"][:20],
            "xml_resource_names": resource_names["xml"][:20]
        }
    }

    return payload

# if __name__ == "__main__":
#     apk_path = "/mnt/SATA_3/akila/AK_PHD3/AgentDroid/apks/benign-LAMD/1C02675B33E015C28B5B89D16096E2D9BE09AD001C0EE034CFCC904D02A9B6F0.apk"
#     apk, d, dx = AnalyzeAPK(apk_path)
#     evidence = extract_role_evidence(apk)
#     print(json.dumps(evidence, indent=2, ensure_ascii=False))