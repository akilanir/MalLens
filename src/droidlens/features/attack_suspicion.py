import math
from dataclasses import dataclass
from typing import Callable

@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    tactic: str
    condition: Callable[[dict[str, float]], bool]


ATTACK_MAPPINGS: list[AttackTechnique] = [
    # =============== Initial Access ===============
    #T1453: Lockscreen Bypass
    AttackTechnique("T1453", "Execution", lambda f: f.get("keyguard", 0) > 0 and(f.get("overlay", 0) > 0 or f.get("accessibility", 0) > 0)),

    # =============== Execution ===============
    # T1575: Native API
    AttackTechnique("T1575", "Execution",lambda f: f.get("native_code", 0) > 0),

    # =============== Persistence ===============
    # T1624 is Event Triggered Execution
    # Check for signal: <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>: permission boot
    # and <action android:name="android.intent.action.BOOT_COMPLETED"/> ---> intent rcv: ToDo
    AttackTechnique("T1624","Persistence",lambda f: f.get("power", 0) > 0 
                    and (f.get("net_access", 0) > 0 or f.get("location", 0) > 0 or f.get("audio_record", 0) > 0 or f.get("accessibility", 0) > 0)),

    #T1624.001 Broadcast Receivers under persistence.
    AttackTechnique("T1624.001", "Persistence",lambda f: f.get("boot", 0) > 0),
    #From Mitre mapping
    AttackTechnique("T1624.001", "Persistence",lambda f: f.get("broad_rcv", 0) > 0),

    # =============== Privilege Escalation ===============
    # T1626.001: Device Admin Permissions -> This is Privilege Escalation.
    AttackTechnique("T1626.001", "Privilege Escalation", lambda f: f.get("admin", 0) > 0 or f.get("tag_device_admin", 0) > 0),

    # T1626: Abuse Elevation Control Mechanism
    # Rule: str_shell: su/chmod.. | str_exec_files: dex/jar/so.. | shell: sens API
    # AttackTechnique("T1626", "Privilege Escalation",lambda f: (f.get("str_shell", 0) > 0) or (f.get("str_exec_files", 0) > 0 and f.get("shell", 0) > 0)),
    AttackTechnique("T1626","Privilege Escalation",lambda f: (f.get("shell", 0) > 0 and (f.get("str_shell", 0) > 0 or f.get("str_exec_files", 0) > 0))),


    # T1404: Exploitation for Privilege Escalation
    # Check the rule: the admin APIs are not complete
    AttackTechnique("T1404", "Privilege Escalation",lambda f: (f.get("str_shell", 0) > 0 and f.get("admin", 0) > 0)),
    # ── future root detection can be added here ──

    # =============== Defense Evasion ===============
    # T1407 is Download New Code at Runtime in Defense Evasion
    AttackTechnique("T1407", "Defense Evasion", lambda f: f.get("dyncode", 0) > 0 and f.get("net_access", 0) > 0),

    # T1406: Obfuscation. obfuscation can be measured by high entropy. 
    # ToDo: anti_decomp: this signal is not there in our features
    # Obfuscation is not a direct malicious signal: assume
    # AttackTechnique("T1406", "Defense Evasion",lambda f: f.get("str_high_entropy", 0) > 0 or f.get("anti_decomp", 0) > 0),

    # T1655: Masquerading. 
    # ToDo: Only issue is the accuracy of our rule based spoof detection algo. It might not be 100% accurate
    AttackTechnique("T1655", "Defense Evasion",lambda f: f.get("spoofed", 0) > 10),

    # T1629: Impair Defenses
    AttackTechnique("T1629", "Defense Evasion",lambda f: f.get("str_impair_defenses", 0) > 0),

    # T1516: Input Injection
    AttackTechnique("T1516", "Defense Evasion",lambda f: f.get("overlay", 0) > 0),


    AttackTechnique("T1655", "Defense Evasion",lambda f: f.get("spoofed_framework", 0) > 0),

    # =============== Credential Access ===============
    # T1417: Input Capture
    AttackTechnique("T1417", "Credential Access",lambda f: f.get("accessibility", 0) > 0),

    
    # T1635: Steal Application Access TOken,
    AttackTechnique("T1635", "Credential Access",lambda f: f.get("clipboard", 0) > 0),

    # =============== Discovery ===============
    # T1418: Software Discovery:
    # ToDo: tag_pkg_list: this signal is not there in features
    AttackTechnique("T1418", "Discovery",lambda f: f.get("package_info", 0) > 0 or f.get("tag_pkg_list", 0) > 0),

    # T val and category corrrect. BUt we dont have device_id category apis. If the apis are something like Landroid/telephony/TelephonyManager;->getDeviceId,net_info,1.0,android.permission.ACCESS_NETWORK_STATE
    # Then we need to change some api categories. we have accounts api category 
    # T1426: System Information Discovery
    # ToDo Check rule
    # AttackTechnique("T1426", "Discovery",lambda f: f.get("accounts", 0) > 0 or f.get("contacts", 0) > 0),
    #From Mitre mapping
    AttackTechnique("T1426", "Discovery",lambda f: f.get("file_sys_discovery", 0) > 0 or f.get("sys_discovery", 0) > 0),

    # File and Directory Discovery. COrrect T val and cat.
    AttackTechnique("T1420", "Discovery",lambda f: f.get("storage", 0) > 0 and f.get("in_degree", 0) > 3),
    
    AttackTechnique("T1420", "Discovery",lambda f: f.get("file_discovery", 0) > 0),

    # System Network COnfiguration Discovery: correct. I think the rule is also correct
    AttackTechnique("T1422", "Discovery",lambda f: f.get("net_info", 0) > 0),
    #From Mitre mapping
    AttackTechnique("T1422", "Discovery",lambda f: f.get("net_discovery", 0) > 0),

    # =============== Collection ===============
    # T1513 Screen Capture
    AttackTechnique("T1513", "Collection",lambda f: f.get("accessibility", 0) > 0),
    #From Mitre mapping
    AttackTechnique("T1513", "Collection",lambda f: f.get("screen_capture", 0) > 0),

    # T1409: Stored Application Data in Collection
    AttackTechnique("T1409", "Collection", lambda f: f.get("accounts", 0) > 0 or f.get("contacts", 0) > 0),
    #From Mitre mapping
    AttackTechnique("T1409", "Collection",lambda f: f.get("app_data", 0) > 0),

    # Location tracking correct
    AttackTechnique("T1430", "Collection",lambda f: f.get("location", 0) > 0),

    # AUdio Capture.
    AttackTechnique("T1429", "Collection",lambda f: f.get("audio_record", 0) > 0),

    # T1412: Capture SMS messages
    AttackTechnique("T1412", "Collection",lambda f: f.get("sms_recv", 0) > 0),

    # T1512: Video Capture
    AttackTechnique("T1512", "Collection",lambda f: f.get("camera", 0) > 0),

    #keylog is T1417.001
    AttackTechnique("T1417.001", "Collection",lambda f: f.get("keylog", 0) > 0),
    #From Mitre mapping
    # AttackTechnique("T1417.001", "Collection",lambda f: f.get("keylog", 0) > 0),
    

    # =============== Command and Control ===============
    # C2 Application Layer Protocol. COrrect T val, signals seems to be correct
    AttackTechnique("T1437", "Command and Control",
                    lambda f: ((f.get("net_access", 0) > 0 or f.get("network", 0) > 0) and (f.get("str_urls", 0) > 0 or f.get("str_ips", 0) > 0))),

    #Proxy Through Victim
    AttackTechnique("T1604","Command and Control",lambda f: f.get("str_proxy_indicators",0)>0),

    
    # =============== Exfiltration ===============
    # T1646: Exfiltration over C2 channel. Seems the rule is too complex. Is it correct?
    AttackTechnique("T1646", "Exfiltration",
                    lambda f: f.get("net_access", 0) > 0 
                    and (f.get("location", 0) > 0 or f.get("sms_recv", 0) > 0 or f.get("accounts", 0) > 0)),

    # =============== Impact ===============
    # Correct one SMS Control
    AttackTechnique("T1582", "Impact",lambda f: f.get("sms_send", 0) > 0 and f.get("str_shortcodes", 0) > 0),

    
    # ========================================== Attack API =========
    AttackTechnique("T1423", "Discovery",lambda f: f.get("net_info_discovery", 0) > 0),

    AttackTechnique("T1424", "Discovery",lambda f: f.get("pro_discovery", 0) > 0),


    AttackTechnique("T1429", "Collection",lambda f: f.get("aud_capture", 0) > 0),

    AttackTechnique("T1430", "Collection",lambda f: f.get("loc_tracking", 0) > 0),

    AttackTechnique("T1471", "Impact",lambda f: f.get("encrypt", 0) > 0),

    AttackTechnique("T1603", "Persistence",lambda f: f.get("sche_task", 0) > 0),

    AttackTechnique("T1623", "Execution",lambda f: f.get("com_script", 0) > 0),

    AttackTechnique("T1636.001", "Collection",lambda f: f.get("calendar", 0) > 0),

    AttackTechnique("T1636.003", "Collection",lambda f: f.get("acc_contact", 0) > 0),

    AttackTechnique("T1636.004", "Collection",lambda f: f.get("cap_sms", 0) > 0),

    AttackTechnique("T1662", "Impact",lambda f: f.get("delete_data", 0) > 0),

    AttackTechnique("T1521", "Command and Control",lambda f: f.get("enc_channel", 0) > 0),

    AttackTechnique("T1630.002", "Defense Evasion",lambda f: f.get("delete_file", 0) > 0),

]

MITRE_RARITY_WEIGHTS = {
    "T1453": 6.833,
    "T1626.001": 6.140,
    "T1407": 5.447,
    "T1624.001": 5.447,
    "T1582": 5.224,
    "T1629": 4.887,
    "T1636.001": 4.636,
    "T1630.002": 4.348,
    "T1521": 2.476,
    "T1646": 2.300,
    "T1624": 2.062,
    "T1417": 1.657,
    "T1516": 1.195,
    "T1512": 1.058,
    "T1635": 1.022,
    "T1513": 0.898,
    "T1412": 0.837,
    "T1409": 0.706,
    "T1430": 0.680,
    "T1429": 0.612,
    "T1423": 0.610,
    "T1626": 0.403,
    "T1437": 0.395,
    "T1662": 0.317,
    "T1471": 0.292,
    "T1422": 0.212,
    "T1623": 0.210,
    "T1603": 0.208,
    "T1417.001": 0.174,
    "T1418": 0.140,
    "T1420": 0.121,
    "T1424": 0.106,
    "T1426": 0.088,
    "T1406": 0.062,
}
DEFAULT_TECHNIQUE_WEIGHT = 5.0

def compute_attack_suspicion(f: dict[str, float], lambda_density: float = 1.0) -> tuple[float, dict]:
    """
    Computes class suspicion based on MITRE ATT&CK Mobile Tactic Breadth. No heuristic float weights are used.
    """
    evidenced_techniques: set[str] = set()
    active_tactics: set[str] = set()
    fired_features: set[str] = set()

    technique_score = 0.0

    for rule in ATTACK_MAPPINGS:
        if rule.condition(f):
            tid = rule.technique_id
            evidenced_techniques.add(rule.technique_id)
            active_tactics.add(rule.tactic)
            weight = MITRE_RARITY_WEIGHTS.get(tid,DEFAULT_TECHNIQUE_WEIGHT)
            technique_score += weight
            fired_features.update(name for name,value in f.items() if value > 0)

    # Core Equation: Tactic Breadth + Log-Damped Technique Density
    tactic_breadth = len(active_tactics)
    technique_density = math.log1p(len(evidenced_techniques))
# float(technique_score) 
    score = float(tactic_breadth) + (lambda_density * technique_density)
    #score = number_of_att@ck_tacticks + lambda * log1p(number of evidenced techniques)
    details = {
        "score": round(score, 3),
        "tactic_breadth": tactic_breadth,
        "tactics": list(active_tactics),
        "techniques": list(evidenced_techniques),
        "fired_features": list(fired_features),
    }
    return round(score, 3), details

# def compute_class_importance(f: dict[str, float], lambda_density: float = 1.0) -> float:
#     evidenced_techniques: set[str] = set()
#     active_tactics: set[str] = set()
#     for rule in ATTACK_MAPPINGS:
#         if rule.condition(f):
#             evidenced_techniques.add(rule.technique_id)
#             active_tactics.add(rule.tactic)
#     tactic_breadth = len(active_tactics)
#     technique_density = math.log1p(len(evidenced_techniques))
#     return round(float(tactic_breadth) + lambda_density * technique_density, 3)
