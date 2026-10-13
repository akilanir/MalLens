"""String-constant analysis: entropy + suspicious-pattern counts."""
from __future__ import annotations

import math
import re
from collections import Counter

_URL = re.compile(r'https?://[^\s"\'<>]{4,}', re.I)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
_B64 = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")
_SHELL = re.compile(
    r"(su\b|sh -c|chmod \d{3}|pm install|am start|mount -o|"
    r"/system/bin/|/system/xbin/|busybox|iptables)"
)
_EXEC_FILE = re.compile(r"\.(apk|dex|jar|so|elf)\b", re.I)
_SMS_PREMIUM = re.compile(r"^\+?\d{4,6}$")   # short-code numbers
# Regex for explicit defense impairment commands
_IMPAIR_DEFENSES_CMD = re.compile(
    r"(setenforce\s+0|setenforce\s+permissive|pm\s+(disable|hide|suspend)|"
    r"logcat\s+-c|mount\s+-o\s+remount,rw\s+/system)",
    re.I
)
_REMOTE_CONNECTION = re.compile(
    r"(ssh|jsch|socket|proxy|tunnel|port.?forward|"
    r"reverse.?shell|socks|session|channel)",
    re.I
)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze_strings(strings: list[str], entropy_threshold: float,
                    min_len_for_entropy: int) -> dict[str, float]:
    n_high_ent, max_ent = 0, 0.0
    n_url = n_ip = n_b64 = n_shell = n_exec = n_short = n_impair_defense = n_proxy_indicators = 0
    for s in strings:
        if len(s) >= min_len_for_entropy:
            e = shannon_entropy(s)
            max_ent = max(max_ent, e)
            if e >= entropy_threshold:
                n_high_ent += 1
        if _URL.search(s):
            n_url += 1
        if _IP.search(s):
            n_ip += 1
        if _B64.match(s):
            n_b64 += 1
        if _SHELL.search(s):
            # print(f"---------------** Important SHELL: {s}")
            n_shell += 1
        if _EXEC_FILE.search(s):
            # print(f"---------------** Important EXEC: {s}")
            n_exec += 1
        if _SMS_PREMIUM.match(s):
            n_short += 1
        if _IMPAIR_DEFENSES_CMD.match(s):
            n_impair_defense += 1 
        if _REMOTE_CONNECTION.match(s):
            n_proxy_indicators += 1

    return {
        "str_count": float(len(strings)),
        "str_high_entropy": float(n_high_ent),
        "str_max_entropy": round(max_ent, 3),
        "str_urls": float(n_url),
        "str_ips": float(n_ip),
        "str_base64": float(n_b64),
        "str_shell": float(n_shell),
        "str_exec_files": float(n_exec),
        "str_shortcodes": float(n_short),
        "str_impair_defenses": float(n_impair_defense),
        "str_proxy_indicators": float(n_proxy_indicators),
    }
