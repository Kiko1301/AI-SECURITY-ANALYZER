"""
Threat scoring: turns device attributes + open ports + flags into a
single 0-100 risk score. Kept isolated so the scoring model can be
tuned or unit-tested without touching scanning/DB/alerting code.
"""
from soc.config import RISKY_PORTS


def compute_threat_score(device: dict, open_ports: list,
                          is_new: bool, arp_spoofed: bool) -> int:
    s = 0
    if arp_spoofed:          s += 45
    if is_new:               s += 25
    if not device.get("is_known"): s += 10
    if not (device.get("vendor") or "").strip() \
       or device.get("vendor") == "Unknown": s += 10
    s += min(int(device.get("abuse_score") or 0) // 5, 20)
    for p in open_ports:
        if p.get("port") in RISKY_PORTS:
            _, risk = RISKY_PORTS[p["port"]]
            s += risk
    return min(s, 100)
