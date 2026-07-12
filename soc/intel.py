"""
Third-party threat intelligence lookups: MAC vendor identification,
IP geolocation/ISP, and AbuseIPDB reputation checks. Each has its own
in-memory cache so a device seen every cycle doesn't re-hit the API.
"""
import re
import time

from soc.config import (
    MAC_VENDOR_ENABLED, IPINFO_ENABLED,
    ABUSEIPDB_ENABLED, ABUSEIPDB_KEY,
)
from soc.utils import safe_request

_vendor_cache: dict = {}
_ipinfo_cache: dict = {}
_abuse_cache: dict = {}


def lookup_mac_vendor(mac: str) -> str:
    if not MAC_VENDOR_ENABLED or not mac:
        return "Unknown"
    prefix = ":".join(mac.upper().replace("-", ":").split(":")[:3])
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]
    r = safe_request("GET", f"https://api.macvendors.com/{prefix}", timeout=5)
    v = r.text.strip() if (r and r.status_code == 200) else "Unknown"
    _vendor_cache[prefix] = v
    time.sleep(0.3)
    return v


def lookup_ipinfo(ip: str) -> dict:
    empty = {"country": "", "city": "", "isp": ""}
    if not IPINFO_ENABLED:
        return empty
    if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', ip):
        return empty
    if ip in _ipinfo_cache:
        return _ipinfo_cache[ip]
    r = safe_request("GET", f"https://ipinfo.io/{ip}/json", timeout=5)
    if r and r.status_code == 200:
        d   = r.json()
        res = {"country": d.get("country", ""),
               "city":    d.get("city", ""),
               "isp":     d.get("org", "")}
    else:
        res = empty
    _ipinfo_cache[ip] = res
    return res


def lookup_abuseipdb(ip: str) -> int:
    if not ABUSEIPDB_ENABLED or not ABUSEIPDB_KEY:
        return 0
    if ip in _abuse_cache:
        return _abuse_cache[ip]
    r = safe_request(
        "GET", "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=8
    )
    score = r.json().get("data", {}).get("abuseConfidenceScore", 0) \
            if (r and r.status_code == 200) else 0
    _abuse_cache[ip] = score
    return score
