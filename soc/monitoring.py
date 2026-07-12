"""
Host-level monitoring integrations: Netdata (system metrics) and
ntopng (network traffic + alerts). Fetchers pull raw data; formatters
turn it into the plain-text blocks used in reports and AI prompts.
"""
import requests

from soc.config import NETDATA_URL, NTOPNG_URL, NTOPNG_USER, NTOPNG_PASS
from soc.utils import safe_request
from soc.ui import cprint, status_ok, status_warn, status_err, C


def get_netdata_metrics() -> dict:
    cprint(f"\n  📊  Fetching Netdata metrics …", C.CYAN)
    r = safe_request("GET", f"{NETDATA_URL}/api/v1/info", timeout=5)
    if not r or r.status_code != 200:
        status_err(f"Netdata unreachable → {NETDATA_URL}")
        return {"error": "Unreachable"}
    status_ok(f"Netdata v{r.json().get('version','?')}")
    metrics = {}
    for key, chart in {
        "cpu": "system.cpu", "ram": "system.ram",
        "network": "system.net", "disk": "system.io", "load": "system.load"
    }.items():
        cr = safe_request(
            "GET", f"{NETDATA_URL}/api/v1/data",
            params={"chart": chart, "after": -60, "before": 0, "points": 1, "format": "json"},
            timeout=10
        )
        if cr and cr.status_code == 200:
            metrics[key] = cr.json(); status_ok(f"{chart} ✓")
        else:
            status_warn(f"{chart}: no data")
    return metrics


def get_ntopng_data() -> dict:
    cprint(f"\n  🌐  Fetching ntopng data …", C.CYAN)
    ntop    = {}
    session = requests.Session()
    try:
        login = session.post(
            f"{NTOPNG_URL}/login",
            data={"user": NTOPNG_USER, "password": NTOPNG_PASS}, timeout=10
        )
        if not login or login.status_code != 200:
            ntop["error"] = "Login failed"; return ntop
        status_ok("ntopng login OK")
        r = session.get(f"{NTOPNG_URL}/lua/traffic_stats.lua", timeout=10)
        if r and r.status_code == 200:
            try:
                d = r.json(); tput = d.get("throughput", {})
                i_kb = float(tput.get("in", 0))/1024
                o_kb = float(tput.get("out", 0))/1024
                ntop["traffic_summary"] = {"in": i_kb, "out": o_kb}
                cprint(f"  📈  In: {i_kb:.1f} KB/s  Out: {o_kb:.1f} KB/s", C.GREEN)
            except Exception:
                status_warn("Traffic endpoint returned non-JSON")
        r = session.get(f"{NTOPNG_URL}/lua/get_alerts.lua", timeout=10)
        if r and r.status_code == 200:
            try:
                alerts = r.json()
                if isinstance(alerts, list):
                    ntop["alerts"] = alerts
                    ntop["alert_count"] = len(alerts)
                    if alerts: status_warn(f"{len(alerts)} ntopng alert(s)")
            except Exception:
                pass
    except KeyboardInterrupt:
        raise
    except Exception as e:
        ntop["error"] = str(e)
    finally:
        session.close()
    return ntop


def _f(v, d=0.0):
    try: return float(v) if v is not None else d
    except Exception: return d


def format_netdata(m: dict) -> str:
    if not m: return "Netdata: No data"
    if "error" in m: return f"Netdata: ⚠️  {m['error']}"
    lines = ["="*62, "📊 NETDATA SYSTEM METRICS", "="*62]
    try:
        dp = m["cpu"]["data"][0]
        u, sy, iw, ir, si, idle = _f(dp[1]), _f(dp[3]), _f(dp[5]), _f(dp[6]), _f(dp[7]), _f(dp[4])
        tot = u+sy+iw+ir+si
        lines += ["", "🔹 CPU", "─"*40,
                  f"   User {u:.1f}%  Sys {sy:.1f}%  IOWait {iw:.1f}%  Idle {idle:.1f}%",
                  f"   Total Used: {tot:.1f}%" + ("  ⚠️ HIGH!" if tot > 85 else "")]
    except Exception: pass
    try:
        dp = m["ram"]["data"][0]; u, f_ = _f(dp[1]), _f(dp[2])
        pct = u/(u+f_)*100 if (u+f_) else 0
        lines += ["", "🔹 RAM", "─"*40,
                  f"   Used {u/1024:.2f} GB  Free {f_/1024:.2f} GB  ({pct:.1f}%)"
                  + ("  ⚠️ PRESSURE!" if pct > 90 else "")]
    except Exception: pass
    try:
        dp = m["network"]["data"][0]
        rx = abs(_f(dp[1]))*8/1000; tx = abs(_f(dp[2]))*8/1000
        lines += ["", "🔹 NETWORK", "─"*40,
                  f"   RX {rx:.1f} kbit/s  TX {tx:.1f} kbit/s"
                  + ("  ⚠️ HIGH!" if rx > 5000 or tx > 5000 else "")]
    except Exception: pass
    try:
        dp = m["disk"]["data"][0]
        rd = abs(_f(dp[1]))/(1024**2); wr = abs(_f(dp[2]))/(1024**2)
        lines += ["", "🔹 DISK", "─"*40,
                  f"   Reads {rd:.2f} MiB/s  Writes {wr:.2f} MiB/s"
                  + ("  ⚠️ HIGH!" if rd > 10 or wr > 10 else "")]
    except Exception: pass
    try:
        dp = m["load"]["data"][0]
        lines += ["", "🔹 LOAD", "─"*40,
                  f"   1m={_f(dp[1]):.2f}  5m={_f(dp[2]):.2f}  15m={_f(dp[3]):.2f}"]
    except Exception: pass
    lines.append("="*62)
    return "\n".join(lines)


def format_ntopng(n: dict) -> str:
    if not n: return "ntopng: No data"
    lines = ["="*62, "🌐 NTOPNG TRAFFIC", "="*62]
    if "error" in n:
        lines.append(f"⚠️  {n['error']}"); return "\n".join(lines)
    if "traffic_summary" in n:
        t = n["traffic_summary"]
        lines += [f"   In  : {t['in']:.1f} KB/s",
                  f"   Out : {t['out']:.1f} KB/s"]
        if t["in"] > 5120 or t["out"] > 5120:
            lines.append("   ⚠️  UNUSUALLY HIGH TRAFFIC!")
    if n.get("alert_count", 0) > 0:
        lines.append(f"   🚨 ACTIVE ALERTS: {n['alert_count']}")
    return "\n".join(lines)
