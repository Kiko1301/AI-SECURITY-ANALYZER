"""
Orchestration layer: service health checks on startup, and the deep
analysis cycle that ties scanning + intel + scoring + AI + alerts +
reporting together. This is the "conductor" — it shouldn't contain
any logic that belongs in a lower-level module.
"""
import socket
import time

from soc.config import (
    NETDATA_URL, NTOPNG_URL, OLLAMA_MODEL,
    TELEGRAM_ENABLED, TELEGRAM_TOKEN,
    EMAIL_ENABLED, EMAIL_TO,
    ABUSEIPDB_ENABLED, ABUSEIPDB_MIN_SCORE,
    IPINFO_ENABLED, MAC_VENDOR_ENABLED,
    RISKY_PORTS,
)
from soc.db import db
from soc.utils import ts, safe_request, get_last_request_error
from soc.network import get_arp_table, check_arp_spoofing, port_scan_host
from soc.intel import lookup_mac_vendor, lookup_ipinfo, lookup_abuseipdb
from soc.scoring import compute_threat_score
from soc.monitoring import get_netdata_metrics, get_ntopng_data
from soc.ai_analysis import analyze_with_ai
from soc.alerts import (
    telegram_new_device, telegram_arp_spoof, telegram_cycle_summary,
    send_email, build_html_report,
)
from soc.reports import save_report, purge_old_reports
from soc.ui import (
    cprint, status_ok, status_warn, status_err, status_alert, status_info,
    section_header, print_threat_table, C,
)


def check_services() -> dict:
    section_header("Service Health Check", "🔌")
    svc = {}

    for label, url, key in [
        ("Netdata", f"{NETDATA_URL}/api/v1/info", "netdata"),
        ("ntopng",  NTOPNG_URL,                    "ntopng"),
        ("Ollama",  "http://localhost:11434/api/tags", "ollama"),
    ]:
        r = safe_request("GET", url, timeout=5, debug=True)
        svc[key] = bool(r and r.status_code == 200)
        fn    = status_ok if svc[key] else status_err
        extra = ""
        if svc[key] and key == "netdata":
            extra = f"  (v{r.json().get('version','?')})"
        if svc[key] and key == "ollama":
            models = r.json().get("models", [])
            names  = [m.get("name", "?") for m in models[:5]]
            extra  = f"  models: {', '.join(names) or 'NONE LOADED'}"
            if not models:
                fn = status_warn
        fn(f"{label:<10} → {url}{extra}")
        if not svc[key] and key == "ollama":
            if get_last_request_error():
                status_err(f"           Reason: {get_last_request_error()}")
            status_warn(f"           Fix:    ollama serve")
            status_warn(f"           Then:   ollama pull {OLLAMA_MODEL}")

    if TELEGRAM_ENABLED:
        r = safe_request(
            "GET",
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getMe",
            timeout=5
        )
        svc["telegram"] = bool(r and r.status_code == 200)
        if svc["telegram"]:
            status_ok(f"Telegram   → @{r.json().get('result',{}).get('username','?')}")
        else:
            status_err("Telegram   → bot unreachable (check token)")
    else:
        status_info("Telegram   → disabled  (set TELEGRAM_ENABLED=True)")

    status_info(f"Email      → {'enabled → '+EMAIL_TO if EMAIL_ENABLED else 'disabled'}")
    status_info(f"AbuseIPDB  → {'enabled' if ABUSEIPDB_ENABLED else 'disabled (set key to enable)'}")
    status_info(f"ipinfo.io  → {'enabled' if IPINFO_ENABLED else 'disabled'}")
    status_info(f"MAC Vendor → {'enabled' if MAC_VENDOR_ENABLED else 'disabled'}")

    return svc


def run_deep_cycle(nmap_path, services: dict, live_ips: list):
    section_header(f"DEEP ANALYSIS CYCLE  ·  {ts()}", "🔬")
    t0 = time.time()

    # ── ARP spoof detection ───────────────────────────────────────
    section_header("ARP Spoof Detection", "🛡️")
    arp_table   = get_arp_table()
    arp_spoofed = check_arp_spoofing(arp_table)
    if not arp_spoofed:
        status_ok("ARP table clean — no MAC changes detected")
    for entry in arp_spoofed:
        telegram_arp_spoof(entry)

    # ── Threat intel enrichment ───────────────────────────────────
    section_header("Threat Intelligence Enrichment", "🔎")
    devices = []

    for ip in live_ips:
        existing = db.get_device(ip)
        is_new   = (existing is None) or not existing["is_known"]

        # Hostname
        hostname = None
        try:
            socket.setdefaulttimeout(2)
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(None)

        # MAC + vendor
        mac    = arp_table.get(ip)
        vendor = lookup_mac_vendor(mac) if mac else "Unknown"

        # AbuseIPDB
        abuse = lookup_abuseipdb(ip)
        if abuse >= ABUSEIPDB_MIN_SCORE:
            status_alert(f"AbuseIPDB hit: {ip} — confidence {abuse}%")
            db.log_event(ip, "ABUSE_HIT",
                         f"Confidence {abuse}%", severity="HIGH")

        # Geolocation
        geo = lookup_ipinfo(ip)

        # Port scan — only for new or high-abuse hosts
        open_ports: list = []
        if nmap_path and (is_new or abuse >= ABUSEIPDB_MIN_SCORE):
            open_ports = port_scan_host(nmap_path, ip)
            db.save_port_scan(ip, open_ports)
            for p in open_ports:
                if p.get("port") in RISKY_PORTS:
                    sname, _ = RISKY_PORTS[p["port"]]
                    db.log_event(ip, "RISKY_PORT",
                                 f"Port {p['port']} ({sname}) open",
                                 severity="WARN")

        # Threat score
        tmp = dict(existing) if existing else {}
        tmp.update({"ip": ip, "vendor": vendor,
                    "is_known": not is_new, "abuse_score": abuse})
        arp_flag = any(s["ip"] == ip for s in arp_spoofed)
        score    = compute_threat_score(tmp, open_ports, is_new, arp_flag)

        # Persist
        device = db.upsert_device(
            ip,
            mac=mac, hostname=hostname, vendor=vendor,
            country=geo["country"], city=geo["city"], isp=geo["isp"],
            abuse_score=abuse, threat_score=score,
        )

        if is_new:
            db.log_event(ip, "NEW_DEVICE",
                         f"vendor={vendor} country={geo['country'] or 'local'} "
                         f"score={score}",
                         severity="WARN" if score < 40 else "HIGH")
            telegram_new_device(device)
            cprint(
                f"  🆕  {ip:<18} vendor={vendor:<20} "
                f"score={score:3d}  country={geo['country'] or 'local'}",
                C.YELLOW
            )
        else:
            db.mark_known(ip)
            col = C.GREEN if score < 15 else C.YELLOW if score < 40 else C.RED
            cprint(
                f"  ✓   {ip:<18} vendor={vendor:<20} "
                f"score={score:3d}  abuse={abuse}%",
                col
            )

        devices.append(device)

    # ── Threat leaderboard ────────────────────────────────────────
    print_threat_table(devices)

    # ── Monitoring services ───────────────────────────────────────
    netdata = get_netdata_metrics() if services.get("netdata") else None
    ntopng  = get_ntopng_data()     if services.get("ntopng")  else None

    # ── Recent events ─────────────────────────────────────────────
    events = db.recent_events(hours=24)
    if events:
        section_header(f"Event Log  ({len(events)} events in last 24h)", "📋")
        sev_color = {"CRITICAL": C.RED, "HIGH": C.RED,
                     "WARN": C.YELLOW, "INFO": C.BLUE}
        for e in events[:10]:
            col = sev_color.get(e["severity"], C.WHITE)
            cprint(
                f"  [{e['severity']:8}] {e['timestamp']}  "
                f"{e['ip']:<18}  {e['event_type']}: {e['details']}",
                col
            )
        if len(events) > 10:
            cprint(f"  … and {len(events)-10} more (see report)", C.GRAY)

    # ── AI report ─────────────────────────────────────────────────
    section_header("AI Security Analysis", "🤖")
    ai_report = analyze_with_ai(devices, netdata, ntopng, events, arp_spoofed)

    print()
    for line in ai_report.splitlines():
        sl = line.strip()
        if any(sl.startswith(t) for t in ("[1]", "[2]", "[3]", "[4]")):
            cprint(f"  {line}", C.CYAN, bold=True)
        elif "⚠️" in line or "WARNING" in line.upper():
            cprint(f"  {line}", C.YELLOW)
        elif "🚨" in line or "CRITICAL" in line.upper() or "IMMEDIATE" in line.upper():
            cprint(f"  {line}", C.RED, bold=True)
        elif "✅" in line or "NORMAL" in line.upper():
            cprint(f"  {line}", C.GREEN)
        else:
            cprint(f"  {line}", C.WHITE)
    print()

    # ── Save report ───────────────────────────────────────────────
    report_path = save_report(
        devices, netdata, ntopng, ai_report, events, arp_spoofed
    )

    # ── Email + Telegram ──────────────────────────────────────────
    html = build_html_report(devices, ai_report, events)
    send_email(
        subject=f"[SOC] Report — {ts()[:16]}",
        body_txt=ai_report,
        body_html=html
    )
    telegram_cycle_summary(devices, events, ai_report)

    # ── Housekeeping ──────────────────────────────────────────────
    purge_old_reports()

    section_header("Deep Cycle Complete", "✅")
    status_ok(f"Report → {report_path}")
    status_ok(f"Duration → {time.time()-t0:.1f}s")
    s = db.stats()
    status_info(
        f"DB: {s['total']} devices  |  "
        f"Critical:{s['critical']}  High:{s['high']}  "
        f"Events(24h):{s['events_24h']}"
    )
