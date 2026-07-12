#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          AI SOC ANALYZER v3.0 — CYBER SENTINEL                   ║
║  Network Threat Intelligence · Real-Time Alerting · Auto-Reports ║
╚══════════════════════════════════════════════════════════════════╝

Entry point only. All logic lives in the soc/ package:
  soc/config.py       settings
  soc/ui.py           terminal output
  soc/db.py           SQLite persistence
  soc/network.py      nmap + ARP spoof detection
  soc/intel.py        MAC vendor / ipinfo / AbuseIPDB lookups
  soc/scoring.py      threat score calculation
  soc/alerts.py       Telegram + email
  soc/monitoring.py   Netdata + ntopng
  soc/ai_analysis.py  Ollama SOC report generation
  soc/reports.py      report file writing/retention
  soc/cycle.py         service checks + the deep analysis cycle
"""
import time
import traceback
from datetime import datetime

from soc.config import (
    NETWORK, HOME_GATEWAY, NMAP_PATH, QUICK_SCAN_INTERVAL, DEEP_SCAN_INTERVAL,
    REPORTS_DIR, REPORT_MAX_DAYS, DB_PATH,
    TELEGRAM_ENABLED, EMAIL_ENABLED, EMAIL_TO,
    ABUSEIPDB_ENABLED, IPINFO_ENABLED, MAC_VENDOR_ENABLED,
)
from soc.db import db
from soc.network import find_nmap, quick_scan
from soc.reports import ensure_reports_dir, purge_old_reports, list_recent_reports
from soc.cycle import check_services, run_deep_cycle
from soc.ui import banner, cprint, status_info, status_warn, section_header, C


def main():
    banner()
    ensure_reports_dir()

    # Config display
    section_header("Configuration", "⚙️")
    cfg = [
        ("Network",     NETWORK),
        ("Gateway",     HOME_GATEWAY),
        ("Quick scan",  f"every {QUICK_SCAN_INTERVAL//60} min"),
        ("Deep cycle",  f"every {DEEP_SCAN_INTERVAL//3600} h"),
        ("Reports dir", str(REPORTS_DIR.resolve())),
        ("Report TTL",  f"{REPORT_MAX_DAYS} days"),
        ("Database",    str(DB_PATH.resolve())),
        ("Telegram",    "✅ enabled"   if TELEGRAM_ENABLED  else "❌ disabled"),
        ("Email",       f"✅ → {EMAIL_TO}" if EMAIL_ENABLED else "❌ disabled"),
        ("AbuseIPDB",   "✅ enabled"   if ABUSEIPDB_ENABLED else "❌ disabled"),
        ("ipinfo.io",   "✅ enabled"   if IPINFO_ENABLED    else "✅ enabled (free)"),
        ("MAC Vendor",  "✅ enabled"   if MAC_VENDOR_ENABLED else "❌ disabled"),
    ]
    for label, val in cfg:
        cprint(f"  {label:<14}: {val}", C.WHITE)

    section_header("Report Housekeeping", "🗂️")
    purge_old_reports()
    list_recent_reports()

    section_header("Nmap", "🗺️")
    nmap_path = find_nmap(NMAP_PATH)

    services = check_services()

    section_header("Database Status", "🗃️")
    s = db.stats()
    status_info(
        f"Total:{s['total']}  Known:{s['known']}  "
        f"Critical:{s['critical']}  High:{s['high']}  "
        f"Events(24h):{s['events_24h']}"
    )

    # Initial sweep
    live_ips: list = []
    if nmap_path:
        section_header("Initial Network Discovery", "📡")
        live_ips = quick_scan(nmap_path)
        for ip in live_ips:
            cprint(f"  ⬤  {ip}", C.GREEN)

    cprint(
        f"\n  {'─'*62}\n"
        f"  🚀  MONITORING LOOP STARTED\n"
        f"      Quick sweep   : every {QUICK_SCAN_INTERVAL//60} min\n"
        f"      Deep analysis : every {DEEP_SCAN_INTERVAL//3600} h\n"
        f"  {'─'*62}\n",
        C.CYAN, bold=True
    )

    last_deep  = 0.0
    last_quick = 0.0

    while True:
        try:
            now = time.time()

            # Quick sweep
            if now - last_quick >= QUICK_SCAN_INTERVAL:
                if nmap_path:
                    live_ips = quick_scan(nmap_path)
                last_quick = now

            # Deep cycle
            if now - last_deep >= DEEP_SCAN_INTERVAL:
                if not live_ips and nmap_path:
                    live_ips = quick_scan(nmap_path)
                if live_ips:
                    run_deep_cycle(nmap_path, services, live_ips)
                else:
                    status_warn("No hosts found — skipping deep cycle")
                last_deep = now

            # Sleep until next event
            nq = last_quick + QUICK_SCAN_INTERVAL
            nd = last_deep  + DEEP_SCAN_INTERVAL
            sleep_s = max(30, min(nq, nd) - time.time())
            cprint(
                f"\n  ⏰  Next quick: "
                f"{datetime.fromtimestamp(nq).strftime('%H:%M:%S')}  |  "
                f"Next deep: "
                f"{datetime.fromtimestamp(nd).strftime('%H:%M:%S')}",
                C.GRAY
            )
            cprint(f"  😴  Sleeping {sleep_s/60:.1f} min …\n", C.GRAY)
            time.sleep(sleep_s)

        except KeyboardInterrupt:
            print()
            cprint("\n  👋  Stopped by user. Closing database …\n", C.YELLOW)
            db.close()
            cprint("  Stay safe out there. 🛡️\n", C.CYAN)
            break

        except Exception as e:
            cprint(f"  ❌  Main loop error: {e}", C.RED)
            traceback.print_exc()
            status_warn("Retrying in 5 min …")
            time.sleep(300)


if __name__ == "__main__":
    main()
