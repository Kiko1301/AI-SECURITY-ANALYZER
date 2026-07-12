"""
Plain-text report generation and lifecycle: file paths, writing the
full report, purging old ones past the retention window, listing
recent ones on startup.
"""
import shutil
from datetime import datetime, timedelta

from soc.config import REPORTS_DIR, REPORT_MAX_DAYS, NETWORK, HOME_GATEWAY
from soc.monitoring import format_netdata, format_ntopng
from soc.ui import cprint, status_warn, status_info, C


def ensure_reports_dir():
    REPORTS_DIR.mkdir(exist_ok=True)


def report_filepath():
    now     = datetime.now()
    day_dir = REPORTS_DIR / now.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    return day_dir / now.strftime("SOC_Report_%Y-%m-%d_%H-%M-%S.txt")


def purge_old_reports():
    if not REPORTS_DIR.exists():
        return
    cutoff = datetime.now() - timedelta(days=REPORT_MAX_DAYS)
    pf = pd = 0
    for d in sorted(REPORTS_DIR.iterdir()):
        if not d.is_dir():
            continue
        try:
            if datetime.strptime(d.name, "%Y-%m-%d") < cutoff:
                pf += len(list(d.glob("*.txt")))
                shutil.rmtree(d); pd += 1
        except ValueError:
            pass
    if pd:
        status_warn(f"Purged {pf} report(s) across {pd} folder(s) older than {REPORT_MAX_DAYS}d")
    else:
        status_info(f"No reports older than {REPORT_MAX_DAYS}d to purge")


def list_recent_reports(n: int = 5):
    reports = sorted(REPORTS_DIR.rglob("SOC_Report_*.txt"), reverse=True)
    if not reports:
        status_info("No previous reports found.")
        return
    cprint(f"\n  📂  Last {min(n,len(reports))} reports:", C.GRAY)
    for r in reports[:n]:
        cprint(f"     {r.relative_to(REPORTS_DIR)}  ({r.stat().st_size/1024:.1f} KB)", C.GRAY)


def save_report(devices: list, netdata, ntopng, ai_report: str,
                events: list, arp_spoofed: list):
    path = report_filepath()
    now  = datetime.now()
    sep  = "═"*66

    dev_lines = "\n".join(
        f"  {str(d.get('ip','?')):<18}"
        f" {str(d.get('hostname') or 'Unknown'):<22}"
        f" {str(d.get('vendor')   or 'Unknown'):<20}"
        f" {str(d.get('country')  or 'Local'):<10}"
        f" Score:{d.get('threat_score',0):3d}"
        f"  Abuse:{d.get('abuse_score',0)}%"
        for d in sorted(devices,
                        key=lambda x: x.get("threat_score", 0), reverse=True)
        if isinstance(d, dict)
    ) or "  (none detected)"

    spoof_lines = "\n".join(
        f"  🚨 {s['ip']}  {s['old_mac']} → {s['new_mac']}"
        for s in arp_spoofed
    ) or "  None detected"

    ev_lines = "\n".join(
        f"  [{e['severity']:8}] {e['timestamp']}  {e['ip']:<18}"
        f"  {e['event_type']:<20}  {e['details']}"
        for e in events[:30]
    ) or "  No events"

    content = (
        f"{sep}\n"
        f"  AI SOC ANALYZER v3.0 — COMPREHENSIVE SECURITY REPORT\n"
        f"  Generated : {now.strftime('%A, %B %d %Y  at  %H:%M:%S')}\n"
        f"  Network   : {NETWORK}    Gateway : {HOME_GATEWAY}\n"
        f"{sep}\n\n"
        f"{'━'*66}\n"
        f"  DEVICE THREAT TABLE  ({len(devices)} online)\n"
        f"{'━'*66}\n"
        f"  {'IP':<18} {'HOSTNAME':<22} {'VENDOR':<20} {'COUNTRY':<10} SCORE  ABUSE\n"
        f"  {'─'*64}\n"
        f"{dev_lines}\n\n"
        f"{'━'*66}\n  ARP SPOOF DETECTION\n{'━'*66}\n"
        f"{spoof_lines}\n\n"
        f"{'━'*66}\n  EVENT LOG (last 24h)\n{'━'*66}\n"
        f"{ev_lines}\n\n"
        f"{'━'*66}\n  SYSTEM METRICS\n{'━'*66}\n"
        f"{format_netdata(netdata)}\n\n"
        f"{'━'*66}\n  NETWORK TRAFFIC\n{'━'*66}\n"
        f"{format_ntopng(ntopng)}\n\n"
        f"{'━'*66}\n  AI SECURITY ANALYSIS\n{'━'*66}\n"
        f"{ai_report}\n\n"
        f"{sep}\n"
        f"  END OF REPORT  ·  {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{sep}\n"
    )
    path.write_text(content, encoding="utf-8")
    return path
