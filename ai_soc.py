#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          AI SOC ANALYZER v3.0 — CYBER SENTINEL                   ║
║  Network Threat Intelligence · Real-Time Alerting · Auto-Reports ║
╚══════════════════════════════════════════════════════════════════╝

NEW IN v3.0:
  • SQLite database  — full device + event + port + ARP history
  • Threat scoring   — 0-100 risk score per device, every cycle
  • MAC vendor lookup — identify device makers instantly (free API)
  • AbuseIPDB        — cross-reference IPs against global threat DB
  • ipinfo.io        — geolocation + ISP for every discovered host
  • ARP spoof detect — alert if a MAC changes for a known IP (MITM)
  • Targeted port scan — nmap top-20 on new / high-threat hosts only
  • Telegram alerts  — instant phone notification for any threat
  • Email reports    — full HTML report delivered to your inbox
  • Dual schedule    — hourly quick sweep + 24 h deep analysis
  • Threat leaderboard — color-coded risk table printed each cycle
"""

# ══════════════════════════════════════════════════════════════════
#  STDLIB
# ══════════════════════════════════════════════════════════════════
import os, re, time, shutil, socket, smtplib, sqlite3
import subprocess, threading, traceback
from datetime      import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from pathlib       import Path

# ══════════════════════════════════════════════════════════════════
#  THIRD-PARTY  (pip install requests)
# ══════════════════════════════════════════════════════════════════
import requests

# ══════════════════════════════════════════════════════════════════
#  SETTINGS  — edit everything in this block
# ══════════════════════════════════════════════════════════════════

# ── Core network ──────────────────────────────────────────────────
HOME_GATEWAY = "192.168.31.1"
NETWORK      = "192.168.31.0/24"
NMAP_PATH    = r"F:\Program Files (x86)\Nmap\nmap.exe"

# ── Scan schedule ─────────────────────────────────────────────────
QUICK_SCAN_INTERVAL = 3600    # seconds — ping sweep frequency
DEEP_SCAN_INTERVAL  = 86400   # seconds — full analysis + AI report

# ── Persistence ───────────────────────────────────────────────────
REPORTS_DIR     = Path("reports")
REPORT_MAX_DAYS = 30
DB_PATH         = Path("soc_database.db")

# ── Local services ────────────────────────────────────────────────
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mistral"
NETDATA_URL  = "http://172.20.244.98:19999"
NTOPNG_URL   = "http://localhost:3001"
NTOPNG_USER  = "admin"
NTOPNG_PASS  = "admin"

# ── Telegram  (https://t.me/BotFather → create bot) ──────────────
TELEGRAM_ENABLED = False
TELEGRAM_TOKEN   = "YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

# ── Email  (Gmail: create an App Password in Google Account) ──────
EMAIL_ENABLED    = False
EMAIL_FROM       = "soc@yourdomain.com"
EMAIL_TO         = "you@yourdomain.com"
EMAIL_SMTP_HOST  = "smtp.gmail.com"
EMAIL_SMTP_PORT  = 587
EMAIL_PASSWORD   = "your_app_password"

# ── AbuseIPDB  (https://www.abuseipdb.com — free 1 000 checks/day) ─
ABUSEIPDB_ENABLED   = False
ABUSEIPDB_KEY       = "YOUR_ABUSEIPDB_KEY"
ABUSEIPDB_MIN_SCORE = 20          # flag IPs with confidence % above this

# ── ipinfo.io  (free 50 k req/month, no key needed) ──────────────
IPINFO_ENABLED = True

# ── MAC Vendor  (free, no key, rate-limited gently) ──────────────
MAC_VENDOR_ENABLED = True

# ── Risky ports: {port: (name, score_addition)} ──────────────────
RISKY_PORTS = {
    21:   ("FTP",       20),
    23:   ("Telnet",    35),
    25:   ("SMTP",      15),
    135:  ("MS-RPC",    20),
    139:  ("NetBIOS",   20),
    445:  ("SMB",       25),
    1433: ("MSSQL",     20),
    3306: ("MySQL",     20),
    3389: ("RDP",       30),
    5900: ("VNC",       25),
    8080: ("HTTP-Alt",  10),
}

# ══════════════════════════════════════════════════════════════════
#  TERMINAL UI
# ══════════════════════════════════════════════════════════════════

class C:
    RESET = "\033[0m";   BOLD  = "\033[1m"
    RED   = "\033[91m";  GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE  = "\033[94m";  MAG   = "\033[95m"; CYAN   = "\033[96m"
    WHITE = "\033[97m";  GRAY  = "\033[90m"

def cprint(text, color=C.WHITE, bold=False):
    print(f"{''+C.BOLD if bold else ''}{color}{text}{C.RESET}")

def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def banner():
    print(f"""
{C.CYAN}{C.BOLD}  ╔══════════════════════════════════════════════════════════════╗
  ║   ██████╗██╗   ██╗██████╗ ███████╗██████╗     ███████╗ ██████╗  ██████╗  ║
  ║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔═══██╗██╔════╝  ║
  ║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ███████╗██║   ██║██║       ║
  ║  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ╚════██║██║   ██║██║       ║
  ║  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ███████║╚██████╔╝╚██████╔╝ ║
  ║   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝  ║
  ║                                                                            ║
  ║   {C.YELLOW}AI SOC ANALYZER v3.0  ·  CYBER SENTINEL{C.CYAN}                            ║
  ║   {C.GRAY}SQLite · Threat Intel · ARP Detection · Telegram · Email{C.CYAN}            ║
  ╚══════════════════════════════════════════════════════════════════════════╝{C.RESET}
""")

def section_header(title: str, icon: str = "▸"):
    w = 66
    print(f"\n{C.CYAN}{'─'*w}{C.RESET}")
    cprint(f"  {icon}  {title}", C.CYAN, bold=True)
    print(f"{C.CYAN}{'─'*w}{C.RESET}")

def status_ok(msg):    cprint(f"  ✅  {msg}", C.GREEN)
def status_warn(msg):  cprint(f"  ⚠️   {msg}", C.YELLOW)
def status_err(msg):   cprint(f"  ❌  {msg}", C.RED)
def status_info(msg):  cprint(f"  ℹ️   {msg}", C.BLUE)
def status_alert(msg): cprint(f"  🚨  {msg}", C.RED, bold=True)

def threat_badge(score: int) -> str:
    if score >= 70: return f"{C.RED}{C.BOLD}[CRITICAL {score:3d}]{C.RESET}"
    if score >= 40: return f"{C.YELLOW}{C.BOLD}[HIGH     {score:3d}]{C.RESET}"
    if score >= 15: return f"{C.BLUE}[MEDIUM   {score:3d}]{C.RESET}"
    return             f"{C.GREEN}[LOW      {score:3d}]{C.RESET}"

def threat_color(score: int) -> str:
    if score >= 70: return C.RED
    if score >= 40: return C.YELLOW
    if score >= 15: return C.BLUE
    return C.GREEN

# ══════════════════════════════════════════════════════════════════
#  SAFE HTTP
# ══════════════════════════════════════════════════════════════════

_last_request_error: str = ""   # stores the real exception for diagnostics

def safe_request(method: str, url: str, **kwargs):
    """
    Returns None on any failure. Always re-raises KeyboardInterrupt.
    Stores the real exception in _last_request_error so callers can log it.
    Pass debug=True to print the error immediately.
    """
    global _last_request_error
    debug = kwargs.pop("debug", False)
    try:
        return requests.request(method, url, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        _last_request_error = f"{type(exc).__name__}: {exc}"
        if debug:
            status_warn(f"HTTP {method} {url} failed  →  {_last_request_error}")
        return None

# ══════════════════════════════════════════════════════════════════
#  SQLITE DATABASE
# ══════════════════════════════════════════════════════════════════

class SocDB:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            ip           TEXT PRIMARY KEY,
            mac          TEXT,
            hostname     TEXT,
            vendor       TEXT,
            country      TEXT,
            city         TEXT,
            isp          TEXT,
            device_type  TEXT DEFAULT 'Unknown',
            first_seen   TEXT,
            last_seen    TEXT,
            threat_score INTEGER DEFAULT 0,
            abuse_score  INTEGER DEFAULT 0,
            is_known     INTEGER DEFAULT 0,
            notes        TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            ip         TEXT,
            event_type TEXT,
            severity   TEXT,
            details    TEXT
        );
        CREATE TABLE IF NOT EXISTS port_scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT,
            port      INTEGER,
            protocol  TEXT,
            service   TEXT,
            version   TEXT,
            scan_time TEXT
        );
        CREATE TABLE IF NOT EXISTS arp_cache (
            ip      TEXT PRIMARY KEY,
            mac     TEXT,
            updated TEXT
        );
        """)
        self.conn.commit()

    # ── Device ────────────────────────────────────────────────────
    def upsert_device(self, ip: str, **fields) -> dict:
        now = ts()
        existing = self.get_device(ip)
        if existing:
            fields["last_seen"] = now
            sets = ", ".join(f"{k}=?" for k in fields)
            self.conn.execute(
                f"UPDATE devices SET {sets} WHERE ip=?",
                list(fields.values()) + [ip]
            )
        else:
            fields.setdefault("first_seen", now)
            fields["last_seen"] = now
            fields["ip"]        = ip
            cols = ", ".join(fields.keys())
            ph   = ", ".join("?" * len(fields))
            self.conn.execute(
                f"INSERT INTO devices ({cols}) VALUES ({ph})",
                list(fields.values())
            )
        self.conn.commit()
        return dict(self.get_device(ip))

    def get_device(self, ip: str):
        return self.conn.execute(
            "SELECT * FROM devices WHERE ip=?", (ip,)
        ).fetchone()

    def all_devices(self) -> list:
        return [
            dict(r) for r in self.conn.execute(
                "SELECT * FROM devices ORDER BY threat_score DESC"
            ).fetchall()
        ]

    def mark_known(self, ip: str):
        self.conn.execute(
            "UPDATE devices SET is_known=1 WHERE ip=?", (ip,)
        )
        self.conn.commit()

    # ── Events ────────────────────────────────────────────────────
    def log_event(self, ip: str, event_type: str,
                  details: str, severity: str = "INFO"):
        self.conn.execute(
            "INSERT INTO events (timestamp,ip,event_type,severity,details) "
            "VALUES (?,?,?,?,?)",
            (ts(), ip, event_type, severity, details)
        )
        self.conn.commit()

    def recent_events(self, hours: int = 24) -> list:
        cutoff = (datetime.now() - timedelta(hours=hours)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return [
            dict(r) for r in self.conn.execute(
                "SELECT * FROM events WHERE timestamp>? "
                "ORDER BY timestamp DESC",
                (cutoff,)
            ).fetchall()
        ]

    # ── Port scans ────────────────────────────────────────────────
    def save_port_scan(self, ip: str, ports: list):
        self.conn.execute("DELETE FROM port_scans WHERE ip=?", (ip,))
        now = ts()
        for p in ports:
            self.conn.execute(
                "INSERT INTO port_scans "
                "(ip,port,protocol,service,version,scan_time) "
                "VALUES (?,?,?,?,?,?)",
                (ip, p.get("port"), p.get("protocol","tcp"),
                 p.get("service",""), p.get("version",""), now)
            )
        self.conn.commit()

    def get_open_ports(self, ip: str) -> list:
        return [
            dict(r) for r in self.conn.execute(
                "SELECT * FROM port_scans WHERE ip=? ORDER BY port",
                (ip,)
            ).fetchall()
        ]

    # ── ARP cache ─────────────────────────────────────────────────
    def get_arp(self, ip: str):
        row = self.conn.execute(
            "SELECT mac FROM arp_cache WHERE ip=?", (ip,)
        ).fetchone()
        return row["mac"] if row else None

    def set_arp(self, ip: str, mac: str):
        self.conn.execute(
            "INSERT INTO arp_cache (ip,mac,updated) VALUES (?,?,?) "
            "ON CONFLICT(ip) DO UPDATE "
            "SET mac=excluded.mac, updated=excluded.updated",
            (ip, mac, ts())
        )
        self.conn.commit()

    # ── Stats ─────────────────────────────────────────────────────
    def stats(self) -> dict:
        c = self.conn
        cutoff = (datetime.now()-timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "total":      c.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "known":      c.execute("SELECT COUNT(*) FROM devices WHERE is_known=1").fetchone()[0],
            "critical":   c.execute("SELECT COUNT(*) FROM devices WHERE threat_score>=70").fetchone()[0],
            "high":       c.execute("SELECT COUNT(*) FROM devices WHERE threat_score>=40 AND threat_score<70").fetchone()[0],
            "events_24h": c.execute("SELECT COUNT(*) FROM events WHERE timestamp>?", (cutoff,)).fetchone()[0],
        }

    def close(self):
        self.conn.close()


db = SocDB()

# ══════════════════════════════════════════════════════════════════
#  REPORT MANAGEMENT
# ══════════════════════════════════════════════════════════════════

def ensure_reports_dir():
    REPORTS_DIR.mkdir(exist_ok=True)

def report_filepath() -> Path:
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

# ══════════════════════════════════════════════════════════════════
#  NMAP
# ══════════════════════════════════════════════════════════════════

def find_nmap():
    if os.path.exists(NMAP_PATH):
        try:
            r = subprocess.run([NMAP_PATH,"--version"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                status_ok(f"Nmap found → {NMAP_PATH}")
                return NMAP_PATH
        except Exception:
            pass
    status_err(f"Nmap not found at {NMAP_PATH}")
    return None

def _extract_ips(output: str) -> list:
    ips = []
    for line in output.splitlines():
        if "Nmap scan report for" not in line:
            continue
        ip = (line.split("(")[-1].replace(")","").strip()
              if "(" in line else line.split("for ")[-1].strip())
        if ip.count('.') == 3 and ip != "0.0.0.0":
            ips.append(ip)
    return list(set(ips))

def quick_scan(nmap_path: str) -> list:
    cprint(f"\n  🔍  Quick ping sweep → {NETWORK} …", C.CYAN)
    try:
        r = subprocess.run(
            f'"{nmap_path}" -sn -T5 -n {NETWORK}',
            shell=True, capture_output=True, text=True, timeout=45
        )
        ips = _extract_ips(r.stdout) if r.returncode == 0 else []
        status_ok(f"Quick sweep: {len(ips)} host(s) up")
        return ips
    except subprocess.TimeoutExpired:
        status_warn("Quick sweep timed out"); return []
    except Exception as e:
        status_warn(f"Quick sweep error: {e}"); return []

def port_scan_host(nmap_path: str, ip: str) -> list:
    """Top-20 port scan on a single host. Returns list of port dicts."""
    cprint(f"  🔭  Port scanning {ip} …", C.MAG)
    try:
        r = subprocess.run(
            f'"{nmap_path}" -sV --top-ports 20 -T4 --host-timeout 30s -n {ip}',
            shell=True, capture_output=True, text=True, timeout=60
        )
        if r.returncode != 0:
            return []
        ports = []
        for line in r.stdout.splitlines():
            m = re.match(r'\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                ports.append({
                    "port":     int(m.group(1)),
                    "protocol": m.group(2),
                    "service":  m.group(3),
                    "version":  m.group(4).strip(),
                })
        if ports:
            cprint(f"  🔓  {ip}: open ports → " +
                   ", ".join(str(p["port"]) for p in ports), C.YELLOW)
        else:
            status_ok(f"{ip}: no risky ports in top-20")
        return ports
    except subprocess.TimeoutExpired:
        status_warn(f"Port scan of {ip} timed out"); return []
    except Exception as e:
        status_warn(f"Port scan error ({ip}): {e}"); return []

# ══════════════════════════════════════════════════════════════════
#  ARP SPOOF DETECTION
# ══════════════════════════════════════════════════════════════════

def get_arp_table() -> dict:
    arp = {}
    try:
        out = subprocess.check_output("arp -a", shell=True, timeout=10).decode()
        for line in out.splitlines():
            m = re.search(
                r'(\d+\.\d+\.\d+\.\d+)\s+'
                r'([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}'
                r'[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}'
                r'[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})',
                line
            )
            if m:
                arp[m.group(1)] = m.group(2).lower().replace("-",":")
    except Exception:
        pass
    return arp

def check_arp_spoofing(arp_table: dict) -> list:
    spoofed = []
    for ip, mac in arp_table.items():
        old = db.get_arp(ip)
        if old and old != mac:
            spoofed.append({"ip": ip, "old_mac": old, "new_mac": mac})
            db.log_event(ip, "ARP_SPOOF",
                         f"MAC changed {old} → {mac}", severity="CRITICAL")
            status_alert(f"ARP SPOOF! {ip}  was {old}  now {mac}")
        db.set_arp(ip, mac)
    return spoofed

# ══════════════════════════════════════════════════════════════════
#  THREAT INTELLIGENCE
# ══════════════════════════════════════════════════════════════════

_vendor_cache: dict = {}

def lookup_mac_vendor(mac: str) -> str:
    if not MAC_VENDOR_ENABLED or not mac:
        return "Unknown"
    prefix = ":".join(mac.upper().replace("-",":").split(":")[:3])
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]
    r = safe_request("GET", f"https://api.macvendors.com/{prefix}", timeout=5)
    v = r.text.strip() if (r and r.status_code == 200) else "Unknown"
    _vendor_cache[prefix] = v
    time.sleep(0.3)
    return v

_ipinfo_cache: dict = {}

def lookup_ipinfo(ip: str) -> dict:
    empty = {"country":"","city":"","isp":""}
    if not IPINFO_ENABLED:
        return empty
    if re.match(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)', ip):
        return empty
    if ip in _ipinfo_cache:
        return _ipinfo_cache[ip]
    r = safe_request("GET", f"https://ipinfo.io/{ip}/json", timeout=5)
    if r and r.status_code == 200:
        d   = r.json()
        res = {"country": d.get("country",""),
               "city":    d.get("city",""),
               "isp":     d.get("org","")}
    else:
        res = empty
    _ipinfo_cache[ip] = res
    return res

_abuse_cache: dict = {}

def lookup_abuseipdb(ip: str) -> int:
    if not ABUSEIPDB_ENABLED or not ABUSEIPDB_KEY:
        return 0
    if ip in _abuse_cache:
        return _abuse_cache[ip]
    r = safe_request(
        "GET", "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept":"application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=8
    )
    score = r.json().get("data",{}).get("abuseConfidenceScore",0) \
            if (r and r.status_code == 200) else 0
    _abuse_cache[ip] = score
    return score

# ══════════════════════════════════════════════════════════════════
#  THREAT SCORING  (0-100)
# ══════════════════════════════════════════════════════════════════

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

# ══════════════════════════════════════════════════════════════════
#  ALERTS
# ══════════════════════════════════════════════════════════════════

def _telegram_send(text: str):
    if not TELEGRAM_ENABLED:
        return
    def _go():
        safe_request(
            "POST",
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID,
                  "text": text, "parse_mode": "HTML"},
            timeout=10
        )
    threading.Thread(target=_go, daemon=True).start()

def telegram_new_device(device: dict):
    score = device.get("threat_score", 0)
    emoji = "🚨" if score >= 40 else "⚠️"
    _telegram_send(
        f"{emoji} <b>NEW DEVICE</b>\n"
        f"IP: <code>{device.get('ip','?')}</code>\n"
        f"Host: {device.get('hostname') or 'Unknown'}\n"
        f"Vendor: {device.get('vendor') or 'Unknown'}\n"
        f"Country: {device.get('country') or 'Local'}\n"
        f"Threat Score: <b>{score}/100</b>\n"
        f"Time: {ts()}"
    )

def telegram_arp_spoof(entry: dict):
    _telegram_send(
        f"🚨🚨 <b>ARP SPOOFING DETECTED</b> 🚨🚨\n"
        f"IP: <code>{entry['ip']}</code>\n"
        f"Old MAC: <code>{entry['old_mac']}</code>\n"
        f"New MAC: <code>{entry['new_mac']}</code>\n"
        f"Possible MITM attack! Investigate immediately.\n"
        f"Time: {ts()}"
    )

def telegram_cycle_summary(devices: list, events: list, ai_snippet: str):
    high = sum(1 for d in devices if d.get("threat_score",0) >= 40)
    _telegram_send(
        f"📊 <b>SOC Cycle Complete</b> — {ts()}\n"
        f"Devices online: {len(devices)}\n"
        f"High-risk: {high}\n"
        f"Events (24h): {len(events)}\n\n"
        f"<b>AI Summary:</b>\n{ai_snippet[:500]}"
    )

def build_html_report(devices: list, ai_report: str, events: list) -> str:
    rows = ""
    for d in sorted(devices, key=lambda x: x.get("threat_score",0), reverse=True):
        s = d.get("threat_score",0)
        c = "#ff4444" if s>=70 else "#ffaa00" if s>=40 \
            else "#4488ff" if s>=15 else "#44bb44"
        rows += (
            f"<tr><td>{d.get('ip','?')}</td>"
            f"<td>{d.get('hostname') or '—'}</td>"
            f"<td>{d.get('vendor')   or '—'}</td>"
            f"<td>{d.get('country')  or 'Local'}</td>"
            f"<td style='color:{c};font-weight:bold'>{s}</td></tr>\n"
        )
    ev_rows = "".join(
        f"<tr><td>{e['timestamp']}</td><td>{e['ip']}</td>"
        f"<td>{e['event_type']}</td><td>{e['details']}</td></tr>\n"
        for e in events[:20]
    )
    return (
        "<html><body style='font-family:monospace;background:#111;color:#eee'>"
        f"<h2 style='color:#0ff'>🛡️ AI SOC Report — {ts()}</h2>"
        "<h3 style='color:#aff'>Device Threat Table</h3>"
        "<table border='1' cellpadding='6' style='border-collapse:collapse'>"
        "<tr style='background:#333'><th>IP</th><th>Hostname</th>"
        f"<th>Vendor</th><th>Country</th><th>Score</th></tr>{rows}</table>"
        "<h3 style='color:#aff'>AI Analysis</h3>"
        f"<pre style='background:#222;padding:12px;border-radius:6px'>{ai_report}</pre>"
        "<h3 style='color:#aff'>Recent Events</h3>"
        "<table border='1' cellpadding='6' style='border-collapse:collapse'>"
        "<tr style='background:#333'><th>Time</th><th>IP</th>"
        f"<th>Type</th><th>Details</th></tr>{ev_rows}</table>"
        "</body></html>"
    )

def send_email(subject: str, body_txt: str, body_html: str = ""):
    if not EMAIL_ENABLED:
        return
    def _go():
        try:
            msg             = MIMEMultipart("alternative")
            msg["Subject"]  = subject
            msg["From"]     = EMAIL_FROM
            msg["To"]       = EMAIL_TO
            msg.attach(MIMEText(body_txt,  "plain"))
            if body_html:
                msg.attach(MIMEText(body_html, "html"))
            with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as s:
                s.starttls()
                s.login(EMAIL_FROM, EMAIL_PASSWORD)
                s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
            status_ok(f"Email report sent to {EMAIL_TO}")
        except Exception as e:
            status_warn(f"Email failed: {e}")
    threading.Thread(target=_go, daemon=True).start()

# ══════════════════════════════════════════════════════════════════
#  NETDATA + NTOPNG
# ══════════════════════════════════════════════════════════════════

def get_netdata_metrics() -> dict:
    cprint(f"\n  📊  Fetching Netdata metrics …", C.CYAN)
    r = safe_request("GET", f"{NETDATA_URL}/api/v1/info", timeout=5)
    if not r or r.status_code != 200:
        status_err(f"Netdata unreachable → {NETDATA_URL}")
        return {"error": "Unreachable"}
    status_ok(f"Netdata v{r.json().get('version','?')}")
    metrics = {}
    for key, chart in {
        "cpu":"system.cpu","ram":"system.ram",
        "network":"system.net","disk":"system.io","load":"system.load"
    }.items():
        cr = safe_request(
            "GET", f"{NETDATA_URL}/api/v1/data",
            params={"chart":chart,"after":-60,"before":0,"points":1,"format":"json"},
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
            data={"user":NTOPNG_USER,"password":NTOPNG_PASS}, timeout=10
        )
        if not login or login.status_code != 200:
            ntop["error"] = "Login failed"; return ntop
        status_ok("ntopng login OK")
        r = session.get(f"{NTOPNG_URL}/lua/traffic_stats.lua", timeout=10)
        if r and r.status_code == 200:
            try:
                d = r.json(); tput = d.get("throughput",{})
                i_kb = float(tput.get("in",0))/1024
                o_kb = float(tput.get("out",0))/1024
                ntop["traffic_summary"] = {"in":i_kb,"out":o_kb}
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

# ══════════════════════════════════════════════════════════════════
#  FORMATTERS
# ══════════════════════════════════════════════════════════════════

def _f(v, d=0.0):
    try: return float(v) if v is not None else d
    except: return d

def format_netdata(m: dict) -> str:
    if not m: return "Netdata: No data"
    if "error" in m: return f"Netdata: ⚠️  {m['error']}"
    lines = ["="*62,"📊 NETDATA SYSTEM METRICS","="*62]
    try:
        dp = m["cpu"]["data"][0]
        u,sy,iw,ir,si,idle = _f(dp[1]),_f(dp[3]),_f(dp[5]),_f(dp[6]),_f(dp[7]),_f(dp[4])
        tot = u+sy+iw+ir+si
        lines += ["","🔹 CPU","─"*40,
                  f"   User {u:.1f}%  Sys {sy:.1f}%  IOWait {iw:.1f}%  Idle {idle:.1f}%",
                  f"   Total Used: {tot:.1f}%" + ("  ⚠️ HIGH!" if tot>85 else "")]
    except Exception: pass
    try:
        dp = m["ram"]["data"][0]; u,f_ = _f(dp[1]),_f(dp[2])
        pct = u/(u+f_)*100 if (u+f_) else 0
        lines += ["","🔹 RAM","─"*40,
                  f"   Used {u/1024:.2f} GB  Free {f_/1024:.2f} GB  ({pct:.1f}%)"
                  + ("  ⚠️ PRESSURE!" if pct>90 else "")]
    except Exception: pass
    try:
        dp = m["network"]["data"][0]
        rx = abs(_f(dp[1]))*8/1000; tx = abs(_f(dp[2]))*8/1000
        lines += ["","🔹 NETWORK","─"*40,
                  f"   RX {rx:.1f} kbit/s  TX {tx:.1f} kbit/s"
                  + ("  ⚠️ HIGH!" if rx>5000 or tx>5000 else "")]
    except Exception: pass
    try:
        dp = m["disk"]["data"][0]
        rd = abs(_f(dp[1]))/(1024**2); wr = abs(_f(dp[2]))/(1024**2)
        lines += ["","🔹 DISK","─"*40,
                  f"   Reads {rd:.2f} MiB/s  Writes {wr:.2f} MiB/s"
                  + ("  ⚠️ HIGH!" if rd>10 or wr>10 else "")]
    except Exception: pass
    try:
        dp = m["load"]["data"][0]
        lines += ["","🔹 LOAD","─"*40,
                  f"   1m={_f(dp[1]):.2f}  5m={_f(dp[2]):.2f}  15m={_f(dp[3]):.2f}"]
    except Exception: pass
    lines.append("="*62)
    return "\n".join(lines)

def format_ntopng(n: dict) -> str:
    if not n: return "ntopng: No data"
    lines = ["="*62,"🌐 NTOPNG TRAFFIC","="*62]
    if "error" in n:
        lines.append(f"⚠️  {n['error']}"); return "\n".join(lines)
    if "traffic_summary" in n:
        t = n["traffic_summary"]
        lines += [f"   In  : {t['in']:.1f} KB/s",
                  f"   Out : {t['out']:.1f} KB/s"]
        if t["in"]>5120 or t["out"]>5120:
            lines.append("   ⚠️  UNUSUALLY HIGH TRAFFIC!")
    if n.get("alert_count",0) > 0:
        lines.append(f"   🚨 ACTIVE ALERTS: {n['alert_count']}")
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════
#  THREAT LEADERBOARD  (terminal)
# ══════════════════════════════════════════════════════════════════

def print_threat_table(devices: list):
    section_header("DEVICE THREAT LEADERBOARD", "🎯")
    hdr = (f"  {'IP':<18} {'HOSTNAME':<22} {'VENDOR':<20} "
           f"{'COUNTRY':<9} {'SCORE':<16} ABUSE")
    cprint(hdr, C.GRAY)
    cprint("  " + "─"*84, C.GRAY)
    for d in sorted(devices, key=lambda x: x.get("threat_score",0), reverse=True):
        score   = d.get("threat_score", 0)
        abuse   = d.get("abuse_score",  0)
        ip      = str(d.get("ip","?"))
        host    = str(d.get("hostname") or "—")[:21]
        vendor  = str(d.get("vendor")   or "—")[:19]
        country = str(d.get("country")  or "—")[:8]
        badge   = threat_badge(score)
        col     = threat_color(score)
        abuse_s = (f"{C.RED}{abuse}%{C.RESET}" if abuse > 0
                   else f"{C.GRAY}0%{C.RESET}")
        print(f"  {col}{ip:<18}{C.RESET} {host:<22} {vendor:<20} "
              f"{country:<9} {badge} {abuse_s}")
    cprint("  " + "─"*84, C.GRAY)

# ══════════════════════════════════════════════════════════════════
#  AI ANALYSIS
# ══════════════════════════════════════════════════════════════════

def analyze_with_ai(devices: list, netdata, ntopng,
                     events: list, arp_spoofed: list) -> str:

    dev_block = ""
    for d in devices:
        ports = db.get_open_ports(str(d.get("ip","?")))
        port_s = ", ".join(str(p["port"]) for p in ports) or "none"
        dev_block += (
            f"  {str(d.get('ip','?')):<18}"
            f" host={str(d.get('hostname') or 'Unknown'):<20}"
            f" vendor={str(d.get('vendor') or 'Unknown'):<18}"
            f" country={str(d.get('country') or 'local'):<8}"
            f" threat={d.get('threat_score',0)}"
            f" abuse={d.get('abuse_score',0)}%"
            f" new={'yes' if not d.get('is_known') else 'no'}"
            f" ports=[{port_s}]\n"
        )

    spoof_block = (
        "⚠️  ARP SPOOFING DETECTED:\n" +
        "\n".join(f"  {s['ip']} MAC {s['old_mac']} → {s['new_mac']}"
                  for s in arp_spoofed)
    ) if arp_spoofed else "No ARP spoofing detected."

    ev_block = "\n".join(
        f"  [{e['severity']:8}] {e['timestamp']} {e['ip']} "
        f"{e['event_type']}: {e['details']}"
        for e in events[:15]
    ) or "  No events in last 24h"

    prompt = (
        f"You are a senior cybersecurity analyst for a 24/7 home SOC.\n\n"
        f"Time: {ts()}  |  Gateway: {HOME_GATEWAY}  |  Network: {NETWORK}\n"
        f"Devices online: {len(devices)}\n\n"
        f"=== DEVICE THREAT INTELLIGENCE ===\n{dev_block}\n"
        f"=== ARP SPOOF STATUS ===\n{spoof_block}\n\n"
        f"=== EVENT LOG (24h) ===\n{ev_block}\n\n"
        f"=== SYSTEM METRICS ===\n{format_netdata(netdata)}\n\n"
        f"=== NETWORK TRAFFIC ===\n{format_ntopng(ntopng)}\n\n"
        f"Write a professional SOC report covering:\n"
        f"[1] 🔐 NETWORK SECURITY — suspicious/unknown devices, traffic anomalies\n"
        f"[2] 🖥️  SYSTEM HEALTH — CPU/RAM/disk/load concerns\n"
        f"[3] 🚨 THREAT INDICATORS — ARP spoofing, high abuse scores, risky ports, "
        f"anything requiring IMMEDIATE action\n"
        f"[4] ✅ RECOMMENDATIONS — prioritized, actionable, include specific IPs\n"
        f"Be concise and professional. Max 400 words."
    )

    cprint(f"\n  🤖  Querying {OLLAMA_MODEL} …", C.MAG, bold=True)

    # ── Pre-flight: is Ollama up at all? ──────────────────────────
    ping = safe_request("GET", "http://localhost:11434/api/tags", timeout=5)
    if not ping or ping.status_code != 200:
        status_err(
            f"Ollama unreachable — {_last_request_error or 'no response'}"
        )
        status_warn("Start Ollama with:  ollama serve")
        return ("⚠️  Ollama is offline.\n"
                "    Run:  ollama serve\n"
                "    AI analysis will resume automatically next cycle.")

    # ── Confirm the model is actually loaded ──────────────────────
    try:
        loaded = [m.get("name","") for m in ping.json().get("models",[])]
        if OLLAMA_MODEL not in loaded and not any(
            m.startswith(OLLAMA_MODEL.split(":")[0]) for m in loaded
        ):
            status_warn(
                f"Model '{OLLAMA_MODEL}' not found in Ollama. "
                f"Loaded: {loaded or ['none']}. "
                f"Pull it with:  ollama pull {OLLAMA_MODEL}"
            )
    except Exception:
        pass

    # ── Send prompt — direct requests call so we see real errors ──
    cprint(f"  📤  Sending prompt ({len(prompt)} chars) …", C.GRAY)
    try:
        r = requests.post(
            OLLAMA_URL,
            json={
                "model":   OLLAMA_MODEL,
                "prompt":  prompt,
                "stream":  False,
                "options": {"num_predict": 800, "temperature": 0.2},
            },
            timeout=300,    # 5 minutes — give slow models room to breathe
        )
        if r.status_code == 200:
            response_text = r.json().get("response", "").strip()
            if not response_text:
                status_warn("Ollama returned an empty response")
                return "⚠️  AI returned an empty response — try: ollama run " + OLLAMA_MODEL
            return response_text
        else:
            status_err(f"Ollama HTTP {r.status_code}: {r.text[:200]}")
            return f"⚠️  Ollama returned HTTP {r.status_code}:\n{r.text[:300]}"

    except requests.exceptions.ConnectionError as e:
        status_err(f"Cannot connect to Ollama: {e}")
        return ("⚠️  Connection refused to Ollama.\n"
                "    Make sure Ollama is running:  ollama serve")

    except requests.exceptions.ReadTimeout:
        status_err(
            f"Ollama timed out after 300s — model '{OLLAMA_MODEL}' is too slow "
            f"or the prompt is too large."
        )
        status_warn(
            "Try a faster model:  set OLLAMA_MODEL = 'phi3' or 'gemma2'"
        )
        return ("⚠️  AI timed out (300s).\n"
                f"    Model '{OLLAMA_MODEL}' may be too slow for your hardware.\n"
                "    Try:  OLLAMA_MODEL = 'phi3'  in the settings block.")

    except KeyboardInterrupt:
        raise

    except Exception as e:
        status_err(f"Unexpected Ollama error: {type(e).__name__}: {e}")
        return f"⚠️  Unexpected AI error: {type(e).__name__}: {str(e)[:200]}"

# ══════════════════════════════════════════════════════════════════
#  REPORT WRITER
# ══════════════════════════════════════════════════════════════════

def save_report(devices: list, netdata, ntopng, ai_report: str,
                events: list, arp_spoofed: list) -> Path:
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
                        key=lambda x: x.get("threat_score",0), reverse=True)
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

# ══════════════════════════════════════════════════════════════════
#  SERVICE CHECKER
# ══════════════════════════════════════════════════════════════════

def check_services() -> dict:
    section_header("Service Health Check", "🔌")
    svc = {}

    for label, url, key in [
        ("Netdata", f"{NETDATA_URL}/api/v1/info",         "netdata"),
        ("ntopng",  NTOPNG_URL,                            "ntopng"),
        ("Ollama",  "http://localhost:11434/api/tags",      "ollama"),
    ]:
        r = safe_request("GET", url, timeout=5, debug=True)
        svc[key] = bool(r and r.status_code == 200)
        fn    = status_ok if svc[key] else status_err
        extra = ""
        if svc[key] and key == "netdata":
            extra = f"  (v{r.json().get('version','?')})"
        if svc[key] and key == "ollama":
            models = r.json().get("models", [])
            names  = [m.get("name","?") for m in models[:5]]
            extra  = f"  models: {', '.join(names) or 'NONE LOADED'}"
            if not models:
                fn = status_warn
        fn(f"{label:<10} → {url}{extra}")
        if not svc[key] and key == "ollama":
            if _last_request_error:
                status_err(f"           Reason: {_last_request_error}")
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

# ══════════════════════════════════════════════════════════════════
#  DEEP ANALYSIS CYCLE
# ══════════════════════════════════════════════════════════════════

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
        tmp.update({"ip":ip,"vendor":vendor,
                    "is_known": not is_new,"abuse_score": abuse})
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
                         severity="WARN" if score<40 else "HIGH")
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
        if any(sl.startswith(t) for t in ("[1]","[2]","[3]","[4]")):
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
        subject=f"[SOC] Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
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

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════

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
    nmap_path = find_nmap()

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
            status_err(f"Main loop error: {e}")
            traceback.print_exc()
            status_warn("Retrying in 5 min …")
            time.sleep(300)


if __name__ == "__main__":
    main()