"""
All user-editable settings live here. This is the one file you should
need to touch to point the analyzer at a different network, enable a
new integration, or tune scan intervals.
"""
from pathlib import Path

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

# ── Credentials ────────────────────────────────────────────────────
# Real values live in soc/secrets.py (gitignored, never committed).
# See soc/secrets.example.py for the template — copy it to secrets.py
# and fill in your real Telegram/Email/AbuseIPDB values there.
# If secrets.py doesn't exist yet, these fall back to placeholders so
# the app still runs (with these integrations effectively disabled).
try:
    from soc.secrets import (
        TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
        EMAIL_FROM, EMAIL_TO, EMAIL_PASSWORD,
        ABUSEIPDB_KEY,
    )
except ImportError:
    TELEGRAM_TOKEN   = "YOUR_BOT_TOKEN"
    TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"
    EMAIL_FROM       = "soc@yourdomain.com"
    EMAIL_TO         = "you@yourdomain.com"
    EMAIL_PASSWORD   = "your_app_password"
    ABUSEIPDB_KEY    = "YOUR_ABUSEIPDB_KEY"

# ── Telegram  (https://t.me/BotFather → create bot) ──────────────
TELEGRAM_ENABLED = False

# ── Email  (Gmail: create an App Password in Google Account) ──────
EMAIL_ENABLED    = False
EMAIL_SMTP_HOST  = "smtp.gmail.com"
EMAIL_SMTP_PORT  = 587

# ── AbuseIPDB  (https://www.abuseipdb.com — free 1 000 checks/day) ─
ABUSEIPDB_ENABLED   = False
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
