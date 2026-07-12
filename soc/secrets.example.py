"""
LOCAL CREDENTIALS — this file is gitignored and never committed.

Copy soc/secrets.example.py to soc/secrets.py and fill in real values.
soc/config.py imports from this file and falls back to safe placeholder
defaults if it doesn't exist yet, so the app still runs (with those
integrations effectively disabled) even before you've created it.
"""

# ── Telegram  (https://t.me/BotFather → create bot) ──────────────
TELEGRAM_TOKEN   = "YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

# ── Email  (Gmail: create an App Password in Google Account) ──────
EMAIL_FROM     = "soc@yourdomain.com"
EMAIL_TO       = "you@yourdomain.com"
EMAIL_PASSWORD = "your_app_password"

# ── AbuseIPDB  (https://www.abuseipdb.com — free 1 000 checks/day) ─
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_KEY"
