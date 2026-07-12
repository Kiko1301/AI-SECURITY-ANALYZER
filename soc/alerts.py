"""
Outbound notifications: Telegram messages and email reports, plus the
HTML report builder that feeds the email body. Both senders fire on
background threads so a slow SMTP/Telegram call never blocks scanning.
"""
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from soc.config import (
    TELEGRAM_ENABLED, TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
    EMAIL_ENABLED, EMAIL_FROM, EMAIL_TO,
    EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, EMAIL_PASSWORD,
)
from soc.utils import safe_request, ts
from soc.ui import status_ok, status_warn


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
    high = sum(1 for d in devices if d.get("threat_score", 0) >= 40)
    _telegram_send(
        f"📊 <b>SOC Cycle Complete</b> — {ts()}\n"
        f"Devices online: {len(devices)}\n"
        f"High-risk: {high}\n"
        f"Events (24h): {len(events)}\n\n"
        f"<b>AI Summary:</b>\n{ai_snippet[:500]}"
    )


def build_html_report(devices: list, ai_report: str, events: list) -> str:
    rows = ""
    for d in sorted(devices, key=lambda x: x.get("threat_score", 0), reverse=True):
        s = d.get("threat_score", 0)
        c = "#ff4444" if s >= 70 else "#ffaa00" if s >= 40 \
            else "#4488ff" if s >= 15 else "#44bb44"
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
