"""
Builds the SOC-analyst prompt from current state and queries the local
Ollama model for a written report. Handles the Ollama-specific failure
modes (offline, model not pulled, timeout) with actionable messages.
"""
import requests

from soc.config import HOME_GATEWAY, NETWORK, OLLAMA_URL, OLLAMA_MODEL
from soc.db import db
from soc.utils import ts, safe_request, get_last_request_error
from soc.monitoring import format_netdata, format_ntopng
from soc.ui import cprint, status_ok, status_warn, status_err, C


def analyze_with_ai(devices: list, netdata, ntopng,
                     events: list, arp_spoofed: list) -> str:

    dev_block = ""
    for d in devices:
        ports = db.get_open_ports(str(d.get("ip", "?")))
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
            f"Ollama unreachable — {get_last_request_error() or 'no response'}"
        )
        status_warn("Start Ollama with:  ollama serve")
        return ("⚠️  Ollama is offline.\n"
                "    Run:  ollama serve\n"
                "    AI analysis will resume automatically next cycle.")

    # ── Confirm the model is actually loaded ──────────────────────
    try:
        loaded = [m.get("name", "") for m in ping.json().get("models", [])]
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
