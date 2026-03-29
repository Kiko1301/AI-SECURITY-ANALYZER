# 🛡️ AI SOC Analyzer — Cyber Sentinel

> A self-hosted, AI-powered Security Operations Center for your home or small-office network.  
> Combines network scanning, threat intelligence, ARP spoof detection, and local LLM analysis into a single Python script — no cloud required.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Ollama](https://img.shields.io/badge/AI-Ollama%20%2F%20Mistral-purple?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Network Scanning** | Hourly ping sweeps + deep 24h nmap analysis |
| 🤖 **AI Analysis** | Local LLM (Mistral via Ollama) writes a professional SOC report every cycle |
| 🛡️ **ARP Spoof Detection** | Compares MAC addresses every cycle — alerts on MITM attacks instantly |
| 🎯 **Threat Scoring** | 0–100 risk score per device based on ports, ARP, AbuseIPDB, and behavior |
| 🏭 **MAC Vendor Lookup** | Identifies device manufacturers from MAC addresses (free, no key) |
| 🌍 **IP Geolocation** | Country / city / ISP via ipinfo.io (free, no key needed) |
| 🚨 **AbuseIPDB Check** | Cross-references every IP against the global threat database |
| 📡 **Port Scanning** | Targeted nmap top-20 port scan on new or suspicious hosts only |
| 📲 **Telegram Alerts** | Instant phone notification for new devices, ARP spoofing, and high-risk events |
| 📧 **Email Reports** | Full HTML report delivered to your inbox after every deep cycle |
| 🗃️ **SQLite Database** | Full history of devices, events, port scans, and ARP cache |
| 📊 **Netdata Integration** | CPU, RAM, disk I/O, network, and load metrics |
| 🌐 **ntopng Integration** | Live traffic analysis and active alert ingestion |
| 🗂️ **Auto Report Cleanup** | Reports saved by date folder; auto-deleted after 30 days |
| 🎨 **Rich Terminal UI** | Color-coded threat leaderboard, section headers, and status icons |

---

## 📸 Terminal Preview

```
  ╔══════════════════════════════════════════════════════════════╗
  ║   CYBER SOC  ·  AI SOC ANALYZER v3.0  ·  CYBER SENTINEL      ║
  ║   SQLite · Threat Intel · ARP Detection · Telegram · Email   ║
  ╚══════════════════════════════════════════════════════════════╝

  ── DEVICE THREAT LEADERBOARD ──────────────────────────────────
  IP                 HOSTNAME               VENDOR               COUNTRY   SCORE           ABUSE
  192.168.31.105     desktop-win11          Dell Inc.            —         [LOW        2]  0%
  192.168.31.42      unknown                Unknown              —         [HIGH      55]  0%
  192.168.31.1       gateway                Xiaomi               —         [LOW        5]  0%
```

---

## 🗂️ Project Structure

```
ai-soc-analyzer/
├── ai_soc.py            # Main script — everything lives here
├── soc_database.db      # SQLite DB (auto-created on first run)
├── reports/             # Auto-created report directory
│   └── YYYY-MM-DD/
│       └── SOC_Report_YYYY-MM-DD_HH-MM-SS.txt
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Requirements

### System
- **Python 3.11+**
- **Nmap** — [download for Windows](https://nmap.org/download.html) or `sudo apt install nmap`
- **Ollama** — [ollama.com](https://ollama.com) — runs the AI model locally

### Optional services (enhances monitoring)
- [Netdata](https://www.netdata.cloud) — system performance metrics
- [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/) — network traffic analysis

### Python packages
```
pip install requests
```
> That's the only third-party dependency. Everything else uses the Python standard library.

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/ai-soc-analyzer.git
cd ai-soc-analyzer
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Install and start Ollama
```bash
# Install from https://ollama.com, then:
ollama serve
ollama pull mistral
```

### 4. Edit the settings block in `ai_soc.py`

Open `ai_soc.py` and edit the **SETTINGS** block near the top:

```python
# ── Core network ──────────────────────────────────────────────────
HOME_GATEWAY = "192.168.31.1"       # Your router's IP
NETWORK      = "192.168.31.0/24"    # Your network range
NMAP_PATH    = r"C:\...\nmap.exe"   # Path to nmap (Windows)
#              "/usr/bin/nmap"       # Path to nmap (Linux)
```

### 5. Run
```bash
python ai_soc.py
```

The analyzer will:
1. Check all services
2. Perform an initial network discovery
3. Enter the monitoring loop (hourly quick sweeps + 24h deep analysis)

---

## 🔧 Configuration Reference

All settings are at the top of `ai_soc.py` in clearly labeled blocks.

### Core
| Setting | Default | Description |
|---|---|---|
| `HOME_GATEWAY` | `192.168.31.1` | Your router IP |
| `NETWORK` | `192.168.31.0/24` | CIDR range to scan |
| `NMAP_PATH` | Windows path | Full path to nmap executable |
| `QUICK_SCAN_INTERVAL` | `3600` | Seconds between ping sweeps (1h) |
| `DEEP_SCAN_INTERVAL` | `86400` | Seconds between full analyses (24h) |
| `REPORT_MAX_DAYS` | `30` | Days before old reports are deleted |
| `OLLAMA_MODEL` | `mistral` | Any model you have pulled in Ollama |

### Telegram Alerts
```python
TELEGRAM_ENABLED = True
TELEGRAM_TOKEN   = "1234567890:ABCdef..."   # From @BotFather
TELEGRAM_CHAT_ID = "123456789"              # Your chat or group ID
```

**How to get your credentials:**
1. Message [@BotFather](https://t.me/BotFather) on Telegram → `/newbot` → copy the token
2. Message [@userinfobot](https://t.me/userinfobot) → it replies with your chat ID

### Email Reports
```python
EMAIL_ENABLED   = True
EMAIL_FROM      = "soc@yourdomain.com"
EMAIL_TO        = "you@yourdomain.com"
EMAIL_SMTP_HOST = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_PASSWORD  = "xxxx xxxx xxxx xxxx"    # Gmail App Password
```

**Gmail App Password:** Google Account → Security → 2-Step Verification → App Passwords

### AbuseIPDB (recommended)
```python
ABUSEIPDB_ENABLED   = True
ABUSEIPDB_KEY       = "your_api_key_here"
ABUSEIPDB_MIN_SCORE = 20    # Flag IPs reported with ≥20% confidence
```

**Get a free key:** [abuseipdb.com/register](https://www.abuseipdb.com/register) — 1,000 checks/day free

---

## 📊 Threat Scoring

Each device gets a 0–100 risk score computed every cycle:

| Condition | Score Added |
|---|---|
| ARP spoofing detected for this IP | +45 |
| Device seen for first time | +25 |
| Device not yet marked as known | +10 |
| MAC vendor is Unknown | +10 |
| AbuseIPDB score (scaled) | up to +20 |
| Risky open port (Telnet, RDP, SMB…) | +10 to +35 per port |

| Score Range | Badge | Meaning |
|---|---|---|
| 0–14 | 🟢 LOW | Normal device |
| 15–39 | 🔵 MEDIUM | Needs a look |
| 40–69 | 🟡 HIGH | Investigate |
| 70–100 | 🔴 CRITICAL | Act now |

---

## 🗃️ Database

The SQLite database (`soc_database.db`) is created automatically and stores:

- **`devices`** — every host ever seen, with vendor, geo, threat score, abuse score, first/last seen
- **`events`** — timestamped event log (new device, ARP spoof, risky port, abuse hit)
- **`port_scans`** — latest open ports per device
- **`arp_cache`** — last known MAC per IP for spoof detection

You can query it directly:
```bash
sqlite3 soc_database.db "SELECT ip, vendor, threat_score FROM devices ORDER BY threat_score DESC;"
```

---

## 📁 Reports

Reports are saved as plain-text files organized by date:
```
reports/
└── 2025-07-15/
    ├── SOC_Report_2025-07-15_08-00-01.txt
    └── SOC_Report_2025-07-15_20-00-04.txt
```

Each report contains:
- Device threat table (all devices, sorted by risk score)
- ARP spoof detection results
- Event log for the last 24 hours
- Netdata system metrics snapshot
- ntopng traffic snapshot
- Full AI-generated security analysis

Reports older than `REPORT_MAX_DAYS` (default 30) are deleted automatically at the start of each deep cycle.

---

## 🤖 Changing the AI Model

Any model available in Ollama works. Recommendations:

| Model | Speed | Quality | Command |
|---|---|---|---|
| `mistral` | Medium | ⭐⭐⭐⭐ | `ollama pull mistral` |
| `phi3` | Fast | ⭐⭐⭐ | `ollama pull phi3` |
| `llama3` | Medium | ⭐⭐⭐⭐⭐ | `ollama pull llama3` |
| `gemma2` | Fast | ⭐⭐⭐⭐ | `ollama pull gemma2` |

Change it in the settings:
```python
OLLAMA_MODEL = "llama3"
```

---

## 🐧 Linux / macOS Notes

- Set `NMAP_PATH = "/usr/bin/nmap"` (or the output of `which nmap`)
- Run with `sudo python3 ai_soc.py` if nmap requires root for SYN scans
- ARP table parsing works on both Windows (`arp -a`) and Linux

---

## 🔒 Privacy & Security Notes

- All AI analysis runs **100% locally** via Ollama — no data leaves your machine
- ipinfo.io receives the IPs you discover (disable with `IPINFO_ENABLED = False`)
- AbuseIPDB receives IPs for lookup (disable with `ABUSEIPDB_ENABLED = False`)
- MAC vendor lookups send only the first 3 octets of each MAC address
- The SQLite database and reports contain network topology — keep them private

---

## 🛠️ Troubleshooting

**`AI returned HTTP N/A` or AI is skipped**
```bash
ollama serve          # Start the Ollama service
ollama pull mistral   # Make sure the model is downloaded
ollama run mistral    # Test it works manually
```

**Nmap not found**
- Windows: install from [nmap.org](https://nmap.org) and update `NMAP_PATH`
- Linux: `sudo apt install nmap` then set `NMAP_PATH = "/usr/bin/nmap"`

**No devices found**
- Make sure you're on the same subnet as the devices
- Check that `NETWORK` matches your actual network range (check with `ipconfig` / `ip addr`)

**ntopng traffic data not JSON**
- ntopng may require a different API path for your version — traffic analysis will be skipped but everything else continues normally

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

## 🙏 Acknowledgements

- [Ollama](https://ollama.com) — local LLM inference
- [Nmap](https://nmap.org) — network scanning engine
- [AbuseIPDB](https://www.abuseipdb.com) — IP threat intelligence
- [ipinfo.io](https://ipinfo.io) — IP geolocation
- [macvendors.com](https://macvendors.com) — MAC vendor lookup
- [Netdata](https://www.netdata.cloud) — system metrics
- [ntopng](https://www.ntop.org) — network traffic analysis