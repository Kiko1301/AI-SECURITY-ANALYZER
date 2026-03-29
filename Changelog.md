# Changelog

All notable changes to AI SOC Analyzer are documented here.

---

## [3.0.0] — 2025

### Added
- **SQLite database** — replaces `known_devices.json`; stores full device history,
  event log, port scan results, and ARP cache across reboots
- **Threat scoring engine** — 0–100 risk score per device computed every cycle
  based on port exposure, ARP status, AbuseIPDB score, and behavioral signals
- **ARP spoof detection** — compares system ARP table every cycle against last
  known MAC per IP; logs and alerts on any change (MITM indicator)
- **MAC vendor lookup** — free API identifies device manufacturer from MAC address
- **ipinfo.io geolocation** — enriches every non-private IP with country/city/ISP
- **AbuseIPDB integration** — cross-references discovered IPs against global
  threat database; flags IPs above configurable confidence threshold
- **Targeted port scanning** — nmap top-20 port scan runs only on new devices or
  IPs flagged by AbuseIPDB, keeping cycle time fast
- **Telegram alerts** — instant phone notifications for new devices, ARP spoofing,
  and cycle summaries; runs in a background thread (non-blocking)
- **Email reports** — full HTML report with device table, event log, and AI
  analysis delivered to inbox after every deep cycle
- **Dual-schedule loop** — hourly quick ping sweep + 24h deep analysis run
  on independent timers in a single process
- **Color-coded threat leaderboard** — terminal table sorted by risk score with
  GREEN / BLUE / YELLOW / RED badge per device
- **Event log** — every significant event (new device, ARP spoof, risky port,
  abuse hit) stored with timestamp and severity in SQLite
- **Model pre-flight check** — verifies Ollama is reachable AND the configured
  model is actually loaded before attempting the AI POST
- **Detailed error reporting** — `safe_request` captures real exception type and
  message; `check_services` prints the exact failure reason at startup

### Changed
- AI POST timeout increased from 200s → 300s to accommodate slower hardware
- Ollama call moved from `safe_request` to direct `requests.post` with
  per-exception handlers (`ConnectionError`, `ReadTimeout`, generic)
- `OLLAMA_MODEL` is now a named constant (was hardcoded `"mistral"`)

### Removed
- `device_database.py` external dependency — replaced by built-in `SocDB` class

---

## [2.0.0] — 2025

### Added
- ANSI color terminal UI with section headers and status icons
- Report directory structure: `reports/YYYY-MM-DD/SOC_Report_*.txt`
- Auto-purge of reports older than `REPORT_MAX_DAYS` (default 30 days)
- `safe_request()` wrapper — prevents `KeyboardInterrupt` from being swallowed
  by `except Exception` blocks during socket cleanup
- Graceful Ollama offline handling — skips AI cycle instead of crashing
- `None`-safe f-string formatting for all device fields

### Fixed
- `KeyboardInterrupt` during Ollama connection no longer causes unhandled crash
- `NoneType.__format__` crash when device fields exist but hold `None` values
- ntopng traffic endpoint returning non-JSON no longer crashes the main loop
- Duplicate `except KeyboardInterrupt` block in main loop removed

---

## [1.0.0] — 2025

### Initial release
- Nmap ping sweep and detailed host scan
- Netdata v1 API metrics (CPU, RAM, network, disk, load)
- ntopng login + traffic + alert ingestion
- Ollama / Mistral AI analysis with 300-word SOC report
- `known_devices.json` device persistence via `DeviceDatabase`
- 24-hour scan loop with report saved to timestamped `.txt` file