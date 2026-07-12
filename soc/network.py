"""
Nmap scanning (host discovery + targeted port scans) and ARP-table
based spoof detection.
"""
import os
import re
import subprocess

from soc.config import NETWORK
from soc.db import db
from soc.ui import cprint, status_ok, status_warn, status_err, status_alert, C


def find_nmap(nmap_path: str):
    if os.path.exists(nmap_path):
        try:
            r = subprocess.run([nmap_path, "--version"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                status_ok(f"Nmap found → {nmap_path}")
                return nmap_path
        except Exception:
            pass
    status_err(f"Nmap not found at {nmap_path}")
    return None


def _extract_ips(output: str) -> list:
    ips = []
    for line in output.splitlines():
        if "Nmap scan report for" not in line:
            continue
        ip = (line.split("(")[-1].replace(")", "").strip()
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
                arp[m.group(1)] = m.group(2).lower().replace("-", ":")
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
