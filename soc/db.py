"""
SQLite persistence: devices, events, port scans, ARP cache.
Nothing in here prints or does network I/O — it's pure storage.
"""
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from soc.config import DB_PATH
from soc.utils import ts


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

    def purge_events_older_than(self, days: int) -> int:
        """Delete events older than `days`. Returns number of rows removed."""
        cutoff = (datetime.now() - timedelta(days=days)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        cur = self.conn.execute(
            "DELETE FROM events WHERE timestamp<?", (cutoff,)
        )
        self.conn.commit()
        return cur.rowcount

    # ── Port scans ────────────────────────────────────────────────
    def save_port_scan(self, ip: str, ports: list):
        self.conn.execute("DELETE FROM port_scans WHERE ip=?", (ip,))
        now = ts()
        for p in ports:
            self.conn.execute(
                "INSERT INTO port_scans "
                "(ip,port,protocol,service,version,scan_time) "
                "VALUES (?,?,?,?,?,?)",
                (ip, p.get("port"), p.get("protocol", "tcp"),
                 p.get("service", ""), p.get("version", ""), now)
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


# Single shared instance used across the app, same as the original script.
db = SocDB()
