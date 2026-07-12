#!/usr/bin/env python3
"""
One-time migration: known_devices.json (old schema) -> soc_database.db (new SocDB schema)

Run this ONCE from your project root, after dropping soc/ and main.py in place
but BEFORE you start main.py for the first time (so the new devices table gets
seeded with your real history instead of starting empty).

Usage:
    python3 migrate_known_devices.py [path/to/known_devices.json]

Defaults to ./known_devices.json if no path is given.

What it does:
  - Reads each entry from the old JSON list
  - Maps it onto the new devices table columns
  - Marks every migrated device is_known=1 (they were already "known" in
    the old system) and threat_score=0 (old schema never scored them —
    the new scorer will re-score them fresh on their next deep cycle)
  - Skips any IP that already exists in the DB (safe to re-run)
  - Leaves known_devices.json untouched — delete it yourself once you've
    confirmed the migration looks right
"""
import json
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path("soc_database.db")


def main():
    json_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("known_devices.json")

    if not json_path.exists():
        print(f"❌  {json_path} not found. Pass the path explicitly:")
        print(f"    python3 migrate_known_devices.py path/to/known_devices.json")
        sys.exit(1)

    old_devices = json.loads(json_path.read_text(encoding="utf-8"))
    print(f"📄  Loaded {len(old_devices)} device(s) from {json_path}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Make sure the devices table exists (same schema as soc/db.py) —
    # safe no-op if main.py has already been run once.
    conn.executescript("""
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
    """)
    conn.commit()

    migrated, skipped = 0, 0

    for d in old_devices:
        ip = d.get("ip")
        if not ip:
            continue

        existing = conn.execute(
            "SELECT ip FROM devices WHERE ip=?", (ip,)
        ).fetchone()
        if existing:
            skipped += 1
            continue

        conn.execute(
            """
            INSERT INTO devices
                (ip, mac, hostname, vendor, device_type,
                 first_seen, last_seen, threat_score, abuse_score,
                 is_known, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                ip,
                d.get("mac"),
                d.get("hostname"),
                d.get("vendor"),
                d.get("device_type") or "Unknown",
                d.get("first_seen"),
                d.get("last_seen"),
                0,      # threat_score — old schema never computed one
                0,      # abuse_score  — old schema never checked AbuseIPDB
                1,      # is_known — these were tracked devices already
                d.get("notes") or "",
            ),
        )
        migrated += 1

    conn.commit()

    total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    conn.close()

    print(f"✅  Migrated {migrated} device(s)")
    if skipped:
        print(f"⏭️   Skipped {skipped} device(s) already present in {DB_PATH}")
    print(f"📊  {DB_PATH} now has {total} device(s) total")
    print(f"\nNext steps:")
    print(f"  1. Spot-check a few rows: sqlite3 {DB_PATH} \"SELECT ip,hostname,is_known FROM devices LIMIT 5;\"")
    print(f"  2. Once it looks right, delete {json_path} (and any code in the old")
    print(f"     ai_soc.py that reads/writes it) — it's no longer used.")


if __name__ == "__main__":
    main()
