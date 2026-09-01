"""Generate data/demo_feed.csv -- the curated sequence for the Live Investigation demo.

Written as a generator rather than a hand-typed CSV so the feed stays in sync
with the detector thresholds in log_analysis_agent.py. Hand-picking "3 brute
force rows" would look right and detect nothing: brute_force needs
FAILED_LOGIN_THRESHOLD (8) failures and port_scan needs PORT_SCAN_THRESHOLD
(10) distinct ports. Every burst below is sized to actually fire its rule.

Feed shape (41 rows, chronological, one clean story per phase):

    02:41  3 rows   off-hours admin login from an unknown device  -> incident
    09:00  8 rows   ordinary office traffic                       -> nothing
    09:20 11 rows   10 failed logins + 1 success from one IP      -> incident
    09:40  4 rows   ordinary office traffic                       -> nothing
    10:00 12 rows   12 distinct ports probed from one IP          -> incident
    10:20  3 rows   ordinary office traffic                       -> nothing

The quiet phases matter as much as the loud ones: they prove the system is
discriminating, not flagging everything that moves.

    python scripts/make_demo_feed.py
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = PROJECT_ROOT / "data" / "demo_feed.csv"
SOURCE_FILE = "demo_feed.csv"

COLUMNS = ["row_id", "timestamp", "source", "event_type", "severity",
           "raw_fields", "source_file", "source_row"]

DAY = datetime(2026, 9, 1)
OFFICE_HOSTS = ["192.168.1.21", "192.168.1.22", "192.168.1.23", "192.168.1.24"]
OFFICE_USERS = ["employee01", "employee02", "employee03", "employee04"]
OFFICE_DEVICES = ["LAP-EMP-01", "LAP-EMP-02", "DESK-EMP-03", "MOB-EMP-04"]

ATTACKER_BRUTE = "203.0.113.66"
ATTACKER_SCAN = "198.51.100.23"
ATTACKER_NIGHT = "185.72.44.19"

rows: List[Dict[str, Any]] = []


def add(when: datetime, source: str, event_type: str, severity: str,
        phase: str, expect: str, **raw: Any) -> None:
    rows.append({
        "timestamp": when,
        "source": source,
        "event_type": event_type,
        "severity": severity,
        # phase/expected ride along in raw_fields so the live page can narrate
        # what should happen without hard-coding row numbers in the UI.
        "raw_fields": {**raw, "demo_phase": phase, "demo_expect": expect},
    })


# ── 02:41 — off-hours admin login from an unrecognised device ──────────────── #
for i in range(3):
    add(DAY + timedelta(hours=2, minutes=41, seconds=i * 62),
        ATTACKER_NIGHT, "login_success", "high",
        "Off-hours access", "suspicious",
        user="admin", dest_ip="10.0.0.10", device="Unknown-Laptop",
        status="SUCCESS", protocol="HTTPS", bytes=500 + i * 6,
        message="Admin login outside working hours")

# ── 09:00 — ordinary office traffic ────────────────────────────────────────── #
for i in range(8):
    add(DAY + timedelta(hours=9, minutes=i, seconds=7 * i),
        OFFICE_HOSTS[i % 4],
        "login_success" if i % 3 == 0 else "http_request", "info",
        "Baseline traffic", "normal",
        user=OFFICE_USERS[i % 4], dest_ip="10.0.0.10",
        device=OFFICE_DEVICES[i % 4], status="SUCCESS",
        protocol="HTTPS", dest_port=443, bytes=420 + i * 30,
        message="Routine activity")

# ── 09:20 — brute force: 10 failures then a success ────────────────────────── #
for i in range(10):
    add(DAY + timedelta(hours=9, minutes=20, seconds=i * 26),
        ATTACKER_BRUTE, "failed_login", "high",
        "Brute force", "suspicious",
        user="admin", dest_ip="10.0.0.10", device="Unknown-Host",
        status="FAILED", protocol="SSH", dest_port=22, bytes=180,
        message="Authentication failure")
add(DAY + timedelta(hours=9, minutes=24, seconds=40),
    ATTACKER_BRUTE, "login_success", "critical",
    "Brute force", "suspicious",
    user="admin", dest_ip="10.0.0.10", device="Unknown-Host",
    status="SUCCESS", protocol="SSH", dest_port=22, bytes=640,
    message="Authentication success after repeated failures")

# ── 09:40 — ordinary office traffic ────────────────────────────────────────── #
for i in range(4):
    add(DAY + timedelta(hours=9, minutes=40 + i, seconds=11 * i),
        OFFICE_HOSTS[i % 4], "file_access", "info",
        "Baseline traffic", "normal",
        user=OFFICE_USERS[i % 4], dest_ip="10.0.0.15",
        device=OFFICE_DEVICES[i % 4], status="SUCCESS",
        protocol="HTTPS", dest_port=443, bytes=900 + i * 40,
        path="/projects/report.docx", message="Routine file read")

# ── 10:00 — port scan: 12 distinct destination ports ───────────────────────── #
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389]
for i, port in enumerate(SCAN_PORTS):
    add(DAY + timedelta(hours=10, minutes=0, seconds=i * 20),
        ATTACKER_SCAN, "network_request", "high",
        "Port scan", "suspicious",
        dest_ip="10.0.0.10", dest_port=port, protocol="TCP",
        status="NO_REPLY", bytes=60, device="Unknown-Scanner",
        message=f"Connection attempt to port {port}")

# ── 10:20 — ordinary office traffic ────────────────────────────────────────── #
for i in range(3):
    add(DAY + timedelta(hours=10, minutes=20 + i, seconds=9 * i),
        OFFICE_HOSTS[i % 4], "http_request", "info",
        "Baseline traffic", "normal",
        user=OFFICE_USERS[i % 4], dest_ip="10.0.0.20",
        device=OFFICE_DEVICES[i % 4], status="SUCCESS",
        protocol="HTTPS", dest_port=443, bytes=1200 + i * 55,
        message="Routine request")


def main() -> int:
    rows.sort(key=lambda r: r["timestamp"])
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        for position, row in enumerate(rows, start=1):
            writer.writerow({
                "row_id": f"F{position:03d}",
                "timestamp": row["timestamp"].strftime("%Y-%m-%dT%H:%M:%S"),
                "source": row["source"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "raw_fields": json.dumps(row["raw_fields"], sort_keys=True),
                "source_file": SOURCE_FILE,
                "source_row": position,
            })

    phases: Dict[str, int] = {}
    for row in rows:
        phases[row["raw_fields"]["demo_phase"]] = \
            phases.get(row["raw_fields"]["demo_phase"], 0) + 1

    print(f"wrote {OUT_PATH}  ({len(rows)} rows)")
    for phase, count in phases.items():
        print(f"  {phase:20s} {count:3d} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
