"""Generate data/demo_feed.csv -- the curated sequence for the Live Investigation demo.

Written as a generator rather than a hand-typed CSV so the feed stays in sync
with the detector thresholds in log_analysis_agent.py. Hand-picking "3 brute
force rows" would look right and detect nothing: brute_force needs
FAILED_LOGIN_THRESHOLD (8) failures and port_scan needs PORT_SCAN_THRESHOLD
(10) distinct ports. Every burst below is sized to actually fire its rule.

Feed shape (~180 rows, chronological, one clean story per phase):

    02:41  3 rows   off-hours admin login from an unknown device  -> incident
    03:10 10 rows   quiet night shift                             -> nothing
    06:00 12 rows   12 accounts tried from one source             -> incident
    09:00 18 rows   the office arrives                            -> nothing
    09:20 11 rows   10 failed logins + 1 success from one IP      -> incident
    09:40 15 rows   ordinary office traffic                       -> nothing
    10:00 14 rows   14 distinct ports probed from one IP          -> incident
    10:20 16 rows   ordinary office traffic                       -> nothing
    11:00  8 rows   internal host sweeping 8 other internal hosts -> incident
    11:20 14 rows   ordinary office traffic                       -> nothing
    13:00 10 rows   oversized DNS lookups carrying data           -> incident
    13:30 12 rows   ordinary office traffic                       -> nothing
    14:00 15 rows   14 sensitive file reads then a 734 MB upload  -> incident
    14:30 14 rows   the day winds down                            -> nothing

Roughly 60% of the feed is normal traffic. That ratio is the point: a system
that alarms on everything is useless, and the quiet stretches are what prove
this one discriminates.

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


ATTACKER_STUFF = "45.13.201.8"       # credential stuffing from a hosting range
COMPROMISED_HOST = "192.168.1.55"    # an internal machine, already owned
ATTACKER_EXFIL = "192.168.1.61"      # insider staging then shipping data
DNS_BEACON = "192.168.1.47"          # host talking to a C2 over DNS

ROUTINE_PATHS = ["/projects/report.docx", "/projects/notes.md", "/share/team/agenda.pdf",
                 "/projects/roadmap.pptx", "/share/team/minutes.docx"]


def baseline(hour: int, minute: int, count: int, dest: str = "10.0.0.10") -> None:
    """Ordinary office activity. Spread wide enough never to look like a burst.

    These rows carry the demo: a system that only ever alarms proves nothing.
    Each quiet phase is a visible stretch where the detectors stay silent.
    """
    kinds = ["http_request", "login_success", "file_access", "http_request", "logout"]
    for i in range(count):
        kind = kinds[i % len(kinds)]
        extra = {"path": ROUTINE_PATHS[i % len(ROUTINE_PATHS)]} if kind == "file_access" else {}
        add(DAY + timedelta(hours=hour, minutes=minute + i, seconds=(i * 13) % 60),
            OFFICE_HOSTS[i % 4], kind, "info",
            "Baseline traffic", "normal",
            user=OFFICE_USERS[i % 4], dest_ip=dest,
            device=OFFICE_DEVICES[i % 4], status="SUCCESS",
            protocol="HTTPS", dest_port=443, bytes=420 + (i * 37) % 900,
            message="Routine activity", **extra)


# ── 02:41 — off-hours admin login from an unrecognised device ──────────────── #
for i in range(3):
    add(DAY + timedelta(hours=2, minutes=41, seconds=i * 62),
        ATTACKER_NIGHT, "login_success", "high",
        "Off-hours access", "suspicious",
        user="admin", dest_ip="10.0.0.10", device="Unknown-Laptop",
        status="SUCCESS", protocol="HTTPS", bytes=500 + i * 6,
        message="Admin login outside working hours")

# ── 03:10 — quiet night shift ──────────────────────────────────────────────── #
baseline(3, 10, 10)

# ── 06:00 — credential stuffing: one source, twelve different accounts ─────── #
STUFFED_USERS = ["asha", "ravi", "meera", "vikram", "neha", "sana",
                 "kabir", "dev1", "finance_svc", "backup_svc", "root", "administrator"]
for i, user in enumerate(STUFFED_USERS):
    add(DAY + timedelta(hours=6, minutes=0, seconds=i * 21),
        ATTACKER_STUFF, "failed_login", "high",
        "Credential stuffing", "suspicious",
        user=user, dest_ip="10.0.0.10", device="Unknown-Host",
        status="FAILED", protocol="HTTPS", dest_port=443, bytes=190,
        message=f"Authentication failure for {user}")

# ── 09:00 — the office arrives ─────────────────────────────────────────────── #
baseline(9, 0, 18)

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
baseline(9, 40, 15, dest="10.0.0.15")

# ── 10:00 — port scan: 14 distinct destination ports ───────────────────────── #
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
for i, port in enumerate(SCAN_PORTS):
    add(DAY + timedelta(hours=10, minutes=0, seconds=i * 18),
        ATTACKER_SCAN, "network_request", "high",
        "Port scan", "suspicious",
        dest_ip="10.0.0.10", dest_port=port, protocol="TCP",
        status="NO_REPLY", bytes=60, device="Unknown-Scanner",
        message=f"Connection attempt to port {port}")

# ── 10:20 — ordinary office traffic ────────────────────────────────────────── #
baseline(10, 20, 16, dest="10.0.0.20")

# ── 11:00 — lateral movement: an internal host sweeping other internal hosts ─ #
INTERNAL_TARGETS = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14",
                    "10.0.0.15", "10.0.0.16", "10.0.0.17", "10.0.0.18"]
for i, target in enumerate(INTERNAL_TARGETS):
    add(DAY + timedelta(hours=11, minutes=0, seconds=i * 27),
        COMPROMISED_HOST, "network_request", "high",
        "Lateral movement", "suspicious",
        dest_ip=target, dest_port=445, protocol="SMB",
        user="admin", status="SUCCESS", bytes=2400,
        message=f"SMB session opened to {target}")

# ── 11:20 — ordinary office traffic ────────────────────────────────────────── #
baseline(11, 20, 14)

# ── 13:00 — DNS tunnelling: oversized lookup names carrying data ───────────── #
for i in range(10):
    payload = f"{'a3f9c1e70b482d5641ff9a02c8e7' * 2}{i:02d}"
    add(DAY + timedelta(hours=13, minutes=0, seconds=i * 24),
        DNS_BEACON, "dns_query", "high",
        "DNS tunnelling", "suspicious",
        query=f"{payload}.cdn-sync-node.net", dest_ip="8.8.8.8",
        dest_port=53, protocol="UDP", status="SUCCESS", bytes=420,
        message="Abnormally long DNS query")

# ── 13:30 — ordinary office traffic ────────────────────────────────────────── #
baseline(13, 30, 12)

# ── 14:00 — collection then exfiltration ───────────────────────────────────── #
SENSITIVE_PATHS = ["/share/finance/payroll_2026.xlsx", "/share/hr/salary_bands.xlsx",
                   "/share/finance/q3_forecast.xlsx", "/share/hr/employee_records.csv",
                   "/share/finance/vendor_payments.xlsx", "/share/hr/contracts.pdf",
                   "/share/finance/audit_2025.pdf", "/share/hr/reviews.docx",
                   "/share/finance/tax_filings.pdf", "/share/hr/onboarding.xlsx",
                   "/share/finance/budget_2027.xlsx", "/share/hr/exit_interviews.docx",
                   "/share/finance/bank_details.csv", "/share/hr/passport_scans.pdf"]
for i, path in enumerate(SENSITIVE_PATHS):
    add(DAY + timedelta(hours=14, minutes=0, seconds=i * 17),
        ATTACKER_EXFIL, "file_access", "high",
        "Data exfiltration", "suspicious",
        user="finance_svc", path=path, dest_ip="10.0.0.15",
        status="SUCCESS", protocol="SMB", bytes=1_200_000 + i * 9000,
        message=f"Read {path}")
add(DAY + timedelta(hours=14, minutes=4, seconds=30),
    ATTACKER_EXFIL, "data_transfer", "critical",
    "Data exfiltration", "suspicious",
    user="finance_svc", dest_ip="198.51.100.77", dest_port=443,
    protocol="HTTPS", status="SUCCESS", bytes=734_000_000,
    message="Large outbound transfer to an external host")

# ── 14:30 — the day winds down ─────────────────────────────────────────────── #
baseline(14, 30, 14, dest="10.0.0.20")


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
