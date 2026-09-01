# Owner: B1
# Log Analysis Agent — detects anomalies in normalized_logs.csv and
# correlates related rows into incident candidates for the Verification Agent.
"""Log Analysis Agent (Agent 1) for SIH26S01.

Pipeline position:
    THIS AGENT -> Verification Agent (B2) -> Threat Investigation Agent (B2) -> Report/Dashboard

Input contract (``data/normalized_logs.csv``, produced by D3)::

    row_id,timestamp,source,event_type,severity,raw_fields,source_file

    row_id      stable unique id for the row -- the Verification Agent looks rows
                up by this value, so it must never be regenerated between runs
    timestamp   "YYYY-MM-DD HH:MM:SS" (ISO-8601 with 'T' also accepted)
    source      the acting entity, normally the source IP
    event_type  normalized event name, e.g. failed_login / http_request
    severity    info | warning | critical
    raw_fields  JSON object string with the original fields (user, dest_ip,
                dest_port, device, bytes, ...)
    source_file which original CSV the row came from

Output contract (exactly these four keys, consumed by the Verification Agent)::

    {
      "incident_id": "INC-001",
      "theory":      "Repeated failed logins ...",
      "confidence":  0.83,
      "cited_rows":  ["R0013", "R0014"]
    }

Design notes:
  * Phase 1 is fully deterministic -- rule detectors plus correlation, no LLM.
    The live demo can therefore never fail on a network call.
  * Phase 2 adds a Groq-written theory on top of the same detections; the rule
    output stays as the fallback if the LLM is unavailable.
  * Every incident cites real row_id values only, which is what makes the
    Verification Layer able to prove or disprove the theory.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agents import llm

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = PROJECT_ROOT / "data" / "normalized_logs.csv"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "incidents.json"
ENV_PATH = PROJECT_ROOT / ".env"

REQUIRED_COLUMNS = (
    "row_id", "timestamp", "source", "event_type", "severity", "raw_fields", "source_file",
)

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M",
    # CICIDS2017 ships day-first, sometimes without seconds.
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
)

# --- detector thresholds (tune here, not inside the detectors) -------------- #

BURST_WINDOW = timedelta(minutes=5)      # sliding window for rate-based rules
CORRELATION_WINDOW = timedelta(minutes=10)  # gap that still keeps rows in one incident

FAILED_LOGIN_THRESHOLD = 8     # failed logins from one source inside BURST_WINDOW
PORT_SCAN_THRESHOLD = 10       # distinct destination ports inside BURST_WINDOW
TRAFFIC_SPIKE_THRESHOLD = 20   # absolute floor: events from one source inside BURST_WINDOW
SPIKE_BASELINE_MULTIPLE = 3.0  # ...AND this many times the median source's volume
LARGE_TRANSFER_BYTES = 100_000_000   # single outbound transfer that looks like exfiltration
LATERAL_MOVEMENT_THRESHOLD = 6       # distinct internal hosts touched inside BURST_WINDOW
CREDENTIAL_STUFFING_THRESHOLD = 5    # distinct usernames failing from one source
MASS_FILE_ACCESS_THRESHOLD = 12      # file reads from one source inside BURST_WINDOW
ACCESS_DENIED_THRESHOLD = 6          # permission denials from one source inside BURST_WINDOW
CONFIG_CHANGE_THRESHOLD = 3          # config changes from one source inside BURST_WINDOW
DNS_QUERY_LENGTH = 50                # query name length that suggests DNS tunneling
DNS_TUNNELING_THRESHOLD = 8          # long DNS queries inside BURST_WINDOW

# --- flow-level thresholds (CICIDS2017-style NetFlow rows from D1) ---------- #
SYN_FLOOD_THRESHOLD = 20             # half-open flows from one source inside BURST_WINDOW
PACKET_RATE_THRESHOLD = 5_000.0      # packets/s in a single flow that looks like a flood
# ...but packets/s is derived (packets / duration), so a 3-packet flow lasting
# 4 microseconds reports 666,667 packets/s and is not a flood at all. Measured
# against the labelled CICIDS subset, the rate alone was BENIGN 90% of the time
# (1031/1142 hits) and the triggering flows had a median of 3 packets. Require
# enough packets for the rate to mean anything.
PACKET_RATE_MIN_PACKETS = 20         # flow must carry this many packets before its rate counts
ONE_WAY_FLOW_THRESHOLD = 15          # unanswered flows inside BURST_WINDOW (scan signature)
# Authentication services. Flow records carry no auth outcome, so a credential
# attack cannot reach detect_brute_force on NetFlow data -- what survives is the
# shape: one source hammering one auth port. This is the FTP-Patator (21) and
# SSH-Patator (22) signature in CICIDS2017.
AUTH_SERVICE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP"}
# Credential attacks are paced deliberately to stay under burst detection: in
# the CICIDS subset both Patator campaigns run for a full hour and never put
# more than 18 flows into any 5-minute window. So this detector gets its own,
# much longer window instead of the shared BURST_WINDOW.
AUTH_FLOOD_WINDOW = timedelta(minutes=30)
AUTH_FLOOD_THRESHOLD = 20            # flows to one auth port inside AUTH_FLOOD_WINDOW
ONE_WAY_MAX_BWD_PACKETS = 1          # a flow with no real reply

# Strict gate: an incident must clear this combined confidence to be reported.
# One weak signal on its own is noise; we want corroboration before we alarm.
MIN_INCIDENT_CONFIDENCE = 0.50

OFF_HOURS_START = 0            # inclusive hour
OFF_HOURS_END = 5              # exclusive hour
LOGIN_EVENTS = ("login_success", "login", "auth_success")
FAILED_LOGIN_EVENTS = ("failed_login", "login_failed", "auth_failure")
TRANSFER_EVENTS = ("data_transfer", "file_upload", "data_exfiltration")
DENIED_EVENTS = ("access_denied", "permission_denied", "unauthorized_access", "forbidden")
CONFIG_EVENTS = ("config_change", "policy_change", "firewall_change", "setting_change")
PRIVILEGE_EVENTS = ("privilege_escalation", "role_change", "permission_grant", "sudo")
DNS_EVENTS = ("dns_query", "dns_request", "dns")
KNOWN_DEVICE_PREFIXES = ("LAP-", "DESK-", "MOB-")

# Ports that should never be reached from outside the internal network.
HIGH_RISK_PORTS = {23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}

# RFC1918 internal ranges -- anything else counts as external.
INTERNAL_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

# Paths whose contents would hurt if they left the building.
SENSITIVE_PATH_MARKERS = ("payroll", "finance", "salary", "/hr/", "credential",
                          "password", "secret", "private_key", ".pem", "shadow")

# Accounts whose compromise is worse than a normal user's.
PRIVILEGED_USERS = ("admin", "administrator", "root", "sa", "svc_admin", "domain_admin")

# --- rule catalogue: weight drives confidence, text drives the theory ------- #

RULES: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "weight": 0.75,
        "text": "{count} failed logins from {source} within a {window}-minute window",
    },
    "port_scan": {
        "weight": 0.70,
        "text": "{count} distinct destination ports probed by {source} within a {window}-minute window",
    },
    "traffic_spike": {
        "weight": 0.60,
        "text": "{count} requests from {source} within a {window}-minute window, far above the baseline",
    },
    "off_hours_login": {
        "weight": 0.45,
        "text": "login by {source} at {detail}, outside normal working hours",
    },
    "unrecognized_device": {
        "weight": 0.40,
        "text": "activity from unrecognized device '{detail}'",
    },
    "large_outbound_transfer": {
        "weight": 0.80,
        "text": "outbound transfer of {detail} from {source}",
    },
    "success_after_failures": {
        "weight": 0.70,
        "text": "a successful login from {source} immediately after the failed attempts",
    },
    "credential_stuffing": {
        "weight": 0.75,
        "text": "{count} different usernames tried from {source}, consistent with credential stuffing",
    },
    "lateral_movement": {
        "weight": 0.70,
        "text": "{source} reached {count} distinct internal hosts within a {window}-minute window",
    },
    "privilege_escalation": {
        "weight": 0.85,
        "text": "a privilege or role change triggered by {source} ({detail})",
    },
    "privileged_account_targeted": {
        "weight": 0.55,
        "text": "the attempts targeted the privileged account '{detail}'",
    },
    "external_to_high_risk_port": {
        "weight": 0.75,
        "text": "an external host {source} connected to {detail}, which should not be exposed",
    },
    "sensitive_file_access": {
        "weight": 0.60,
        "text": "access to sensitive path '{detail}'",
    },
    "mass_file_access": {
        "weight": 0.65,
        "text": "{count} files read by {source} within a {window}-minute window, consistent with bulk collection",
    },
    "repeated_access_denied": {
        "weight": 0.55,
        "text": "{count} access denials for {source} within a {window}-minute window",
    },
    "config_tampering": {
        "weight": 0.70,
        "text": "{count} configuration changes made by {source} within a {window}-minute window",
    },
    "dns_tunneling": {
        "weight": 0.70,
        "text": "{count} abnormally long DNS queries from {source}, a common covert-channel pattern",
    },
    "off_hours_transfer": {
        "weight": 0.65,
        "text": "a data transfer at {detail}, well outside working hours",
    },
    "syn_flood": {
        "weight": 0.80,
        "text": "{count} half-open SYN flows from {source} within a {window}-minute window",
    },
    "high_packet_rate": {
        "weight": 0.70,
        "text": "a flow from {source} sustained {detail}, far above normal traffic",
    },
    "unanswered_flows": {
        "weight": 0.65,
        "text": "{count} flows from {source} received no reply, the signature of a sweep",
    },
    "auth_service_flood": {
        "weight": 0.80,
        "text": "{count} connection attempts from {source} into {detail}, a paced credential attack",
    },
}

# MITRE ATT&CK mapping, one entry per rule: (tactic id, tactic, technique id, technique).
# Defense SOC teams triage by tactic, so every detection carries its place in
# the kill chain rather than only a free-text theory.
MITRE_MAP: Dict[str, Tuple[str, str, str, str]] = {
    "brute_force":                 ("TA0006", "Credential Access", "T1110", "Brute Force"),
    "credential_stuffing":         ("TA0006", "Credential Access", "T1110.004", "Credential Stuffing"),
    "auth_service_flood":          ("TA0006", "Credential Access", "T1110.001", "Password Guessing"),
    "success_after_failures":      ("TA0006", "Credential Access", "T1110", "Brute Force"),
    "privileged_account_targeted": ("TA0006", "Credential Access", "T1078.002", "Domain Accounts"),
    "repeated_access_denied":      ("TA0006", "Credential Access", "T1110", "Brute Force"),
    "port_scan":                   ("TA0007", "Discovery", "T1046", "Network Service Discovery"),
    "unanswered_flows":            ("TA0007", "Discovery", "T1046", "Network Service Discovery"),
    "lateral_movement":            ("TA0008", "Lateral Movement", "T1021", "Remote Services"),
    "external_to_high_risk_port":  ("TA0001", "Initial Access", "T1133", "External Remote Services"),
    "off_hours_login":             ("TA0001", "Initial Access", "T1078", "Valid Accounts"),
    "unrecognized_device":         ("TA0001", "Initial Access", "T1078", "Valid Accounts"),
    "privilege_escalation":        ("TA0004", "Privilege Escalation", "T1078", "Valid Accounts"),
    "config_tampering":            ("TA0005", "Defense Evasion", "T1562.001", "Disable or Modify Tools"),
    "mass_file_access":            ("TA0009", "Collection", "T1005", "Data from Local System"),
    "sensitive_file_access":       ("TA0009", "Collection", "T1005", "Data from Local System"),
    "large_outbound_transfer":     ("TA0010", "Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    "off_hours_transfer":          ("TA0010", "Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    "dns_tunneling":               ("TA0011", "Command and Control", "T1071.004", "DNS"),
    "syn_flood":                   ("TA0040", "Impact", "T1498.001", "Direct Network Flood"),
    "traffic_spike":               ("TA0040", "Impact", "T1498", "Network Denial of Service"),
    "high_packet_rate":            ("TA0040", "Impact", "T1498", "Network Denial of Service"),
}


def mitre_for_rules(rules: List[str]) -> List[Dict[str, str]]:
    """Distinct MITRE entries for the rules that fired, ordered by tactic id."""
    seen: Dict[str, Dict[str, str]] = {}
    for rule in rules:
        entry = MITRE_MAP.get(rule)
        if entry is None:
            continue
        tactic_id, tactic, technique_id, technique = entry
        seen[technique_id] = {
            "tactic_id": tactic_id, "tactic": tactic,
            "technique_id": technique_id, "technique": technique,
        }
    return sorted(seen.values(), key=lambda m: (m["tactic_id"], m["technique_id"]))

MAX_CONFIDENCE = 0.95

# Supporting-only rules: real context once an attack is already suspected, but
# far too common on their own (an HR file read at 3pm is just someone working).
# They add confidence to a cluster, they never raise an incident by themselves.
SUPPORTING_ONLY_RULES = frozenset({
    "sensitive_file_access",
    "privileged_account_targeted",
    "unrecognized_device",
    # A fast flow is meaningful next to a scan or a flood, but on its own it is
    # the single noisiest signal in the flow data -- see PACKET_RATE_MIN_PACKETS.
    "high_packet_rate",
})

# --- Phase 2: LLM settings -------------------------------------------------- #

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

LLM_TIMEOUT_SECONDS = 20
LLM_MAX_EVIDENCE_ROWS = 8    # rows sent to the model per incident, keeps prompts small
LLM_MAX_WORKERS = int(os.getenv("LLM_MAX_WORKERS", "4"))  # concurrent calls; free tiers cap tokens per minute
LLM_MAX_INCIDENTS = int(os.getenv("LLM_MAX_INCIDENTS", "8"))  # most-confident clusters given an LLM theory
LLM_CONFIDENCE_SHIFT = 0.15  # how far the model may move the rule-based confidence


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #

def load_env(env_path: Optional[Path] = None) -> None:
    """Load GROQ_API_KEY from the project .env file.

    Uses python-dotenv when installed, otherwise a tiny KEY=VALUE parser so the
    agent still runs with no extra dependency. Real environment values win.
    """
    path = Path(env_path or ENV_PATH)
    try:
        from dotenv import load_dotenv
        load_dotenv(path, override=False)
        return
    except ImportError:
        pass

    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lstrip("﻿")
        if key.lower().startswith("export "):
            key = key[7:].strip()
        os.environ.setdefault(key, value.strip().strip('"').strip("'"))


load_env()



# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

class LogFormatError(ValueError):
    """Raised when the normalized log file does not match the agreed schema."""


def _parse_timestamp(value: str) -> Optional[datetime]:
    """Parse a timestamp using the accepted formats; None if none of them fit."""
    value = (value or "").strip()
    if not value:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _parse_raw_fields(value: str) -> Dict[str, Any]:
    """Decode the raw_fields JSON column; an unreadable value becomes {}."""
    value = (value or "").strip()
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def load_logs(log_path: Path | str = DEFAULT_LOG_PATH) -> List[Dict[str, Any]]:
    """Read the normalized log file into memory, sorted by timestamp.

    Rows with an unparseable timestamp are skipped rather than crashing the run:
    a malformed row must never take down the demo.
    """
    path = Path(log_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Normalized log file not found: {path}. "
            "D3 produces this file; see data/README.md."
        )

    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise LogFormatError(
                f"{path} is missing required column(s): {', '.join(missing)}. "
                f"Expected schema: {', '.join(REQUIRED_COLUMNS)}"
            )

        rows: List[Dict[str, Any]] = []
        for record in reader:
            timestamp = _parse_timestamp(record.get("timestamp", ""))
            if timestamp is None or not (record.get("row_id") or "").strip():
                continue
            rows.append({
                "row_id": record["row_id"].strip(),
                "timestamp": timestamp,
                "source": (record.get("source") or "").strip(),
                "event_type": (record.get("event_type") or "").strip().lower(),
                "severity": (record.get("severity") or "").strip().lower(),
                "raw_fields": _parse_raw_fields(record.get("raw_fields", "")),
                "source_file": (record.get("source_file") or "").strip(),
            })

    rows.sort(key=lambda r: r["timestamp"])
    return rows


# --------------------------------------------------------------------------- #
# Detection primitives
# --------------------------------------------------------------------------- #

# A finding is one rule firing on one or more rows.
#   rule    -> key into RULES
#   rows    -> row_id values that justify the finding
#   source  -> the acting entity the finding is about
#   count   -> how many rows/ports/requests triggered it (0 when not counting)
#   detail  -> free-text slot used by rules whose text needs a value
Finding = Dict[str, Any]


def _finding(rule: str, source: str, rows: List[str], count: int = 0, detail: str = "") -> Finding:
    return {"rule": rule, "source": source, "rows": rows, "count": count, "detail": detail}


def _group_by_source(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["source"], []).append(row)
    return grouped


def _sliding_windows(rows: List[Dict[str, Any]], window: timedelta):
    """Yield each maximal run of rows that starts at index i and fits in `window`."""
    for start in range(len(rows)):
        end = start
        while end + 1 < len(rows) and rows[end + 1]["timestamp"] - rows[start]["timestamp"] <= window:
            end += 1
        yield rows[start:end + 1]


def _best_window(rows: List[Dict[str, Any]], window: timedelta, key=len) -> List[Dict[str, Any]]:
    """Return the window with the highest `key` score, or [] when there are no rows."""
    best: List[Dict[str, Any]] = []
    best_score = 0
    for candidate in _sliding_windows(rows, window):
        score = key(candidate)
        if score > best_score:
            best, best_score = candidate, score
    return best


# --------------------------------------------------------------------------- #
# Rule detectors -- each takes the full log and returns findings
# --------------------------------------------------------------------------- #

def detect_brute_force(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Many failed logins from one source inside a short window."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        failures = [r for r in source_rows if r["event_type"] in FAILED_LOGIN_EVENTS]
        window = _best_window(failures, BURST_WINDOW)
        if len(window) >= FAILED_LOGIN_THRESHOLD:
            findings.append(_finding(
                "brute_force", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


def detect_success_after_failures(rows: List[Dict[str, Any]]) -> List[Finding]:
    """A successful login right after a burst of failures -- possible takeover."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        failures = [r for r in source_rows if r["event_type"] in FAILED_LOGIN_EVENTS]
        if len(failures) < FAILED_LOGIN_THRESHOLD:
            continue
        last_failure = failures[-1]["timestamp"]
        for row in source_rows:
            if row["event_type"] in LOGIN_EVENTS and 0 <= (row["timestamp"] - last_failure).total_seconds() <= BURST_WINDOW.total_seconds():
                findings.append(_finding("success_after_failures", source, [row["row_id"]]))
                break
    return findings


def detect_port_scan(rows: List[Dict[str, Any]]) -> List[Finding]:
    """One source probing many distinct destination ports in a short window."""
    def distinct_ports(window: List[Dict[str, Any]]) -> int:
        return len({r["raw_fields"].get("dest_port") for r in window if r["raw_fields"].get("dest_port") is not None})

    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        probes = [r for r in source_rows if r["raw_fields"].get("dest_port") is not None]
        window = _best_window(probes, BURST_WINDOW, key=distinct_ports)
        ports = distinct_ports(window)
        if ports >= PORT_SCAN_THRESHOLD:
            findings.append(_finding(
                "port_scan", source, [r["row_id"] for r in window], count=ports,
            ))
    return findings


def detect_traffic_spike(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Volume from one source far above what the rest of the log is doing.

    A fixed count cannot work across both event logs and NetFlow rows -- 20
    events in five minutes is an attack in one and idle chatter in the other.
    So a source must clear BOTH an absolute floor and a multiple of the median
    source's volume. The rule therefore re-tunes itself to whatever data D1 and
    D3 hand over, instead of needing a magic number per dataset.
    """
    busiest = {
        source: _best_window(source_rows, BURST_WINDOW)
        for source, source_rows in _group_by_source(rows).items()
    }
    volumes = sorted(len(w) for w in busiest.values())
    if not volumes:
        return []
    median = volumes[len(volumes) // 2] or 1
    floor = max(TRAFFIC_SPIKE_THRESHOLD, SPIKE_BASELINE_MULTIPLE * median)

    return [
        _finding("traffic_spike", source, [r["row_id"] for r in window], count=len(window))
        for source, window in busiest.items()
        if len(window) >= floor
    ]


def detect_off_hours_login(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Successful logins during the configured off-hours band."""
    findings: List[Finding] = []
    for row in rows:
        if row["event_type"] in LOGIN_EVENTS and OFF_HOURS_START <= row["timestamp"].hour < OFF_HOURS_END:
            findings.append(_finding(
                "off_hours_login", row["source"], [row["row_id"]],
                detail=row["timestamp"].strftime("%H:%M on %Y-%m-%d"),
            ))
    return findings


def detect_unrecognized_device(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Activity from a device name that does not match any known naming prefix."""
    findings: List[Finding] = []
    for row in rows:
        device = str(row["raw_fields"].get("device") or "").strip()
        if device and not device.upper().startswith(KNOWN_DEVICE_PREFIXES):
            findings.append(_finding(
                "unrecognized_device", row["source"], [row["row_id"]], detail=device,
            ))
    return findings


def detect_large_outbound_transfer(rows: List[Dict[str, Any]]) -> List[Finding]:
    """A single transfer big enough to look like data leaving the network."""
    findings: List[Finding] = []
    for row in rows:
        if row["event_type"] not in TRANSFER_EVENTS:
            continue
        try:
            transferred = int(row["raw_fields"].get("bytes", 0))
        except (TypeError, ValueError):
            continue
        if transferred >= LARGE_TRANSFER_BYTES:
            findings.append(_finding(
                "large_outbound_transfer", row["source"], [row["row_id"]],
                count=transferred, detail=f"{transferred / 1_000_000:.1f} MB",
            ))
    return findings


def detect_credential_stuffing(rows: List[Dict[str, Any]]) -> List[Finding]:
    """One source failing against many different usernames -- stolen-list replay."""
    def distinct_users(window: List[Dict[str, Any]]) -> int:
        return len({str(r["raw_fields"].get("user") or "").lower() for r in window if r["raw_fields"].get("user")})

    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        failures = [r for r in source_rows if r["event_type"] in FAILED_LOGIN_EVENTS]
        window = _best_window(failures, BURST_WINDOW, key=distinct_users)
        users = distinct_users(window)
        if users >= CREDENTIAL_STUFFING_THRESHOLD:
            findings.append(_finding(
                "credential_stuffing", source, [r["row_id"] for r in window], count=users,
            ))
    return findings


def detect_lateral_movement(rows: List[Dict[str, Any]]) -> List[Finding]:
    """One internal host fanning out to many other internal hosts."""
    def distinct_hosts(window: List[Dict[str, Any]]) -> int:
        return len({d for r in window
                    if (d := str(r["raw_fields"].get("dest_ip") or "")).startswith(INTERNAL_PREFIXES)})

    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        if not source.startswith(INTERNAL_PREFIXES):
            continue  # an external source fanning out is a scan, not lateral movement
        window = _best_window(source_rows, BURST_WINDOW, key=distinct_hosts)
        hosts = distinct_hosts(window)
        if hosts >= LATERAL_MOVEMENT_THRESHOLD:
            findings.append(_finding(
                "lateral_movement", source, [r["row_id"] for r in window], count=hosts,
            ))
    return findings


def detect_privilege_escalation(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Any event that grants or changes privileges -- always worth a look."""
    findings: List[Finding] = []
    for row in rows:
        if row["event_type"] in PRIVILEGE_EVENTS:
            user = str(row["raw_fields"].get("user") or "unknown user")
            findings.append(_finding(
                "privilege_escalation", row["source"], [row["row_id"]], detail=f"user {user}",
            ))
    return findings


def detect_privileged_account_targeted(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Failed logins aimed at an admin-class account.

    On its own this is only a supporting signal -- it is designed to combine
    with brute_force rather than raise an incident by itself.
    """
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        for user in PRIVILEGED_USERS:
            hits = [r for r in source_rows
                    if r["event_type"] in FAILED_LOGIN_EVENTS
                    and str(r["raw_fields"].get("user") or "").lower() == user]
            if hits:
                findings.append(_finding(
                    "privileged_account_targeted", source,
                    [r["row_id"] for r in hits], count=len(hits), detail=user,
                ))
    return findings


def detect_external_to_high_risk_port(rows: List[Dict[str, Any]]) -> List[Finding]:
    """An outside address touching a port that should never leave the LAN."""
    findings: List[Finding] = []
    for row in rows:
        if row["source"].startswith(INTERNAL_PREFIXES):
            continue
        try:
            port = int(row["raw_fields"].get("dest_port"))
        except (TypeError, ValueError):
            continue
        if port in HIGH_RISK_PORTS:
            findings.append(_finding(
                "external_to_high_risk_port", row["source"], [row["row_id"]],
                count=port, detail=f"port {port} ({HIGH_RISK_PORTS[port]})",
            ))
    return findings


def detect_sensitive_file_access(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Reads against payroll, HR, credential or key material."""
    findings: List[Finding] = []
    for row in rows:
        path = str(row["raw_fields"].get("path") or "")
        if path and any(marker in path.lower() for marker in SENSITIVE_PATH_MARKERS):
            findings.append(_finding(
                "sensitive_file_access", row["source"], [row["row_id"]], detail=path,
            ))
    return findings


def detect_mass_file_access(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Bulk file reads from one source -- staging data before exfiltration."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        reads = [r for r in source_rows if r["raw_fields"].get("path")]
        window = _best_window(reads, BURST_WINDOW)
        if len(window) >= MASS_FILE_ACCESS_THRESHOLD:
            findings.append(_finding(
                "mass_file_access", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


def detect_repeated_access_denied(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Someone repeatedly hitting a wall -- probing what they can reach."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        denials = [r for r in source_rows if r["event_type"] in DENIED_EVENTS]
        window = _best_window(denials, BURST_WINDOW)
        if len(window) >= ACCESS_DENIED_THRESHOLD:
            findings.append(_finding(
                "repeated_access_denied", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


def detect_config_tampering(rows: List[Dict[str, Any]]) -> List[Finding]:
    """A burst of configuration changes, e.g. quietly opening the firewall."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        changes = [r for r in source_rows if r["event_type"] in CONFIG_EVENTS]
        window = _best_window(changes, BURST_WINDOW)
        if len(window) >= CONFIG_CHANGE_THRESHOLD:
            findings.append(_finding(
                "config_tampering", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


def detect_dns_tunneling(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Many oversized DNS queries -- data smuggled inside lookup names."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        long_queries = [
            r for r in source_rows
            if r["event_type"] in DNS_EVENTS
            and len(str(r["raw_fields"].get("query") or "")) >= DNS_QUERY_LENGTH
        ]
        window = _best_window(long_queries, BURST_WINDOW)
        if len(window) >= DNS_TUNNELING_THRESHOLD:
            findings.append(_finding(
                "dns_tunneling", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


def detect_off_hours_transfer(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Data moving out while nobody is supposed to be working."""
    findings: List[Finding] = []
    for row in rows:
        if row["event_type"] in TRANSFER_EVENTS and OFF_HOURS_START <= row["timestamp"].hour < OFF_HOURS_END:
            findings.append(_finding(
                "off_hours_transfer", row["source"], [row["row_id"]],
                detail=row["timestamp"].strftime("%H:%M on %Y-%m-%d"),
            ))
    return findings


def _number(row: Dict[str, Any], *names: str) -> Optional[float]:
    """Read the first present numeric raw_field, tolerating string values."""
    for name in names:
        value = row["raw_fields"].get(name)
        if value in (None, ""):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if number == number and abs(number) != float("inf"):  # drop NaN/inf
            return number
    return None


def detect_syn_flood(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Many SYNs from one source that never complete -- SYN flood or SYN scan.

    Flow-level rule: works on the CICIDS2017 columns D1 keeps.
    """
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        half_open = [
            r for r in source_rows
            if (_number(r, "syn_flag_count") or 0) >= 1
            and (_number(r, "bwd_packets") or 0) <= ONE_WAY_MAX_BWD_PACKETS
        ]
        window = _best_window(half_open, BURST_WINDOW)
        if len(window) >= SYN_FLOOD_THRESHOLD:
            findings.append(_finding(
                "syn_flood", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


def detect_high_packet_rate(rows: List[Dict[str, Any]]) -> List[Finding]:
    """A single flow pushing packets far faster than any user session would.

    Guarded by PACKET_RATE_MIN_PACKETS: a high rate computed from a handful of
    packets is a duration-rounding artifact, not a flood.
    """
    findings: List[Finding] = []
    for row in rows:
        rate = _number(row, "flow_packets_per_s")
        if rate is None or rate < PACKET_RATE_THRESHOLD:
            continue
        packets = (_number(row, "fwd_packets") or 0) + (_number(row, "bwd_packets") or 0)
        if packets < PACKET_RATE_MIN_PACKETS:
            continue
        findings.append(_finding(
            "high_packet_rate", row["source"], [row["row_id"]],
            count=int(rate), detail=f"{rate:,.0f} packets/s over {int(packets)} packets",
        ))
    return findings


def detect_auth_service_flood(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Repeated flows from one source into a single authentication service.

    Complements detect_brute_force, which needs a failed_login event type that
    flow data never has. See AUTH_SERVICE_PORTS.
    """
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        by_port: Dict[int, List[Dict[str, Any]]] = {}
        for row in source_rows:
            try:
                port = int(row["raw_fields"].get("dest_port"))
            except (TypeError, ValueError):
                continue
            if port in AUTH_SERVICE_PORTS:
                by_port.setdefault(port, []).append(row)

        for port, hits in by_port.items():
            window = _best_window(hits, AUTH_FLOOD_WINDOW)
            if len(window) >= AUTH_FLOOD_THRESHOLD:
                findings.append(_finding(
                    "auth_service_flood", source, [r["row_id"] for r in window],
                    count=len(window),
                    detail=f"{AUTH_SERVICE_PORTS[port]} (port {port})",
                ))
    return findings


def detect_unanswered_flows(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Flows that got no reply -- what a host sweep looks like at flow level."""
    findings: List[Finding] = []
    for source, source_rows in _group_by_source(rows).items():
        silent = [
            r for r in source_rows
            if (_number(r, "fwd_packets") or 0) >= 1
            and (_number(r, "bwd_packets") or 0) <= ONE_WAY_MAX_BWD_PACKETS
        ]
        window = _best_window(silent, BURST_WINDOW)
        if len(window) >= ONE_WAY_FLOW_THRESHOLD:
            findings.append(_finding(
                "unanswered_flows", source, [r["row_id"] for r in window], count=len(window),
            ))
    return findings


DETECTORS = (
    detect_brute_force,
    detect_success_after_failures,
    detect_credential_stuffing,
    detect_privileged_account_targeted,
    detect_port_scan,
    detect_external_to_high_risk_port,
    detect_traffic_spike,
    detect_lateral_movement,
    detect_privilege_escalation,
    detect_off_hours_login,
    detect_off_hours_transfer,
    detect_unrecognized_device,
    detect_sensitive_file_access,
    detect_mass_file_access,
    detect_repeated_access_denied,
    detect_config_tampering,
    detect_dns_tunneling,
    detect_large_outbound_transfer,
    # flow-level (CICIDS2017)
    detect_syn_flood,
    detect_high_packet_rate,
    detect_unanswered_flows,
    detect_auth_service_flood,
)


def run_detectors(rows: List[Dict[str, Any]]) -> List[Finding]:
    """Run every detector over the log and return the combined findings."""
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(rows))
    return findings


# --------------------------------------------------------------------------- #
# Correlation -- many findings become few incidents
# --------------------------------------------------------------------------- #

def _finding_span(finding: Finding, index: Dict[str, Dict[str, Any]]) -> Tuple[datetime, datetime]:
    times = [index[r]["timestamp"] for r in finding["rows"] if r in index]
    return (min(times), max(times)) if times else (datetime.min, datetime.min)


def correlate(findings: List[Finding], rows: List[Dict[str, Any]]) -> List[List[Finding]]:
    """Merge findings that share a source and sit close together in time.

    Without this step a brute-force burst would be reported as ten separate
    events. With it, all of the evidence lands in one incident an analyst can
    actually read.
    """
    index = {row["row_id"]: row for row in rows}
    clusters: List[List[Finding]] = []

    for source in sorted({f["source"] for f in findings}):
        source_findings = sorted(
            (f for f in findings if f["source"] == source),
            key=lambda f: _finding_span(f, index)[0],
        )
        current: List[Finding] = []
        current_end: Optional[datetime] = None

        for finding in source_findings:
            start, end = _finding_span(finding, index)
            if current and current_end is not None and start - current_end > CORRELATION_WINDOW:
                clusters.append(current)
                current = []
            current.append(finding)
            current_end = end if current_end is None else max(current_end, end)

        if current:
            clusters.append(current)

    return clusters


# --------------------------------------------------------------------------- #
# Incident assembly
# --------------------------------------------------------------------------- #

def score_confidence(cluster: List[Finding]) -> float:
    """Combine rule weights so that independent signals reinforce each other.

    Uses a noisy-OR: confidence = 1 - prod(1 - weight) over the DISTINCT rules
    that fired. Two weak-but-different signals therefore beat one weak signal
    repeated, and no single rule can reach certainty on its own.
    """
    residual = 1.0
    for rule in {f["rule"] for f in cluster}:
        residual *= (1.0 - RULES[rule]["weight"])
    return round(min(1.0 - residual, MAX_CONFIDENCE), 2)


def build_theory(cluster: List[Finding]) -> str:
    """Write the deterministic, evidence-grounded theory for a cluster.

    Phase 2 replaces this text with a Groq-written version, but keeps this one
    as the fallback -- so the theory is never empty even if the LLM is down.
    """
    source = cluster[0]["source"]
    seen: set[str] = set()
    parts: List[str] = []
    for finding in sorted(cluster, key=lambda f: -RULES[f["rule"]]["weight"]):
        if finding["rule"] in seen:
            continue
        seen.add(finding["rule"])
        parts.append(RULES[finding["rule"]]["text"].format(
            count=finding["count"],
            source=finding["source"],
            detail=finding["detail"],
            window=int(BURST_WINDOW.total_seconds() // 60),
        ))

    if len(parts) == 1:
        body = parts[0]
    else:
        body = "; ".join(parts[:-1]) + f"; and {parts[-1]}"
    return f"Suspicious activity involving {source}: {body}."


# --------------------------------------------------------------------------- #
# Phase 2 -- LLM theory (Groq), grounded against the cited evidence
# --------------------------------------------------------------------------- #

LLM_SYSTEM_PROMPT = (
    "You are a SOC log-analysis assistant. You are given the evidence rows a "
    "deterministic rule engine already flagged, plus the rules that fired. "
    "Write ONE short analyst-grade theory (max 45 words) explaining what the "
    "attacker is most likely doing.\n"
    "HARD RULES:\n"
    "- Use ONLY facts present in the evidence. Never invent an IP, user, port, "
    "row id, time or byte count that is not shown.\n"
    "- Do not recommend an action; another agent does that.\n"
    "Reply with JSON only: {\"theory\": \"...\", \"confidence\": 0.0-1.0}"
)


def _get_groq_client():
    """Historical name. Returns a truthy sentinel when an LLM is usable.

    Provider selection now lives in agents/llm.py; this keeps the existing call
    sites and the --no-llm behaviour unchanged.
    """
    return llm if llm.is_available() else None


def _evidence_digest(cited: List[str], index: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compact, token-cheap view of the evidence rows for the prompt."""
    digest = []
    for row_id in cited[:LLM_MAX_EVIDENCE_ROWS]:
        row = index.get(row_id)
        if not row:
            continue
        digest.append({
            "row_id": row["row_id"],
            "time": row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "source": row["source"],
            "event": row["event_type"],
            "severity": row["severity"],
            "fields": row["raw_fields"],
        })
    return digest


def _is_grounded(theory: str, digest: List[Dict[str, Any]]) -> bool:
    """Reject a theory that names an IP the evidence never mentioned.

    This is the Log Analysis Agent's own hallucination guard. The Verification
    Agent still re-checks everything downstream -- this just stops obviously
    invented text from ever entering the pipeline.
    """
    evidence_text = json.dumps(digest)
    return all(ip in evidence_text for ip in set(IPV4_RE.findall(theory)))


def generate_llm_theory(
    cluster: List[Finding],
    cited: List[str],
    index: Dict[str, Dict[str, Any]],
    client,
) -> Optional[Tuple[str, Optional[float]]]:
    """Ask Groq for a natural-language theory. None on any failure.

    Returning None is not an error path we hide -- the caller simply keeps the
    deterministic theory, so the pipeline output is identical in shape whether
    or not the LLM was reachable.
    """
    digest = _evidence_digest(cited, index)
    payload = {
        "rules_fired": sorted({f["rule"] for f in cluster}),
        "source": cluster[0]["source"],
        "evidence": digest,
    }
    try:
        text, status = llm.complete(LLM_SYSTEM_PROMPT, json.dumps(payload),
                                    max_tokens=250, json_mode=True,
                                    timeout=LLM_TIMEOUT_SECONDS)
        if text is None:
            return None
        parsed = json.loads(text)
    except Exception:
        return None

    theory = str(parsed.get("theory") or "").strip()
    if not theory or not _is_grounded(theory, digest):
        return None

    try:
        confidence = float(parsed["confidence"])
    except (KeyError, TypeError, ValueError):
        confidence = None
    return theory, confidence


def _blend_confidence(rule_confidence: float, llm_confidence: Optional[float]) -> float:
    """Let the model nudge the rule score, never overrule it.

    The deterministic score stays in charge; the LLM can move it by at most
    LLM_CONFIDENCE_SHIFT in either direction. A hallucinating model therefore
    cannot turn a weak signal into a Critical incident.
    """
    if llm_confidence is None or not 0.0 <= llm_confidence <= 1.0:
        return rule_confidence
    low = rule_confidence - LLM_CONFIDENCE_SHIFT
    high = rule_confidence + LLM_CONFIDENCE_SHIFT
    return round(min(max(min(max(llm_confidence, low), high), 0.0), MAX_CONFIDENCE), 2)


def build_incidents(
    rows: List[Dict[str, Any]],
    findings: Optional[List[Finding]] = None,
    use_llm: bool = True,
) -> List[Dict[str, Any]]:
    """Turn raw log rows into the incident candidates the next agent consumes."""
    findings = run_detectors(rows) if findings is None else findings
    index = {row["row_id"]: row for row in rows}
    client = _get_groq_client() if use_llm else None

    incidents: List[Dict[str, Any]] = []
    # (index into incidents, cluster, cited rows) for the optional LLM pass.
    pending: List[Tuple[int, List[Finding], List[str]]] = []
    for cluster in correlate(findings, rows):
        cited = sorted(
            {row_id for finding in cluster for row_id in finding["rows"]},
            key=lambda rid: (index[rid]["timestamp"], rid) if rid in index else (datetime.max, rid),
        )
        if not cited:
            continue

        # Strict gate, two parts: the cluster needs at least one rule that can
        # stand on its own, and the combined score must clear the floor.
        if all(f["rule"] in SUPPORTING_ONLY_RULES for f in cluster):
            continue
        confidence = score_confidence(cluster)
        if confidence < MIN_INCIDENT_CONFIDENCE:
            continue

        pending.append((len(incidents), cluster, cited))
        incidents.append({
            "incident_id": "",  # assigned below, after ordering
            "theory": build_theory(cluster),
            "confidence": confidence,
            "cited_rows": cited,
            # Which detectors fired, as data rather than only as prose. The
            # normalized schema flattens every CICIDS flow to
            # event_type=network_flow/severity=info, so the rule names are the
            # only place the attack semantics survive -- the Investigation
            # Agent scores risk from these.
            "rules_fired": sorted({f["rule"] for f in cluster}),
            # Kill-chain position, derived from the same rules.
            "mitre": mitre_for_rules(sorted({f["rule"] for f in cluster})),
        })

    # Optional LLM pass, run concurrently. One round trip per incident done in
    # sequence is seconds each, which reads as a hung dashboard; these calls are
    # independent and I/O-bound, so they overlap cleanly. The deterministic
    # theory written above stays in place for anything the model cannot answer.
    if client is not None and pending:
        from concurrent.futures import ThreadPoolExecutor

        def fetch(job):
            position, cluster, cited = job
            try:
                return position, generate_llm_theory(cluster, cited, index, client)
            except Exception:
                return position, None

        # Highest-confidence clusters first, then only as many as the token
        # budget allows -- the rest keep their deterministic theory.
        pending.sort(key=lambda job: -incidents[job[0]]["confidence"])
        pending = pending[:LLM_MAX_INCIDENTS]

        with ThreadPoolExecutor(max_workers=min(LLM_MAX_WORKERS, len(pending))) as pool:
            for position, result in pool.map(fetch, pending):
                if result is None:
                    continue
                theory, llm_confidence = result
                incidents[position]["theory"] = theory
                incidents[position]["confidence"] = _blend_confidence(
                    incidents[position]["confidence"], llm_confidence)

    # Highest confidence first, so the dashboard's top row is the worst problem.
    incidents.sort(key=lambda inc: (-inc["confidence"], inc["cited_rows"][0]))
    for position, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{position:03d}"
    return incidents


def run_log_analysis(
    log_path: Path | str = DEFAULT_LOG_PATH,
    use_llm: bool = True,
) -> List[Dict[str, Any]]:
    """Entry point for the pipeline (B3) and for the CLI below.

    Returns the list of incident candidates, each with exactly the four keys of
    the output contract. `use_llm=False` forces the deterministic path, which is
    what the live demo should use if the venue's network is unreliable.
    """
    return build_incidents(load_logs(log_path), use_llm=use_llm)


# --------------------------------------------------------------------------- #
# LangGraph node (B3 wires this into the pipeline)
# --------------------------------------------------------------------------- #

def log_analysis_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph-compatible node: reads `log_path`, writes `incidents`.

    A LangGraph node is just a callable taking state and returning state, so
    this needs no langgraph import -- the pipeline module owns the graph.

    State in : {"log_path": str (optional), "use_llm": bool (optional)}
    State out: {..., "incidents": [ {incident_id, theory, confidence, cited_rows} ]}
    """
    log_path = state.get("log_path") or DEFAULT_LOG_PATH
    incidents = run_log_analysis(log_path, use_llm=state.get("use_llm", True))
    return {**state, "log_path": str(log_path), "incidents": incidents}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Log Analysis Agent over a normalized log file.")
    parser.add_argument("--logs", default=str(DEFAULT_LOG_PATH), help="path to normalized_logs.csv")
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT_PATH), help="where to write incidents.json")
    parser.add_argument("--quiet", action="store_true", help="write the file without printing a summary")
    parser.add_argument("--no-llm", action="store_true", help="skip Groq and use the deterministic theory only")
    args = parser.parse_args()

    use_llm = not args.no_llm
    if use_llm and _get_groq_client() is None and not args.quiet:
        print("[info] Groq unavailable (no GROQ_API_KEY or groq package) -- using rule-based theories.\n")

    incidents = run_log_analysis(args.logs, use_llm=use_llm)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(incidents, indent=2), encoding="utf-8")

    if args.quiet:
        return

    print(f"{len(incidents)} incident candidate(s) -> {out_path}\n")
    for incident in incidents:
        print(f"  {incident['incident_id']}  confidence={incident['confidence']:.2f}  "
              f"rows={len(incident['cited_rows'])}")
        print(f"    {incident['theory']}")


if __name__ == "__main__":
    main()
