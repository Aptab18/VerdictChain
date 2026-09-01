# Owner: D3
# Reads raw_subset.csv, anomaly_logs.csv, normal_baseline.csv and converts each
# into the common schema (timestamp, source, event_type, severity, raw_fields,
# source_file), writing the combined output to normalized_logs.csv.
"""D3 - Log Normalizer for SIH26S01 (VerdictChain).

Turns three heterogeneous log sources into ONE common schema that every
downstream agent (B1 Log Analysis -> B2 Verification -> B3 Investigation)
can read without knowing where a row came from.

    data/raw_subset.csv       CICIDS2017 network flows      -> network_flow rows
    data/anomaly_logs.csv     D2 synthetic anomalies        -> host/app event rows
    data/normal_baseline.csv  D2 synthetic clean baseline   -> host/app event rows

Common schema (one row per event)::

    row_id       stable, globally unique id  (D001 / N001 / R000001)
    timestamp    ISO-8601 "YYYY-MM-DDTHH:MM:SS"  (empty if unparseable)
    source       source IP / actor of the event
    event_type   lowercase snake_case event class
    severity     one of: info | low | medium | high | critical
    raw_fields   JSON object, source-specific detail (exact keys per D1 contract)
    source_file  originating file name  (traceability for the Verification Agent)
    source_row   1-based row number inside that file (excluding the header)

Outputs
    data/normalized_logs.csv    canonical artefact, raw_fields is a JSON string
    data/normalized_logs.jsonl  same rows, raw_fields as a real JSON object

Design rules that matter downstream:
  * ``severity`` for CICIDS rows is FIXED to "info" -- it is deliberately NOT
    derived from ``Label``. The Label lives in ``raw_fields.label`` and exists
    only so the team can score detection accuracy after the fact. Deriving
    severity from it would leak the answer into the detector's input.
  * ``event_type`` for CICIDS rows is FIXED to "network_flow".
  * Infinity / NaN (the famous CICIDS "Flow Packets/s" bug) are dropped
    silently: the key is simply absent from raw_fields rather than carrying a
    poison value that would crash json / float() downstream.
  * Every raw_fields key is emitted with the exact name agreed with D1, so the
    rule engine can read them without a translation layer.

Usage
    python data/normalize.py
    python data/normalize.py --data-dir data --out data/normalized_logs.csv
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

CICIDS_FILE = "raw_subset.csv"
# D2 shipped the anomaly file as anomaly_logs.csv; the blueprint calls it
# demo_logs.csv. Accept either so neither team has to rename anything.
DEMO_FILES = ("anomaly_logs.csv", "demo_logs.csv", "demo_logs_200_rows.csv")
BASELINE_FILES = ("normal_baseline.csv", "normal_baseline_200_rows.csv")

OUTPUT_COLUMNS = [
    "row_id",
    "timestamp",
    "source",
    "event_type",
    "severity",
    "raw_fields",
    "source_file",
    "source_row",
]

# CICIDS2017 is day-first ("5/7/2017 15:16") and frequently drops the seconds.
# Formats are tried in order; whatever a format cannot parse is handed to the
# next one, so a file mixing "with seconds" and "without seconds" still works.
TIMESTAMP_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%d-%m-%Y %H:%M:%S",
    "%d/%m/%Y %I:%M:%S %p",
    "%d/%m/%Y %I:%M %p",
]

ISO = "%Y-%m-%dT%H:%M:%S"

# IANA protocol numbers seen in CICIDS2017.
PROTOCOL_NAMES = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_ALIASES = {
    "informational": "info",
    "information": "info",
    "notice": "info",
    "warn": "medium",
    "warning": "medium",
    "error": "high",
    "severe": "high",
    "crit": "critical",
    "fatal": "critical",
}


# --------------------------------------------------------------------------- #
# Scalar helpers
# --------------------------------------------------------------------------- #

def _clean(value: Any) -> Optional[str]:
    """Trim a value to a non-empty string, or None."""
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null", "-"}:
        return None
    return text


def _number(value: Any) -> Optional[float]:
    """Parse a numeric cell, dropping Infinity/NaN instead of propagating them.

    CICIDS2017's "Flow Packets/s" contains Infinity and blank cells for
    zero-duration flows. Returning None here means the key is omitted from
    raw_fields entirely -- downstream float()/json never sees a poison value.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text or text.lower() in {"nan", "none", "null", "-"}:
            return None
        if text.lower().lstrip("+-") in {"inf", "infinity"}:
            return None
        try:
            value = float(text)
        except ValueError:
            return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _int(value: Any) -> Optional[float]:
    """Numeric cell as an int when it is integral, else the float, else None."""
    number = _number(value)
    if number is None:
        return None
    return int(number) if float(number).is_integer() else number


def _snake(value: Any) -> Optional[str]:
    """'NETWORK_REQUEST' / 'Brute Force' -> 'network_request' / 'brute_force'."""
    text = _clean(value)
    if text is None:
        return None
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or None


def _severity(value: Any, default: str = "info") -> str:
    """Map a free-text severity onto the project's five-level scale."""
    text = _snake(value)
    if text is None:
        return default
    text = SEVERITY_ALIASES.get(text, text)
    return text if text in SEVERITY_ORDER else default


def _put(target: Dict[str, Any], key: str, value: Any) -> None:
    """Set ``key`` only when the value is present -- keeps raw_fields clean."""
    if value is not None and value != "":
        target[key] = value


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #

def parse_timestamps(series: pd.Series) -> pd.Series:
    """Parse a timestamp column into datetimes, trying each known format.

    Each format only gets the cells still unparsed by the previous ones, so one
    column may legitimately mix several layouts. Whatever survives that falls
    back to pandas' day-first inference, which is correct for CICIDS2017.
    """
    text = series.astype("string").str.strip()
    best = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns]")

    for fmt in TIMESTAMP_FORMATS:
        missing = best.isna()
        if not missing.any():
            break
        best.loc[missing] = pd.to_datetime(text[missing], format=fmt,
                                           errors="coerce")

    missing = best.isna()
    if missing.any():
        # dayfirst=True: CICIDS2017 is D/M/Y. Harmless for ISO strings.
        best.loc[missing] = pd.to_datetime(text[missing], errors="coerce",
                                           dayfirst=True, format="mixed")
    return best


def _iso(value: Any) -> str:
    """Datetime -> 'YYYY-MM-DDTHH:MM:SS'; unparseable -> '' (never a crash)."""
    if value is None or pd.isna(value):
        return ""
    return pd.Timestamp(value).strftime(ISO)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def read_csv(path: Path) -> pd.DataFrame:
    """Read a CSV and strip the leading/trailing spaces CICIDS puts in headers.

    ``df.columns.str.strip()`` is the very first thing that happens to any
    dataframe in this module -- CICIDS2017 ships columns like ' Source IP' and
    every lookup afterwards assumes the clean name.
    """
    df = pd.read_csv(path, dtype=str, keep_default_na=False, na_values=[""],
                     low_memory=False)
    df.columns = df.columns.str.strip()
    # Belt and braces for the CICIDS Infinity bug in case a caller reads the
    # frame numerically later; _number() already handles the string form.
    df = df.replace([np.inf, -np.inf], np.nan)
    return df


def _find(data_dir: Path, candidates) -> Optional[Path]:
    for name in candidates:
        path = data_dir / name
        if path.exists():
            return path
    return None


# --------------------------------------------------------------------------- #
# Normalizers -- one per source format
# --------------------------------------------------------------------------- #

def normalize_cicids(df: pd.DataFrame, source_file: str) -> List[Dict[str, Any]]:
    """CICIDS2017 network flows -> common schema.

    event_type is fixed to "network_flow" and severity is fixed to "info".
    ``Label`` is carried in raw_fields.label for EVALUATION ONLY -- it must not
    influence severity, or the detector would be grading its own homework.
    """
    timestamps = parse_timestamps(df["Timestamp"]) if "Timestamp" in df else None

    rows: List[Dict[str, Any]] = []
    for position, (_, record) in enumerate(df.iterrows(), start=1):
        raw: Dict[str, Any] = {}

        _put(raw, "dest_ip", _clean(record.get("Destination IP")))
        _put(raw, "dest_port", _int(record.get("Destination Port")))
        _put(raw, "src_port", _int(record.get("Source Port")))

        protocol = _int(record.get("Protocol"))
        _put(raw, "protocol", protocol)
        if isinstance(protocol, int):
            _put(raw, "protocol_name", PROTOCOL_NAMES.get(protocol))

        _put(raw, "fwd_packets", _int(record.get("Total Fwd Packets")))
        _put(raw, "bwd_packets", _int(record.get("Total Backward Packets")))
        _put(raw, "fwd_bytes", _int(record.get("Total Length of Fwd Packets")))
        _put(raw, "bwd_bytes", _int(record.get("Total Length of Bwd Packets")))
        _put(raw, "flow_duration", _int(record.get("Flow Duration")))
        # Infinity / NaN here are dropped by _number(), not forwarded.
        _put(raw, "flow_packets_per_s", _number(record.get("Flow Packets/s")))
        _put(raw, "syn_flag_count", _int(record.get("SYN Flag Count")))
        _put(raw, "label", _clean(record.get("Label")))          # evaluation only

        _put(raw, "timestamp_raw", _clean(record.get("Timestamp")))

        rows.append({
            "row_id": "R{:06d}".format(position),
            "timestamp": _iso(timestamps.iloc[position - 1]) if timestamps is not None else "",
            "source": _clean(record.get("Source IP")) or "",
            "event_type": "network_flow",                        # fixed
            "severity": "info",                                  # fixed
            "raw_fields": raw,
            "source_file": source_file,
            "source_row": position,
        })
    return rows


def normalize_demo(df: pd.DataFrame, source_file: str) -> List[Dict[str, Any]]:
    """D2 synthetic host/application logs (anomaly + baseline) -> common schema.

    These already carry a row_id, an event_type and a severity, so the job is
    to snake_case them onto the project's vocabulary and park the remaining
    columns in raw_fields under stable names.
    """
    timestamps = parse_timestamps(df["timestamp"]) if "timestamp" in df else None

    rows: List[Dict[str, Any]] = []
    for position, (_, record) in enumerate(df.iterrows(), start=1):
        raw: Dict[str, Any] = {}

        _put(raw, "dest_ip", _clean(record.get("destination_ip")))
        _put(raw, "username", _clean(record.get("username")))
        _put(raw, "protocol", _clean(record.get("protocol")))
        _put(raw, "bytes", _int(record.get("bytes")))
        _put(raw, "status", _clean(record.get("status")))
        _put(raw, "device", _clean(record.get("device")))
        _put(raw, "message", _clean(record.get("message")))
        _put(raw, "timestamp_raw", _clean(record.get("timestamp")))

        row_id = _clean(record.get("row_id")) or "{}#{}".format(
            Path(source_file).stem, position)

        rows.append({
            "row_id": row_id,
            "timestamp": _iso(timestamps.iloc[position - 1]) if timestamps is not None else "",
            "source": _clean(record.get("source_ip")) or "",
            "event_type": _snake(record.get("event_type")) or "unknown",
            "severity": _severity(record.get("severity")),
            "raw_fields": raw,
            "source_file": source_file,
            "source_row": position,
        })
    return rows


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def normalize_all(data_dir: Path = DATA_DIR) -> List[Dict[str, Any]]:
    """Normalize every source file found in ``data_dir``, in a stable order."""
    rows: List[Dict[str, Any]] = []

    demo_path = _find(data_dir, DEMO_FILES)
    baseline_path = _find(data_dir, BASELINE_FILES)
    cicids_path = _find(data_dir, (CICIDS_FILE,))

    for path in (demo_path, baseline_path):
        if path is None:
            continue
        rows.extend(normalize_demo(read_csv(path), path.name))

    if cicids_path is not None:
        rows.extend(normalize_cicids(read_csv(cicids_path), cicids_path.name))

    if not rows:
        raise FileNotFoundError(
            "no input logs found in {} (expected {}, {} or {})".format(
                data_dir, DEMO_FILES[0], BASELINE_FILES[0], CICIDS_FILE))
    return rows


def validate(rows: List[Dict[str, Any]]) -> List[str]:
    """Cheap contract checks. Returns a list of human-readable problems."""
    problems: List[str] = []

    seen = Counter(r["row_id"] for r in rows)
    duplicates = [rid for rid, n in seen.items() if n > 1]
    if duplicates:
        problems.append("duplicate row_id(s): {}{}".format(
            ", ".join(duplicates[:5]), " ..." if len(duplicates) > 5 else ""))

    for field in ("row_id", "event_type", "severity", "source_file"):
        blank = sum(1 for r in rows if not r.get(field))
        if blank:
            problems.append("{} blank in {} row(s)".format(field, blank))

    bad_severity = sorted({r["severity"] for r in rows} - set(SEVERITY_ORDER))
    if bad_severity:
        problems.append("severity outside the scale: " + ", ".join(bad_severity))

    no_timestamp = sum(1 for r in rows if not r["timestamp"])
    if no_timestamp:
        problems.append("timestamp unparseable in {} row(s)".format(no_timestamp))

    no_source = sum(1 for r in rows if not r["source"])
    if no_source:
        problems.append("source empty in {} row(s)".format(no_source))

    for row in rows:
        try:
            json.dumps(row["raw_fields"], allow_nan=False)
        except (ValueError, TypeError) as exc:
            problems.append("raw_fields not JSON-safe for {}: {}".format(
                row["row_id"], exc))
            break
    return problems


def write_outputs(rows: List[Dict[str, Any]], csv_path: Path) -> Path:
    """Write normalized_logs.csv (raw_fields as JSON text) and a .jsonl twin."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    flat = [
        {**row, "raw_fields": json.dumps(row["raw_fields"], separators=(",", ":"),
                                         sort_keys=True, allow_nan=False)}
        for row in rows
    ]
    pd.DataFrame(flat, columns=OUTPUT_COLUMNS).to_csv(
        csv_path, index=False, encoding="utf-8")

    jsonl_path = csv_path.with_suffix(".jsonl")
    with jsonl_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":"),
                                    allow_nan=False) + "\n")
    return jsonl_path


def summarize(rows: List[Dict[str, Any]]) -> str:
    """Human-readable summary printed after a run (and pasted into D3 notes)."""
    by_file = Counter(r["source_file"] for r in rows)
    by_event = Counter(r["event_type"] for r in rows)
    by_severity = Counter(r["severity"] for r in rows)
    labels = Counter(r["raw_fields"]["label"] for r in rows
                     if "label" in r["raw_fields"])
    dropped = sum(1 for r in rows
                  if r["event_type"] == "network_flow"
                  and "flow_packets_per_s" not in r["raw_fields"])

    lines = ["normalized {} rows".format(len(rows)), "", "by source_file:"]
    lines += ["  {:<24} {}".format(k, v) for k, v in sorted(by_file.items())]
    lines += ["", "by event_type:"]
    lines += ["  {:<24} {}".format(k, v) for k, v in by_event.most_common()]
    lines += ["", "by severity:"]
    lines += ["  {:<24} {}".format(k, by_severity.get(k, 0))
              for k in SEVERITY_ORDER if by_severity.get(k)]
    if labels:
        lines += ["", "raw_fields.label (evaluation only, not used for severity):"]
        lines += ["  {:<24} {}".format(k, v) for k, v in labels.most_common()]
    lines += ["", "flow_packets_per_s dropped (Infinity/NaN): {}".format(dropped)]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="D3 log normalizer")
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR,
                        help="folder holding the raw CSVs (default: data/)")
    parser.add_argument("--out", type=Path, default=None,
                        help="output CSV (default: <data-dir>/normalized_logs.csv)")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero if any validation problem is found")
    args = parser.parse_args(argv)

    out_path = args.out or (args.data_dir / "normalized_logs.csv")

    rows = normalize_all(args.data_dir)
    problems = validate(rows)
    jsonl_path = write_outputs(rows, out_path)

    print(summarize(rows))
    print("\nwrote {}\nwrote {}".format(out_path, jsonl_path))

    if problems:
        print("\nvalidation warnings:")
        for problem in problems:
            print("  - " + problem)
        if args.strict:
            return 1
    else:
        print("\nvalidation: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
