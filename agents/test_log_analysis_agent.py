# Owner: B1
# Self-check for the Log Analysis Agent. Run it after ANY change:
#     python agents/test_log_analysis_agent.py
# No pytest needed -- plain Python, prints PASS/FAIL per check.

from __future__ import annotations

import csv
import json
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.log_analysis_agent import (  # noqa: E402
    DEFAULT_LOG_PATH,
    LogFormatError,
    _get_groq_client,
    load_logs,
    log_analysis_node,
    run_log_analysis,
)

RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((passed, name, detail))


def write_csv(rows: list[dict], path: Path) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "row_id", "timestamp", "source", "event_type", "severity", "raw_fields", "source_file",
        ])
        writer.writeheader()
        writer.writerows(rows)
    return path


# --------------------------------------------------------------------------- #
# 1. The real sample file: incidents found, and no clean row accused
# --------------------------------------------------------------------------- #

def test_sample_file() -> None:
    incidents = run_log_analysis(DEFAULT_LOG_PATH, use_llm=False)
    check("sample file produces incidents", len(incidents) > 0, f"{len(incidents)} found")

    with open(DEFAULT_LOG_PATH, newline="", encoding="utf-8") as handle:
        rows = {r["row_id"]: r for r in csv.DictReader(handle)}

    cited = {row_id for inc in incidents for row_id in inc["cited_rows"]}
    unknown = [r for r in cited if r not in rows]
    check("every cited row exists in the CSV", not unknown, f"missing: {unknown}")

    false_positives = [r for r in cited if rows[r]["source_file"] == "normal_baseline.csv"]
    check("no clean baseline row is accused", not false_positives,
          f"{len(false_positives)} false positive(s): {false_positives}")


# --------------------------------------------------------------------------- #
# 2. The output contract B2 depends on
# --------------------------------------------------------------------------- #

def test_output_contract() -> None:
    incidents = run_log_analysis(DEFAULT_LOG_PATH, use_llm=False)
    expected = {"incident_id", "theory", "confidence", "cited_rows"}

    bad_keys = [i["incident_id"] for i in incidents if set(i) != expected]
    check("each incident has exactly the 4 contract keys", not bad_keys, f"offenders: {bad_keys}")

    bad_types = [
        i["incident_id"] for i in incidents
        if not isinstance(i["theory"], str) or not i["theory"].strip()
        or not isinstance(i["cited_rows"], list) or not i["cited_rows"]
        or not (0.0 <= float(i["confidence"]) <= 1.0)
    ]
    check("theory/confidence/cited_rows are well formed", not bad_types, f"offenders: {bad_types}")

    ids = [i["incident_id"] for i in incidents]
    check("incident ids are unique", len(ids) == len(set(ids)))

    confidences = [i["confidence"] for i in incidents]
    check("incidents are sorted worst-first", confidences == sorted(confidences, reverse=True),
          str(confidences))

    check("output is JSON serialisable", bool(json.dumps(incidents)))


# --------------------------------------------------------------------------- #
# 3. Detection quality: attacks caught, quiet traffic ignored
# --------------------------------------------------------------------------- #

def test_detects_brute_force() -> None:
    base = datetime(2026, 5, 1, 11, 0, 0)
    rows = [{
        "row_id": f"T{i:03d}",
        "timestamp": (base + timedelta(seconds=i * 20)).strftime("%Y-%m-%d %H:%M:%S"),
        "source": "10.0.0.90",
        "event_type": "failed_login",
        "severity": "warning",
        "raw_fields": json.dumps({"user": "admin", "reason": "bad_password"}),
        "source_file": "t.csv",
    } for i in range(12)]

    with tempfile.TemporaryDirectory() as tmp:
        path = write_csv(rows, Path(tmp) / "brute.csv")
        incidents = run_log_analysis(path, use_llm=False)

    check("brute force is detected", len(incidents) == 1, f"{len(incidents)} incident(s)")
    if incidents:
        check("brute force cites all 12 attempts", len(incidents[0]["cited_rows"]) == 12,
              f"{len(incidents[0]['cited_rows'])} rows")
        check("brute force is high confidence", incidents[0]["confidence"] >= 0.75,
              str(incidents[0]["confidence"]))


def test_quiet_traffic_is_ignored() -> None:
    """Normal office activity must produce zero incidents -- this is the strict gate."""
    base = datetime(2026, 5, 1, 11, 0, 0)
    rows = []
    for host in range(5):
        for i in range(6):
            rows.append({
                "row_id": f"Q{host}{i:02d}",
                "timestamp": (base + timedelta(minutes=i * 2)).strftime("%Y-%m-%d %H:%M:%S"),
                "source": f"10.0.0.{20 + host}",
                "event_type": "http_request",
                "severity": "info",
                "raw_fields": json.dumps({"user": f"user{host}", "dest_ip": "10.0.0.5",
                                          "dest_port": 443, "bytes": 1200}),
                "source_file": "t.csv",
            })
    # one isolated failed login -- everybody mistypes a password sometimes
    rows.append({
        "row_id": "Q999", "timestamp": base.strftime("%Y-%m-%d %H:%M:%S"),
        "source": "10.0.0.21", "event_type": "failed_login", "severity": "info",
        "raw_fields": json.dumps({"user": "user1", "device": "LAP-U1-01"}), "source_file": "t.csv",
    })

    with tempfile.TemporaryDirectory() as tmp:
        path = write_csv(rows, Path(tmp) / "quiet.csv")
        incidents = run_log_analysis(path, use_llm=False)

    check("quiet office traffic raises no alarm", not incidents,
          f"{len(incidents)} false incident(s): {[i['theory'] for i in incidents]}")


def test_flow_data_cicids_shape() -> None:
    """CICIDS2017-shaped rows from D1: attacks caught, BENIGN flows untouched."""
    base = datetime(2017, 7, 5, 15, 16, 0)

    def stamp(seconds: int) -> str:
        return (base + timedelta(seconds=seconds)).strftime("%d/%m/%Y %H:%M:%S")

    rows, n = [], 0

    def add(ts: str, source: str, fields: dict) -> None:
        nonlocal n
        n += 1
        rows.append({"row_id": f"F{n:04d}", "timestamp": ts, "source": source,
                     "event_type": "network_flow", "severity": "info",
                     "raw_fields": json.dumps(fields), "source_file": "raw_subset.csv"})

    for host in range(6):  # benign background from several hosts
        for i in range(20):
            add(stamp(i * 10), f"192.168.10.{5 + host}",
                {"dest_ip": "192.168.10.50", "dest_port": 443, "fwd_packets": 12,
                 "bwd_packets": 10, "flow_packets_per_s": 18.3, "syn_flag_count": 1,
                 "label": "BENIGN"})
    for i in range(30):  # DDoS
        add(stamp(400 + i * 3), "172.16.0.1",
            {"dest_ip": "192.168.10.50", "dest_port": 80, "fwd_packets": 900,
             "bwd_packets": 0, "flow_packets_per_s": 41000.0, "syn_flag_count": 1,
             "label": "DDoS"})
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                              443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]):
        add(stamp(900 + i * 2), "172.16.0.9",
            {"dest_ip": "192.168.10.50", "dest_port": port, "fwd_packets": 1,
             "bwd_packets": 0, "flow_packets_per_s": 25.0, "syn_flag_count": 1,
             "label": "PortScan"})

    with tempfile.TemporaryDirectory() as tmp:
        path = write_csv(rows, Path(tmp) / "flows.csv")
        loaded = {r["row_id"]: r for r in load_logs(path)}
        incidents = run_log_analysis(path, use_llm=False)

    check("day-first CICIDS timestamps parse", len(loaded) == len(rows),
          f"{len(loaded)}/{len(rows)} rows parsed")

    labels = {
        inc["incident_id"]: {loaded[r]["raw_fields"].get("label") for r in inc["cited_rows"]}
        for inc in incidents
    }
    found = set().union(*labels.values()) if labels else set()
    check("DDoS is detected in flow data", "DDoS" in found, str(labels))
    check("PortScan is detected in flow data", "PortScan" in found, str(labels))

    benign_cited = sum(
        1 for inc in incidents for r in inc["cited_rows"]
        if loaded[r]["raw_fields"].get("label") == "BENIGN"
    )
    check("no BENIGN flow is accused", benign_cited == 0, f"{benign_cited} BENIGN row(s) cited")


# --------------------------------------------------------------------------- #
# 4. It must not crash on bad input -- the demo cannot afford a traceback
# --------------------------------------------------------------------------- #

def test_bad_input() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        try:
            load_logs(tmp_path / "does_not_exist.csv")
            check("missing file raises FileNotFoundError", False)
        except FileNotFoundError:
            check("missing file raises FileNotFoundError", True)

        wrong = tmp_path / "wrong.csv"
        wrong.write_text("alpha,beta\n1,2\n", encoding="utf-8")
        try:
            load_logs(wrong)
            check("wrong columns raise LogFormatError", False)
        except LogFormatError:
            check("wrong columns raise LogFormatError", True)

        empty = write_csv([], tmp_path / "empty.csv")
        check("empty-but-valid file returns no incidents", run_log_analysis(empty, use_llm=False) == [])

        junk = write_csv([
            {"row_id": "X1", "timestamp": "not-a-date", "source": "1.1.1.1",
             "event_type": "x", "severity": "info", "raw_fields": "{broken",
             "source_file": "t.csv"},
            {"row_id": "", "timestamp": "2026-01-01 00:00:00", "source": "1.1.1.1",
             "event_type": "x", "severity": "info", "raw_fields": "{}", "source_file": "t.csv"},
        ], tmp_path / "junk.csv")
        check("malformed rows are skipped, not fatal", load_logs(junk) == [])


# --------------------------------------------------------------------------- #
# 5. The LangGraph hand-off B3 relies on
# --------------------------------------------------------------------------- #

def test_langgraph_node() -> None:
    state = log_analysis_node({"log_path": str(DEFAULT_LOG_PATH), "use_llm": False})
    check("node returns incidents in state", isinstance(state.get("incidents"), list))
    check("node preserves incoming state keys", "log_path" in state and "use_llm" in state)

    passthrough = log_analysis_node({"log_path": str(DEFAULT_LOG_PATH), "use_llm": False, "run_id": "abc"})
    check("node passes unknown keys through", passthrough.get("run_id") == "abc")


# --------------------------------------------------------------------------- #

def main() -> int:
    for test in (test_sample_file, test_output_contract, test_detects_brute_force,
                 test_quiet_traffic_is_ignored, test_flow_data_cicids_shape,
                 test_bad_input, test_langgraph_node):
        try:
            test()
        except Exception as exc:  # a crashing test is itself a failure
            check(f"{test.__name__} ran without crashing", False, f"{type(exc).__name__}: {exc}")

    print()
    for passed, name, detail in RESULTS:
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail and not passed else ""))

    failed = sum(1 for passed, _, _ in RESULTS if not passed)
    print(f"\n{len(RESULTS) - failed}/{len(RESULTS)} checks passed.")

    if _get_groq_client() is None:
        print("\nNote: Groq is not configured, so only the rule-based path was tested.")
        print("      Put a real key in .env, then run:  python agents/log_analysis_agent.py")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
