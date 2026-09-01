# Owner: B1
# Detection-logic tests for the Log Analysis Agent. Run after ANY change:
#     python agents/test_log_analysis_agent.py
#
# scripts/smoke_e2e.py already proves the three agents connect and the contracts
# hold. This file covers the thing only B1 owns: does the detector fire on an
# attack, stay quiet on normal traffic, and cite the WHOLE attack when it does.
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
    BURST_WINDOW,
    DEFAULT_LOG_PATH,
    LogFormatError,
    load_logs,
    log_analysis_node,
    run_log_analysis,
)

RESULTS: list[tuple[bool, str, str]] = []
COLUMNS = ["row_id", "timestamp", "source", "event_type", "severity", "raw_fields", "source_file"]


def check(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((passed, name, detail))


def write_csv(rows: list[dict], path: Path) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def row(row_id: str, when: datetime, source: str, event_type: str, **fields) -> dict:
    return {
        "row_id": row_id,
        "timestamp": when.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "event_type": event_type,
        "severity": "info",
        "raw_fields": json.dumps(fields),
        "source_file": "t.csv",
    }


# --------------------------------------------------------------------------- #
# 1. Output contract the Verification Agent depends on
# --------------------------------------------------------------------------- #

def test_output_contract() -> None:
    incidents = run_log_analysis(DEFAULT_LOG_PATH, use_llm=False)
    check("real log file produces incidents", len(incidents) > 0, f"{len(incidents)} found")

    required = {"incident_id", "theory", "confidence", "cited_rows"}
    missing = [i.get("incident_id") for i in incidents if not required <= set(i)]
    check("every incident carries the 4 contract keys", not missing, f"offenders: {missing}")

    malformed = [
        i["incident_id"] for i in incidents
        if not str(i["theory"]).strip()
        or not isinstance(i["cited_rows"], list) or not i["cited_rows"]
        or not (0.0 <= float(i["confidence"]) <= 1.0)
    ]
    check("theory/confidence/cited_rows are well formed", not malformed, f"offenders: {malformed}")

    ids = [i["incident_id"] for i in incidents]
    check("incident ids are unique", len(ids) == len(set(ids)))

    scores = [i["confidence"] for i in incidents]
    check("incidents are sorted worst-first", scores == sorted(scores, reverse=True), str(scores))

    with open(DEFAULT_LOG_PATH, newline="", encoding="utf-8") as handle:
        known = {r["row_id"] for r in csv.DictReader(handle)}
    invented = [c for i in incidents for c in i["cited_rows"] if c not in known]
    check("no incident cites a row that does not exist", not invented,
          f"{len(invented)} invented citation(s)")

    check("output is JSON serialisable", bool(json.dumps(incidents)))


# --------------------------------------------------------------------------- #
# 2. Detection: fires on attacks, quiet on normal traffic
# --------------------------------------------------------------------------- #

def test_detects_brute_force() -> None:
    base = datetime(2026, 5, 1, 11, 0, 0)
    rows = [row(f"T{i:03d}", base + timedelta(seconds=i * 20), "10.0.0.90", "failed_login",
                user="admin", reason="bad_password") for i in range(12)]

    with tempfile.TemporaryDirectory() as tmp:
        incidents = run_log_analysis(write_csv(rows, Path(tmp) / "b.csv"), use_llm=False)

    check("brute force is detected", len(incidents) == 1, f"{len(incidents)} incident(s)")
    if incidents:
        check("brute force cites all 12 attempts", len(incidents[0]["cited_rows"]) == 12,
              f"cited {len(incidents[0]['cited_rows'])}")
        check("brute force is high confidence", incidents[0]["confidence"] >= 0.75,
              str(incidents[0]["confidence"]))


def test_quiet_traffic_is_ignored() -> None:
    """Normal office activity must raise nothing. This is the strict gate.

    If this ever fails, the agent has started alarming on everything -- the
    single worst thing a judge can find in a live demo.
    """
    base = datetime(2026, 5, 1, 11, 0, 0)
    rows = [
        row(f"Q{host}{i:02d}", base + timedelta(minutes=i * 2), f"10.0.0.{20 + host}",
            "http_request", user=f"user{host}", dest_ip="10.0.0.5", dest_port=443, bytes=1200)
        for host in range(5) for i in range(6)
    ]
    # one isolated failed login -- everybody mistypes a password sometimes
    rows.append(row("Q999", base, "10.0.0.21", "failed_login", user="user1", device="LAP-U1-01"))
    # one sensitive-looking read during work hours -- supporting signal, not an incident
    rows.append(row("Q998", base, "10.0.0.22", "file_access", user="user2",
                    path="/share/hr/policy.pdf"))

    with tempfile.TemporaryDirectory() as tmp:
        incidents = run_log_analysis(write_csv(rows, Path(tmp) / "q.csv"), use_llm=False)

    check("quiet office traffic raises no alarm", not incidents,
          f"{len(incidents)} false incident(s): {[i['theory'][:70] for i in incidents]}")


# --------------------------------------------------------------------------- #
# 3. Recall regression -- a sustained attack must be cited in full
# --------------------------------------------------------------------------- #

def test_sustained_attack_is_cited_in_full() -> None:
    """Guards the bug that put recall at 47%.

    Detectors used to cite only the single busiest window. A flood lasting far
    longer than BURST_WINDOW was still detected, but most of its rows were never
    cited -- which reads as a false negative against labelled ground truth.
    A sustained attack must now cite every row it covers.
    """
    base = datetime(2026, 5, 1, 9, 0, 0)
    span = BURST_WINDOW * 6                      # attack runs six windows long
    attack_rows = 240
    step = span / attack_rows

    rows = [row(f"A{i:04d}", base + step * i, "203.0.113.9", "http_request",
                dest_ip="10.0.0.5", dest_port=80, bytes=90000) for i in range(attack_rows)]
    # quiet background from several hosts, so the relative baseline has something to compare against
    rows += [row(f"N{h}{i:03d}", base + timedelta(seconds=i * 90), f"10.0.0.{30 + h}",
                 "http_request", dest_ip="10.0.0.5", dest_port=443, bytes=1100)
             for h in range(6) for i in range(12)]

    with tempfile.TemporaryDirectory() as tmp:
        incidents = run_log_analysis(write_csv(rows, Path(tmp) / "s.csv"), use_llm=False)

    check("sustained flood is detected", len(incidents) >= 1, f"{len(incidents)} incident(s)")
    if not incidents:
        return

    cited = {c for i in incidents for c in i["cited_rows"]}
    covered = sum(1 for c in cited if c.startswith("A"))
    coverage = covered / attack_rows
    check("sustained flood cites most of the attack, not one window",
          coverage >= 0.90, f"only {coverage:.0%} of {attack_rows} attack rows cited")

    benign_cited = sum(1 for c in cited if c.startswith("N"))
    check("wider citation did not drag in background traffic",
          benign_cited == 0, f"{benign_cited} background row(s) cited")


def test_flow_data_cicids_shape() -> None:
    """CICIDS2017-shaped NetFlow rows: attacks caught, BENIGN flows untouched."""
    base = datetime(2017, 7, 5, 15, 16, 0)
    rows, n = [], 0

    def flow(seconds: int, source: str, **fields) -> None:
        nonlocal n
        n += 1
        stamp = (base + timedelta(seconds=seconds)).strftime("%d/%m/%Y %H:%M:%S")
        rows.append({"row_id": f"F{n:04d}", "timestamp": stamp, "source": source,
                     "event_type": "network_flow", "severity": "info",
                     "raw_fields": json.dumps(fields), "source_file": "raw_subset.csv"})

    for host in range(6):
        for i in range(20):
            flow(i * 10, f"192.168.10.{5 + host}", dest_ip="192.168.10.50", dest_port=443,
                 fwd_packets=12, bwd_packets=10, flow_packets_per_s=18.3,
                 syn_flag_count=1, label="BENIGN")
    for i in range(30):
        flow(400 + i * 3, "172.16.0.1", dest_ip="192.168.10.50", dest_port=80,
             fwd_packets=900, bwd_packets=0, flow_packets_per_s=41000.0,
             syn_flag_count=1, label="DDoS")
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                              443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]):
        flow(900 + i * 2, "172.16.0.9", dest_ip="192.168.10.50", dest_port=port,
             fwd_packets=1, bwd_packets=0, flow_packets_per_s=25.0,
             syn_flag_count=1, label="PortScan")

    with tempfile.TemporaryDirectory() as tmp:
        path = write_csv(rows, Path(tmp) / "f.csv")
        loaded = {r["row_id"]: r for r in load_logs(path)}
        incidents = run_log_analysis(path, use_llm=False)

    check("day-first CICIDS timestamps parse", len(loaded) == len(rows),
          f"{len(loaded)}/{len(rows)} parsed")

    found = {loaded[c]["raw_fields"].get("label")
             for i in incidents for c in i["cited_rows"] if c in loaded}
    check("DDoS is detected in flow data", "DDoS" in found, str(found))
    check("PortScan is detected in flow data", "PortScan" in found, str(found))
    check("no BENIGN flow is accused", "BENIGN" not in found, str(found))


# --------------------------------------------------------------------------- #
# 4. Bad input must never produce a traceback on stage
# --------------------------------------------------------------------------- #

def test_bad_input() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        try:
            load_logs(tmp_path / "nope.csv")
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

        check("empty-but-valid file returns no incidents",
              run_log_analysis(write_csv([], tmp_path / "e.csv"), use_llm=False) == [])

        junk = write_csv([
            {"row_id": "X1", "timestamp": "not-a-date", "source": "1.1.1.1",
             "event_type": "x", "severity": "info", "raw_fields": "{broken", "source_file": "t"},
            {"row_id": "", "timestamp": "2026-01-01 00:00:00", "source": "1.1.1.1",
             "event_type": "x", "severity": "info", "raw_fields": "{}", "source_file": "t"},
        ], tmp_path / "j.csv")
        check("malformed rows are skipped, not fatal", load_logs(junk) == [])


# --------------------------------------------------------------------------- #
# 5. The LangGraph hand-off B3 relies on
# --------------------------------------------------------------------------- #

def test_langgraph_node() -> None:
    state = log_analysis_node({"log_path": str(DEFAULT_LOG_PATH), "use_llm": False,
                               "run_id": "abc"})
    check("node returns incidents in state", isinstance(state.get("incidents"), list))
    check("node passes unknown keys through", state.get("run_id") == "abc")


# --------------------------------------------------------------------------- #

def main() -> int:
    for test in (test_output_contract, test_detects_brute_force, test_quiet_traffic_is_ignored,
                 test_sustained_attack_is_cited_in_full, test_flow_data_cicids_shape,
                 test_bad_input, test_langgraph_node):
        try:
            test()
        except Exception as exc:  # a crashing test is itself a failure
            check(f"{test.__name__} ran without crashing", False, f"{type(exc).__name__}: {exc}")

    print()
    for passed, name, detail in RESULTS:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
              + (f"  -- {detail}" if detail and not passed else ""))

    failed = sum(1 for passed, _, _ in RESULTS if not passed)
    print(f"\n{len(RESULTS) - failed}/{len(RESULTS)} checks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
