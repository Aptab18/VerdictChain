"""End-to-end contract smoke test for the SIH26S01 agent chain.

Chains the three agents by hand -- no LangGraph -- and asserts that each
agent's output actually satisfies the next agent's input contract. This is the
safety net: run it after any change to an agent, before touching the pipeline,
the API or the dashboard.

    python scripts/smoke_e2e.py            # full normalized log, no LLM
    python scripts/smoke_e2e.py --llm      # same, but let Groq write theories

Exit code 0 = every contract holds. Non-zero = something downstream will break.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "agents"))

import pandas as pd

from agents import investigation_agent
from agents.log_analysis_agent import run_log_analysis
from agents.verification_agent import load_normalized_logs, verify_incidents
from reports.report_generator import generate_markdown_report

DEFAULT_LOGS = PROJECT_ROOT / "data" / "normalized_logs.csv"

failures: list[str] = []
checks_run = 0


def check(condition: bool, label: str) -> bool:
    """Record one contract assertion. Returns the condition for chaining."""
    global checks_run
    checks_run += 1
    if not condition:
        failures.append(label)
        print(f"  FAIL  {label}")
    return bool(condition)


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", default=str(DEFAULT_LOGS))
    parser.add_argument("--llm", action="store_true",
                        help="allow Groq calls (default: deterministic only)")
    args = parser.parse_args(argv)

    use_llm = args.llm
    log_path = Path(args.logs)

    # ---------------------------------------------------------------- stage 0
    step("Stage 0: normalized log")
    check(log_path.exists(), f"{log_path} exists")
    if not log_path.exists():
        return 1

    first_line = log_path.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0]
    check(not first_line.startswith("<<<<<<<"), "no merge conflict markers in the log file")

    df = pd.read_csv(log_path, dtype=str)
    check("row_id" in df.columns, "log has a row_id column")
    check(df["row_id"].is_unique, "row_id values are unique")
    valid_row_ids = set(df["row_id"])
    print(f"  {len(df)} rows, {df['source_file'].nunique()} source files")

    # ---------------------------------------------------------------- stage 1
    step("Stage 1: Log Analysis Agent -> incident candidates")
    incidents = run_log_analysis(str(log_path), use_llm=use_llm)
    check(len(incidents) > 0, "at least one incident was detected")
    check(len(incidents) < 100, f"incident count is demo-sized (got {len(incidents)})")

    for inc in incidents:
        label = inc.get("incident_id", "?")
        for key in ("incident_id", "theory", "confidence", "cited_rows"):
            check(key in inc, f"{label} has required key '{key}'")
        check(isinstance(inc.get("confidence"), (int, float)),
              f"{label} confidence is numeric")
        check(bool(inc.get("cited_rows")), f"{label} cites at least one row")
        # The whole Verification Layer depends on this being true.
        unknown = [r for r in inc.get("cited_rows", []) if str(r) not in valid_row_ids]
        check(not unknown, f"{label} cites only real row_ids (bad: {unknown[:3]})")
    print(f"  {len(incidents)} incident candidate(s)")

    # ---------------------------------------------------------------- stage 2
    step("Stage 2: Verification Agent -> verified incidents")
    logs_df = load_normalized_logs(str(log_path))
    verified = verify_incidents(incidents, logs_df)
    check(len(verified) == len(incidents), "verification preserves incident count")

    for inc in verified:
        label = inc.get("incident_id", "?")
        for key in ("row_checks", "verified", "confidence", "original_confidence"):
            check(key in inc, f"{label} has verification key '{key}'")
        check(len(inc["row_checks"]) == len(inc["cited_rows"]),
              f"{label} has one check per cited row")
        check(inc["confidence"] <= inc["original_confidence"] + 1e-9,
              f"{label} confidence was never raised by verification")
        for chk in inc["row_checks"]:
            for key in ("row_id", "verified", "exists", "mismatches", "row"):
                check(key in chk, f"{label} row_check has key '{key}'")

    n_verified = sum(1 for i in verified if i["verified"])
    print(f"  {n_verified}/{len(verified)} incidents fully verified")

    # ---------------------------------------------------------------- stage 3
    step("Stage 3: Investigation Agent -> findings")
    findings = investigation_agent.investigate_all(
        verified, log_path=log_path, use_llm=use_llm)
    check(len(findings) == len(verified), "investigation preserves incident count")

    for f in findings:
        label = f.get("incident_id", "?")
        for key in ("incident_id", "risk_level", "risk_score", "explanation",
                    "recommended_action", "evidence", "score_breakdown", "generated_at"):
            check(key in f, f"{label} has finding key '{key}'")
        check(f["risk_level"] in investigation_agent.RISK_LEVELS,
              f"{label} risk_level is one of {investigation_agent.RISK_LEVELS}")
        check(0.0 <= f["risk_score"] <= 1.0, f"{label} risk_score in [0,1]")
        # The problem statement requires recommend-only behaviour.
        check(f["recommended_action"]["auto_executed"] is False,
              f"{label} action is not auto-executed")
        check(len(f["evidence"]) == f["score_breakdown"]["total_rows"],
              f"{label} evidence count matches score_breakdown.total_rows")
        # An incident with zero verified evidence must never be escalated.
        if f["score_breakdown"]["verified_rows"] == 0:
            check(f["risk_level"] in ("Low", "Medium"),
                  f"{label} unverified incident capped at Medium")

    order = [investigation_agent.RISK_LEVELS.index(f["risk_level"]) for f in findings]
    check(order == sorted(order, reverse=True), "findings are sorted worst-first")

    # ---------------------------------------------------------------- stage 4
    step("Stage 4: Report Generator")
    report = generate_markdown_report(findings[0])
    check(findings[0]["incident_id"] in report, "report contains the incident id")
    check("Verified" in report or "Unverified" in report,
          "report shows verification status")
    check(len(report) > 200, "report is non-trivial")

    # ---------------------------------------------------------------- stage 5
    step("Stage 5: Red-team drill — the Verification Layer must catch a lie")
    from agents.redteam_drill import inject_hallucination

    poisoned, info = inject_hallucination(incidents)
    check(info.get("injected") is True, "drill injected false citations")

    drill_findings = investigation_agent.investigate_all(
        verify_incidents(poisoned, logs_df), log_path=log_path, use_llm=False)
    caught = [e for f in drill_findings for e in f["evidence"] if not e["verified"]]

    check(len(caught) >= 2, f"both false citations were caught (got {len(caught)})")
    check(any(not e["exists"] for e in caught), "the ghost row was caught as non-existent")
    check(any(e["mismatches"] for e in caught),
          "the false claim was caught with a field mismatch")
    for evidence_row in caught:
        for mismatch in evidence_row["mismatches"]:
            check(mismatch.get("claimed") != mismatch.get("actual"),
                  "mismatch records a real difference between claim and log")
    print(f"  {len(caught)} false citation(s) caught, "
          f"{sum(len(e['mismatches']) for e in caught)} field mismatch(es) recorded")

    # ---------------------------------------------------------------- summary
    step("Summary")
    by_level: dict[str, int] = {}
    for f in findings:
        by_level[f["risk_level"]] = by_level.get(f["risk_level"], 0) + 1
    total_ev = sum(len(f["evidence"]) for f in findings)
    ok_ev = sum(1 for f in findings for e in f["evidence"] if e["verified"])

    print(f"  incidents        : {len(findings)}")
    print(f"  risk levels      : {by_level}")
    print(f"  evidence rows    : {ok_ev}/{total_ev} verified")
    print(f"  contract checks  : {checks_run - len(failures)}/{checks_run} passed")

    if failures:
        print(f"\n{len(failures)} CONTRACT FAILURE(S):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\nAll contracts hold. Safe to build the pipeline on top.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
