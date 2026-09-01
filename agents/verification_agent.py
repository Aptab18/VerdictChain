# Owner: B2
# Verification Agent — cross-checks cited_rows from the Log Analysis Agent
# against normalized_logs.csv and tags each incident verified/unverified.
#
# No LLM call here on purpose: this is a direct data lookup so it stays fast
# and demo-safe even if the Groq API is down or rate-limited.
#
# cited_rows on an incident can be given two ways:
#   1. Plain IDs:   "cited_rows": ["R003", "R004"]
#                   -> existence-only check (row must exist in the CSV).
#   2. Rich claims: "cited_rows": [{"row_id": "R003", "timestamp": "...",
#                                    "source": "...", "event_type": "..."}]
#                   -> existence check PLUS the claimed field values must
#                      match the actual row, which is the stronger
#                      hallucination check described in sih.md.
# B1's current documented output format is (1). Ask B1 to switch to (2)
# once their agent is stable -- that's what turns this from "does the row
# exist" into "did the agent tell the truth about the row".
#
# Output contract: each incident gets an added "row_checks" list of
# {"row_id", "verified", "exists", "mismatches", "row"} plus a top-level
# "verified" bool and an adjusted "confidence". This matches exactly what
# investigation_agent.py's build_evidence() already reads (Aptab18's
# implementation), so the two connect with no extra glue code.

from __future__ import annotations

import copy
from typing import Any

import pandas as pd

CONFIDENCE_FLOOR = 0.05  # never let adjusted confidence hit exactly 0


def load_normalized_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str)
    if "row_id" not in df.columns:
        raise ValueError(
            f"{path} has no 'row_id' column. Verification needs a stable, "
            "unique row identifier -- ask D3 to add one to normalized_logs.csv."
        )
    return df.set_index("row_id", drop=False)


def _get_row(df: pd.DataFrame, row_id: str) -> dict[str, Any] | None:
    if row_id not in df.index:
        return None
    row = df.loc[row_id]
    if isinstance(row, pd.DataFrame):  # duplicate row_id -- treat as ambiguous
        return None
    return row.to_dict()


def _values_match(claimed: str, actual: str) -> bool:
    return str(claimed).strip().lower() == str(actual).strip().lower()


def verify_citation(citation: str | dict, df: pd.DataFrame) -> dict[str, Any]:
    """Verify a single citation. Returns a per-citation verification record."""
    if isinstance(citation, dict):
        row_id = citation.get("row_id")
        claims = {k: v for k, v in citation.items() if k != "row_id"}
    else:
        row_id = citation
        claims = {}

    row = _get_row(df, row_id) if row_id else None
    exists = row is not None

    mismatches = []
    if exists and claims:
        for field, claimed_value in claims.items():
            actual_value = row.get(field)
            if actual_value is None or not _values_match(claimed_value, actual_value):
                mismatches.append(
                    {"field": field, "claimed": claimed_value, "actual": actual_value}
                )

    matched = exists and not mismatches
    return {
        "row_id": row_id,
        "verified": matched,
        "exists": exists,
        "matched": matched,
        "mismatches": mismatches,
        "row": row,
    }


def verify_incident(incident: dict[str, Any], df: pd.DataFrame) -> dict[str, Any]:
    """Return a new incident dict with verification results and an
    adjusted confidence score. Does not mutate the input incident."""
    result = copy.deepcopy(incident)
    cited = incident.get("cited_rows", [])

    checks = [verify_citation(c, df) for c in cited]
    total = len(checks)
    passed = sum(1 for c in checks if c["matched"])

    original_confidence = float(incident.get("confidence", 0.0))
    if total == 0:
        adjusted_confidence = original_confidence
    else:
        adjusted_confidence = round(original_confidence * (passed / total), 3)
        adjusted_confidence = max(adjusted_confidence, CONFIDENCE_FLOOR if passed > 0 else 0.0)

    result["row_checks"] = checks
    result["verified"] = total > 0 and passed == total
    result["original_confidence"] = original_confidence
    result["confidence"] = adjusted_confidence
    return result


def verify_incidents(incidents: list[dict[str, Any]], df: pd.DataFrame) -> list[dict[str, Any]]:
    return [verify_incident(incident, df) for incident in incidents]


if __name__ == "__main__":
    import json
    from pathlib import Path

    fixtures = Path(__file__).parent / "fixtures"
    logs_df = load_normalized_logs(fixtures / "mock_normalized_logs.csv")
    incidents = json.loads((fixtures / "mock_b1_output.json").read_text())

    verified = verify_incidents(incidents, logs_df)
    for inc in verified:
        print(f"{inc['incident_id']}: verified={inc['verified']} "
              f"confidence {inc['original_confidence']} -> {inc['confidence']}")
        for check in inc["row_checks"]:
            status = "OK" if check["matched"] else "FAIL"
            print(f"  [{status}] {check['row_id']} exists={check['exists']} "
                  f"mismatches={check['mismatches']}")
