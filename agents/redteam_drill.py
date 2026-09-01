"""Red-team drill: deliberately poison an incident to prove the Verification Layer works.

Why this exists
---------------
On clean data the Log Analysis Agent only ever cites row ids it actually read,
so verification passes 100% of the time and the Verification Layer -- the whole
point of this system -- never visibly does anything. That is a demo problem, not
a design problem: you cannot show a smoke detector working in a room with no smoke.

This module injects a controlled, clearly-labelled false citation into an
incident *before* it reaches the Verification Agent, so the layer can be seen
catching it. Two failure modes are injected, because they are caught differently:

  1. GHOST ROW    -- a citation to a row id that does not exist in the log at all.
                     Caught by the existence check   (exists=False).
  2. FALSE CLAIM  -- a citation to a row that DOES exist, but with a wrong
                     timestamp claimed against it. Caught by the field check
                     (exists=True, mismatches=[{field, claimed, actual}]).

The second one is the interesting one: the row is real, so a naive "does this
row exist" check would pass it. Only comparing the claimed values against the
raw log catches the lie.

This is a test harness, never a silent default. Every incident it touches is
tagged ``drill_injected: True`` so the dashboard can label it as a drill and
nobody can mistake a drill result for a real detection.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple

GHOST_ROW_ID = "R999999-GHOST"
FALSE_CLAIM_TIMESTAMP = "1999-01-01T00:00:00"


def inject_hallucination(
    incidents: List[Dict[str, Any]],
    target_index: int = 0,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return (incidents_with_a_poisoned_copy, description_of_what_was_injected).

    Does not mutate the input. If there are no incidents to poison, returns the
    input unchanged with ``injected: False``.
    """
    if not incidents:
        return incidents, {"injected": False, "reason": "no incidents to poison"}

    poisoned = copy.deepcopy(incidents)
    target = poisoned[min(target_index, len(poisoned) - 1)]
    cited = list(target.get("cited_rows") or [])
    if not cited:
        return incidents, {"injected": False, "reason": "target incident cites no rows"}

    # A real row id that the agent will now lie about.
    real_row_id = cited[0]
    if isinstance(real_row_id, dict):
        real_row_id = real_row_id.get("row_id")

    # 1. Ghost row: cited, but no such row was ever logged.
    cited.append(GHOST_ROW_ID)

    # 2. False claim: real row, wrong timestamp claimed against it. Sent as a
    #    rich citation so the Verification Agent runs its field check.
    cited.append({"row_id": real_row_id, "timestamp": FALSE_CLAIM_TIMESTAMP})

    target["cited_rows"] = cited
    target["drill_injected"] = True
    target["theory"] = (
        target.get("theory", "").rstrip(".")
        + f". The agent additionally claims row {GHOST_ROW_ID} supports this, and that "
          f"row {real_row_id} occurred at {FALSE_CLAIM_TIMESTAMP}."
    )

    return poisoned, {
        "injected": True,
        "incident_id": target.get("incident_id"),
        "ghost_row_id": GHOST_ROW_ID,
        "false_claim_row_id": real_row_id,
        "false_claim_timestamp": FALSE_CLAIM_TIMESTAMP,
        "note": (
            "Red-team drill: two false citations were injected into "
            f"{target.get('incident_id')} before verification. Anything the "
            "Verification Agent flags below is the layer working as designed."
        ),
    }


if __name__ == "__main__":
    import json

    sample = [{"incident_id": "INC-001", "theory": "Port scan detected",
               "confidence": 0.9, "cited_rows": ["R0001", "R0002"]}]
    out, info = inject_hallucination(sample)
    print(json.dumps(info, indent=2))
    print("\npoisoned cited_rows:", json.dumps(out[0]["cited_rows"], indent=2))
