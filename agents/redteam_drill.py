"""Red-team drill: deliberately poison an incident to prove the Verification Layer works.

Why this exists
---------------
On clean data the Log Analysis Agent only ever cites row ids it actually read,
so verification passes 100% of the time and the Verification Layer -- the whole
point of this system -- never visibly does anything. That is a demo problem, not
a design problem: you cannot show a smoke detector working in a room with no smoke.

This module injects controlled, clearly-labelled false citations into incidents
*before* they reach the Verification Agent, so the layer can be seen catching
them. Five failure modes are injected, because they are caught differently and
they are not equally easy to catch:

  1. GHOST ROW      -- a row id that does not exist in the log at all.
                       Caught by the existence check (exists=False).
  2. PLAUSIBLE GHOST-- a row id shaped exactly like the real ones (R0007 style)
                       but past the end of the file. Indistinguishable by eye;
                       only a real lookup catches it.
  3. FALSE TIMESTAMP-- a real row, wrong time claimed against it.
  4. FALSE SOURCE   -- a real row, wrong source IP claimed against it. This is
                       the one that matters operationally: acting on it means
                       blocking an innocent host.
  5. FALSE EVENT    -- a real row, wrong event_type claimed against it.

Modes 3-5 are the interesting ones: the row is real, so a naive "does this row
exist" check passes them. Only comparing claimed values against the raw log
catches the lie.

Scale
-----
`lies` controls how many false citations are injected, spread round-robin
across incidents. Two is enough to prove the mechanism; a larger number is for
showing the layer holding up under volume. Be careful reading the dashboard
afterwards: a heavily-poisoned run makes the verification rate drop, and that
drop is the DRILL's lies being caught, not the Log Analysis Agent hallucinating.
Every poisoned incident carries ``drill_injected: True`` and the returned info
carries the exact count, so the UI can say so plainly.

This is a test harness, never a silent default.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple

GHOST_ROW_ID = "R999999-GHOST"
FALSE_CLAIM_TIMESTAMP = "1999-01-01T00:00:00"
FALSE_CLAIM_SOURCE = "203.0.113.255"
FALSE_CLAIM_EVENT = "printer_maintenance"

# Ordered so a 2-lie drill still injects one ghost and one false claim, which
# is what the smoke test and the existing narration expect.
MODES = ("ghost", "false_timestamp", "false_source", "plausible_ghost", "false_event")


def _row_id_of(citation: Any) -> Any:
    return citation.get("row_id") if isinstance(citation, dict) else citation


def _make_lie(mode: str, real_row_id: Any, serial: int) -> Tuple[Any, str]:
    """Build one false citation. Returns (citation, human description)."""
    if mode == "ghost":
        return GHOST_ROW_ID, f"cites {GHOST_ROW_ID}, which was never logged"

    if mode == "plausible_ghost":
        # Same shape as a real id, but past the end of the file -- looks right,
        # is not. Only a lookup can tell.
        fake = f"R{900000 + serial}"
        return fake, f"cites {fake}, a row id that looks real but does not exist"

    if mode == "false_timestamp":
        return ({"row_id": real_row_id, "timestamp": FALSE_CLAIM_TIMESTAMP},
                f"claims row {real_row_id} occurred at {FALSE_CLAIM_TIMESTAMP}")

    if mode == "false_source":
        return ({"row_id": real_row_id, "source": FALSE_CLAIM_SOURCE},
                f"claims row {real_row_id} came from {FALSE_CLAIM_SOURCE}")

    return ({"row_id": real_row_id, "event_type": FALSE_CLAIM_EVENT},
            f"claims row {real_row_id} was a {FALSE_CLAIM_EVENT} event")


def inject_hallucination(
    incidents: List[Dict[str, Any]],
    target_index: int = 0,
    lies: int = 2,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return (incidents_with_poisoned_copies, description_of_what_was_injected).

    Does not mutate the input. `lies` false citations are spread round-robin
    across the incidents starting at `target_index`, cycling through MODES so
    the mix of failure types stays even at any scale.

    With the default lies=2 this poisons a single incident with one ghost row
    and one false timestamp -- the original behaviour.
    """
    if not incidents:
        return incidents, {"injected": False, "reason": "no incidents to poison"}

    poisoned = copy.deepcopy(incidents)
    # Only incidents that actually cite something can be lied about.
    targets = [i for i in poisoned if i.get("cited_rows")]
    if not targets:
        return incidents, {"injected": False, "reason": "no incident cites any rows"}

    start = min(target_index, len(targets) - 1)
    targets = targets[start:] + targets[:start]

    # Concentrate a small drill in one incident -- "INC-001 verified 11/13" is a
    # far clearer story than one stray lie in each of two incidents. Only spread
    # wider once there are enough lies for every incident to carry a couple.
    spread = min(len(targets), max(1, lies // 2))
    targets = targets[:spread]

    per_incident: Dict[str, List[str]] = {}
    counts: Dict[str, int] = {}
    injected = 0

    for serial in range(max(lies, 0)):
        target = targets[serial % len(targets)]
        mode = MODES[serial % len(MODES)]
        cited = list(target["cited_rows"])

        # Lie about a different real row each time, so a poisoned incident does
        # not stack five contradictory claims onto one row.
        real_pool = [_row_id_of(c) for c in cited if not isinstance(c, dict)]
        if not real_pool:
            continue
        real_row_id = real_pool[serial % len(real_pool)]

        citation, description = _make_lie(mode, real_row_id, serial)
        cited.append(citation)
        target["cited_rows"] = cited
        target["drill_injected"] = True

        incident_id = target.get("incident_id", "?")
        per_incident.setdefault(incident_id, []).append(description)
        counts[mode] = counts.get(mode, 0) + 1
        injected += 1

    if not injected:
        return incidents, {"injected": False, "reason": "no plain row ids to lie about"}

    for incident in poisoned:
        claims = per_incident.get(incident.get("incident_id", "?"))
        if claims:
            incident["theory"] = (
                incident.get("theory", "").rstrip(".")
                + ". The agent additionally " + "; and ".join(claims) + "."
            )

    return poisoned, {
        "injected": True,
        "lies": injected,
        "incidents_poisoned": len(per_incident),
        "incident_ids": sorted(per_incident),
        "by_mode": counts,
        # Kept for callers written against the original two-lie drill.
        "incident_id": sorted(per_incident)[0],
        "ghost_row_id": GHOST_ROW_ID,
        "false_claim_timestamp": FALSE_CLAIM_TIMESTAMP,
        "note": (
            f"Red-team drill: {injected} false citation(s) were injected into "
            f"{len(per_incident)} incident(s) before verification. Every "
            "unverified row below is one of these planted lies being caught -- "
            "not the Log Analysis Agent hallucinating."
        ),
    }


if __name__ == "__main__":
    import json

    sample = [{"incident_id": "INC-001", "theory": "Port scan detected",
               "confidence": 0.9, "cited_rows": ["R0001", "R0002"]}]
    out, info = inject_hallucination(sample)
    print(json.dumps(info, indent=2))
    print("\npoisoned cited_rows:", json.dumps(out[0]["cited_rows"], indent=2))
