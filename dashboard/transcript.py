"""Agent transcript — the reasoning behind a finding, as a conversation.

A risk score on its own is a claim. This turns the same finding into the
step-by-step exchange that produced it: what Agent 1 proposed, what Agent 2
accepted or rejected, and how Agent 3 arrived at the number.

Every line is derived from values already present in the finding -- rule names,
row counts, verification results, score factors. Nothing is narrated that the
pipeline did not actually do, so the transcript can be read as an audit trail
rather than as flavour text.
"""

from __future__ import annotations

from html import escape
from typing import Any, Dict, List, Tuple

AGENTS = {
    "analysis": ("Agent 1 · Log Analysis", "#00d4ff"),
    "verify": ("Agent 2 · Verification", "#8b7cf6"),
    "investigate": ("Agent 3 · Investigation", "#2ed573"),
}

# kind -> (glyph, colour). "challenge" and "reject" are what make this a
# conversation rather than a status list.
KINDS = {
    "say": ("→", "#8b98a9"),
    "ok": ("✓", "#2ed573"),
    "challenge": ("!", "#ff8b3d"),
    "reject": ("✗", "#ff4757"),
    "verdict": ("◆", "#e6edf3"),
}


def build_transcript(finding: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Return [(agent_key, kind, text)] for one finding."""
    evidence = finding.get("evidence", []) or []
    verified = [e for e in evidence if e.get("verified")]
    failed = [e for e in evidence if not e.get("verified")]
    breakdown = finding.get("score_breakdown", {}) or {}
    rules = finding.get("rules_fired", []) or []
    sources = sorted({e.get("source", "") for e in evidence if e.get("source")})
    lines: List[Tuple[str, str, str]] = []

    # ---- Agent 1 ---------------------------------------------------------- #
    who = sources[0] if sources else "an unidentified source"
    lines.append(("analysis", "say",
                  f"Correlated {len(evidence)} related rows involving {who}."))
    for rule in rules:
        lines.append(("analysis", "say", f"Detector fired: {rule.replace('_', ' ')}."))
    lines.append(("analysis", "say",
                  f"Hypothesis at confidence {finding.get('confidence', 0):.2f} — "
                  f"{finding.get('theory', '')[:160]}"))
    lines.append(("analysis", "verdict",
                  f"Passing {len(evidence)} citations to Verification."))

    # ---- Agent 2 ---------------------------------------------------------- #
    lines.append(("verify", "say",
                  f"Checking all {len(evidence)} cited rows against the raw log. "
                  "No model is used here — this is a direct lookup."))
    if failed:
        lines.append(("verify", "challenge",
                      f"{len(failed)} citation(s) do not hold up. Challenging them."))
        for row in failed[:6]:
            rid = row.get("row_id", "?")
            if not row.get("exists", True):
                lines.append(("verify", "reject",
                              f"Row {rid} was cited as evidence, but no such row "
                              "exists in the log. Rejected."))
            for mismatch in row.get("mismatches") or []:
                lines.append((
                    "verify", "reject",
                    f"Row {rid}: Agent 1 claimed {mismatch.get('field')} = "
                    f"\"{mismatch.get('claimed')}\", but the log records "
                    f"\"{mismatch.get('actual')}\". Rejected."))
        before = float(finding.get("original_confidence", finding.get("confidence", 0)) or 0)
        after = float(finding.get("confidence", 0) or 0)
        shift = (f"Confidence {before:.2f} → {after:.2f}." if before != after
                 else f"Confidence holds at {after:.2f}.")
        lines.append(("verify", "verdict",
                      f"{len(verified)}/{len(evidence)} citations proven. {shift} "
                      "The rejected claims are excluded from scoring."))
    else:
        lines.append(("verify", "ok",
                      f"All {len(evidence)} citations matched the raw log on row id, "
                      "timestamp and source."))
        lines.append(("verify", "verdict",
                      "Nothing to dispute. Confidence stands."))

    # ---- Agent 3 ---------------------------------------------------------- #
    lines.append(("investigate", "say",
                  f"Threat weight {breakdown.get('threat_weight', 0):.2f} from the "
                  f"detector that fired; verification factor "
                  f"{breakdown.get('verification_factor', 0):.2f} from "
                  f"{breakdown.get('verified_rows', 0)}/{breakdown.get('total_rows', 0)} "
                  "proven rows."))
    if breakdown.get("capped_by_verification"):
        lines.append(("investigate", "challenge",
                      "Not one citation could be proven, so this is capped at Medium "
                      "no matter what the other factors say."))
    elif failed:
        lines.append(("investigate", "challenge",
                      "Scoring on the surviving evidence only — the rejected rows "
                      "carry no weight."))
    lines.append(("investigate", "verdict",
                  f"{finding.get('risk_level', '?')} at {finding.get('risk_score', 0):.2f}. "
                  f"Recommending: {(finding.get('recommended_action') or {}).get('action', 'n/a')}. "
                  "Recommendation only — not executed."))
    return lines


TRANSCRIPT_CSS = """
<style>
  .vc-tr { border-left: 2px solid #232b3a; margin-left: 6px; padding-left: 14px; }
  .vc-tr-agent { font-size: 0.76rem; font-weight: 700; letter-spacing: .4px;
                 margin: 12px 0 5px -20px; }
  .vc-tr-line { font-size: 0.83rem; line-height: 1.5; margin-bottom: 4px;
                color: #b8c2cf; }
  .vc-tr-line .g { display: inline-block; width: 15px; font-weight: 700; }
</style>
"""


def transcript_html(finding: Dict[str, Any]) -> str:
    """Render the transcript, grouping consecutive lines under their speaker."""
    parts = ['<div class="vc-tr">']
    current = None
    for agent_key, kind, text in build_transcript(finding):
        if agent_key != current:
            label, color = AGENTS[agent_key]
            parts.append(f'<div class="vc-tr-agent" style="color:{color}">{label}</div>')
            current = agent_key
        glyph, glyph_color = KINDS.get(kind, KINDS["say"])
        weight = "600" if kind in ("verdict", "reject") else "400"
        parts.append(
            f'<div class="vc-tr-line" style="font-weight:{weight}">'
            f'<span class="g" style="color:{glyph_color}">{glyph}</span>'
            f'{escape(text)}</div>')
    parts.append("</div>")
    return TRANSCRIPT_CSS + "".join(parts)
