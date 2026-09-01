# Owner: B2
# Generates downloadable incident report (PDF/Markdown): summary, risk level,
# evidence with verification status, recommended action, timestamp.
#
# Input: one "finding" dict -- the output of
# agents/investigation_agent.py's investigate()/investigate_all(), i.e.:
#   {incident_id, risk_level, risk_score, confidence, verified, verified_ratio,
#    theory, explanation, explanation_source,
#    recommended_action: {action, rationale, auto_executed, requires_analyst_approval},
#    evidence: [{row_id, verified, timestamp, source, event_type, severity,
#                source_file, summary}],
#    score_breakdown, generated_at}
#
# B3 wires save_report()/generate_markdown_report() to the
# "GET /incidents/{id}/report" endpoint and the dashboard's Download button.

from __future__ import annotations

from pathlib import Path
from typing import Any

DEFAULT_OUTPUT_DIR = Path(__file__).parent / "output"

RISK_BADGE = {
    "Critical": "\U0001F534 CRITICAL",
    "High": "\U0001F7E0 HIGH",
    "Medium": "\U0001F7E1 MEDIUM",
    "Low": "\U0001F7E2 LOW",
}


def _evidence_lines_markdown(evidence: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Row ID | Timestamp | Source | Event Type | Severity | Status |",
        "|---|---|---|---|---|---|",
    ]
    for row in evidence:
        badge = "✓ Verified" if row.get("verified") else "⚠ Unverified"
        lines.append(
            "| {row_id} | {timestamp} | {source} | {event_type} | {severity} | {badge} |".format(
                row_id=row.get("row_id", ""),
                timestamp=row.get("timestamp", ""),
                source=row.get("source", ""),
                event_type=row.get("event_type", ""),
                severity=row.get("severity", ""),
                badge=badge,
            )
        )
    return lines


def generate_markdown_report(finding: dict[str, Any]) -> str:
    """Build a clean, self-contained Markdown incident report."""
    risk_level = finding.get("risk_level", "Unknown")
    badge = RISK_BADGE.get(risk_level, risk_level)
    action = finding.get("recommended_action", {}) or {}
    evidence = finding.get("evidence", []) or []
    unverified_count = sum(1 for e in evidence if not e.get("verified"))

    lines = [
        f"# Incident Report — {finding.get('incident_id', 'UNKNOWN')}",
        "",
        f"**Generated:** {finding.get('generated_at', '')}",
        f"**Risk Level:** {badge}  ",
        f"**Risk Score:** {finding.get('risk_score', 'n/a')}  ",
        f"**Confidence (post-verification):** {finding.get('confidence', 'n/a')}  ",
        f"**Evidence Verified:** {len(evidence) - unverified_count}/{len(evidence)} rows",
        "",
        "## Summary",
        "",
        finding.get("explanation") or finding.get("theory", "No explanation available."),
        "",
        "## Evidence",
        "",
    ]
    lines.extend(_evidence_lines_markdown(evidence))
    if unverified_count:
        lines += [
            "",
            f"⚠ **{unverified_count} cited row(s) could not be verified against the raw "
            "log file.** Their claims were excluded from the risk score above. "
            "This is the Verification Layer catching a potential hallucination "
            "before it reached this report.",
        ]

    lines += [
        "",
        "## Recommended Action",
        "",
        f"**{action.get('action', 'No action recommended.')}**",
        "",
        action.get("rationale", ""),
        "",
        "_This is a recommendation only. No action has been automatically executed._",
    ]
    return "\n".join(lines)


# Evidence rows printed in the PDF. INC-002 cites 829 rows; printing every one
# produces a 20-page table nobody reads, so the report shows a sample and states
# the true total.
PDF_EVIDENCE_ROWS = 25

PDF_RISK_COLOR = {
    "Critical": "#c0392b", "High": "#d35400",
    "Medium": "#b7950b", "Low": "#1e8449",
}


def _escape(text: Any) -> str:
    """reportlab Paragraph parses a mini-HTML dialect, so bare & and < break it."""
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def generate_pdf_report(finding: dict[str, Any], output_path: str | Path) -> Path:
    """Render the incident as an analyst-ready PDF.

    Carries everything the dashboard shows, including the verification result.
    A report that quietly omitted the failed citations would defeat the point of
    having a Verification Layer at all.
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    base = getSampleStyleSheet()
    body = ParagraphStyle("vc_body", parent=base["Normal"], fontSize=9.5, leading=14,
                          alignment=TA_LEFT, spaceAfter=4)
    small = ParagraphStyle("vc_small", parent=body, fontSize=8,
                           textColor=colors.HexColor("#666666"))
    h2 = ParagraphStyle("vc_h2", parent=base["Heading2"], fontSize=12, spaceBefore=12,
                        spaceAfter=6, textColor=colors.HexColor("#1a2332"))
    cell = ParagraphStyle("vc_cell", parent=body, fontSize=8, leading=10, spaceAfter=0)

    risk = finding.get("risk_level", "Unknown")
    accent_hex = PDF_RISK_COLOR.get(risk, "#555555")
    evidence = finding.get("evidence", []) or []
    verified_rows = [e for e in evidence if e.get("verified")]
    failed_rows = [e for e in evidence if not e.get("verified")]

    story: list[Any] = []

    # --- header ------------------------------------------------------------ #
    story.append(Paragraph(
        '<font size="16"><b>Incident Report &mdash; '
        f'{_escape(finding.get("incident_id", "UNKNOWN"))}</b></font>', body))
    story.append(Paragraph(
        f'<font color="{accent_hex}"><b>{_escape(risk).upper()}</b></font>'
        f'  &middot;  risk score {finding.get("risk_score", "n/a")}'
        f'  &middot;  generated {_escape(finding.get("generated_at", ""))}', small))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor(accent_hex),
                            spaceBefore=6, spaceAfter=10))

    # --- key facts --------------------------------------------------------- #
    verdict = ("All cited evidence verified against the raw log" if not failed_rows
               else f"{len(failed_rows)} of {len(evidence)} citations FAILED verification")
    facts = [
        ["Risk level", risk, "Risk score", str(finding.get("risk_score", "n/a"))],
        ["Confidence", str(finding.get("confidence", "n/a")),
         "Evidence verified", f"{len(verified_rows)}/{len(evidence)}"],
        ["Verification", verdict, "", ""],
    ]
    facts_table = Table(facts, colWidths=[28 * mm, 55 * mm, 32 * mm, 59 * mm])
    facts_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666666")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#666666")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("SPAN", (1, 2), (3, 2)),
        ("TEXTCOLOR", (1, 2), (1, 2),
         colors.HexColor("#c0392b") if failed_rows else colors.HexColor("#1e8449")),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#dddddd")),
    ]))
    story.append(facts_table)

    # --- MITRE ATT&CK ------------------------------------------------------ #
    mitre = finding.get("mitre") or []
    if mitre:
        story.append(Paragraph("MITRE ATT&amp;CK", h2))
        rows = [["Tactic", "Technique"]] + [
            [f'{m.get("tactic_id", "")} {m.get("tactic", "")}',
             f'{m.get("technique_id", "")} {m.get("technique", "")}'] for m in mitre]
        table = Table(rows, colWidths=[80 * mm, 94 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)

    # --- narrative --------------------------------------------------------- #
    story.append(Paragraph("Summary", h2))
    story.append(Paragraph(
        _escape(finding.get("explanation") or finding.get("theory", "")), body))
    source = finding.get("explanation_source", "")
    story.append(Paragraph(
        "Written by the language model and ground-checked against the verified evidence."
        if source == "llm" else
        "Generated deterministically; no language model was used for this summary.", small))

    # --- how the score was reached ----------------------------------------- #
    breakdown = finding.get("score_breakdown") or {}
    if breakdown:
        story.append(Paragraph("How this score was reached", h2))
        score_rows = [
            ["Threat weight", "Confidence", "Verification", "Volume", "Final score"],
            [str(breakdown.get("threat_weight", "")),
             str(breakdown.get("confidence_factor", "")),
             str(breakdown.get("verification_factor", "")),
             str(breakdown.get("volume_factor", "")),
             str(finding.get("risk_score", ""))],
        ]
        table = Table(score_rows, colWidths=[34.8 * mm] * 5)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)
        story.append(Paragraph(
            "threat x confidence x verification x volume. Unverified evidence lowers the "
            "verification factor, and an incident with no verified evidence at all is "
            "capped at Medium regardless of the other factors.", small))

    # --- verification failures: the differentiator, inside the report ------- #
    if failed_rows:
        story.append(Paragraph("Verification failures", h2))
        story.append(Paragraph(
            f"{len(failed_rows)} citation(s) could not be proven against the raw log. "
            "These claims were excluded from the risk score above.", body))
        lie_rows = [["Row", "Field", "Claimed by agent", "Actual value in log"]]
        for row in failed_rows:
            if not row.get("exists", True):
                lie_rows.append([str(row.get("row_id", "")), "row existence",
                                 "cited as evidence", "no such row in the log"])
            for mismatch in row.get("mismatches") or []:
                lie_rows.append([str(row.get("row_id", "")),
                                 str(mismatch.get("field", "")),
                                 str(mismatch.get("claimed", "")),
                                 str(mismatch.get("actual", ""))])
        table = Table([[Paragraph(_escape(c), cell) for c in r] for r in lie_rows],
                      colWidths=[26 * mm, 26 * mm, 61 * mm, 61 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#fdf0ee")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e0b4ac")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(table)

    # --- evidence ---------------------------------------------------------- #
    story.append(Paragraph("Evidence", h2))
    shown = evidence[:PDF_EVIDENCE_ROWS]
    table_data = [["Row ID", "Timestamp", "Source", "Event", "Severity", "Status"]]
    for row in shown:
        table_data.append([
            str(row.get("row_id", "")), str(row.get("timestamp", "")),
            str(row.get("source", "")), str(row.get("event_type", "")),
            str(row.get("severity", "")),
            "Verified" if row.get("verified") else "UNVERIFIED",
        ])
    table = Table([[Paragraph(_escape(c), cell) for c in r] for r in table_data],
                  colWidths=[24 * mm, 36 * mm, 32 * mm, 34 * mm, 22 * mm, 26 * mm],
                  repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2332")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for position, row in enumerate(shown, start=1):
        tint = "#f2fbf5" if row.get("verified") else "#fdf0ee"
        style.append(("BACKGROUND", (0, position), (-1, position), colors.HexColor(tint)))
    table.setStyle(TableStyle(style))
    story.append(table)
    if len(evidence) > PDF_EVIDENCE_ROWS:
        story.append(Paragraph(
            f"Showing {PDF_EVIDENCE_ROWS} of {len(evidence)} cited rows. Every row was "
            "verified individually; the counts above cover all of them.", small))

    # --- recommended action ------------------------------------------------ #
    action = finding.get("recommended_action", {}) or {}
    story.append(KeepTogether([
        Paragraph("Recommended action", h2),
        Paragraph(f'<b>{_escape(action.get("action", "No action recommended."))}</b>', body),
        Paragraph(_escape(action.get("rationale", "")), body),
        Spacer(1, 4),
        Paragraph("This is a recommendation only. No action has been executed "
                  "automatically; the analyst retains the decision.", small),
    ]))

    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Incident Report {finding.get('incident_id', '')}", author="VerdictChain")
    doc.build(story)
    return output_path


def save_report(finding: dict[str, Any], output_dir: str | Path = DEFAULT_OUTPUT_DIR, fmt: str = "markdown") -> Path:
    """Generate and write the report to disk. Returns the file path.

    This is the function B3 should call from the FastAPI
    GET /incidents/{id}/report endpoint and the dashboard's Download button.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    incident_id = finding.get("incident_id", "unknown")

    if fmt == "markdown":
        path = output_dir / f"{incident_id}.md"
        path.write_text(generate_markdown_report(finding), encoding="utf-8")
        return path
    if fmt == "pdf":
        path = output_dir / f"{incident_id}.pdf"
        return generate_pdf_report(finding, path)
    raise ValueError(f"Unknown report format: {fmt!r} (expected 'markdown' or 'pdf')")


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path as _Path

    sys.path.insert(0, str(_Path(__file__).parent.parent / "agents"))
    from investigation_agent import investigate_all  # noqa: E402
    from verification_agent import load_normalized_logs, verify_incidents  # noqa: E402

    fixtures = _Path(__file__).parent.parent / "agents" / "fixtures"
    logs_df = load_normalized_logs(fixtures / "mock_normalized_logs.csv")
    raw_incidents = json.loads((fixtures / "mock_b1_output.json").read_text())

    verified = verify_incidents(raw_incidents, logs_df)
    findings = investigate_all(verified, use_llm=False)

    for finding in findings:
        md_path = save_report(finding, fmt="markdown")
        print(f"Wrote {md_path}")
