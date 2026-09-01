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


def generate_pdf_report(finding: dict[str, Any], output_path: str | Path) -> Path:
    """Render the same report as a PDF using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    story = []

    risk_level = finding.get("risk_level", "Unknown")
    story.append(Paragraph(f"Incident Report — {finding.get('incident_id', 'UNKNOWN')}", styles["Title"]))
    story.append(Paragraph(f"Generated: {finding.get('generated_at', '')}", styles["Normal"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Risk Level:</b> {risk_level}", styles["Normal"]))
    story.append(Paragraph(f"<b>Risk Score:</b> {finding.get('risk_score', 'n/a')}", styles["Normal"]))
    story.append(Paragraph(f"<b>Confidence:</b> {finding.get('confidence', 'n/a')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(Paragraph(finding.get("explanation") or finding.get("theory", ""), styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Evidence", styles["Heading2"]))
    evidence = finding.get("evidence", []) or []
    table_data = [["Row ID", "Timestamp", "Source", "Event Type", "Severity", "Status"]]
    for row in evidence:
        status = "Verified" if row.get("verified") else "UNVERIFIED"
        table_data.append([
            str(row.get("row_id", "")),
            str(row.get("timestamp", "")),
            str(row.get("source", "")),
            str(row.get("event_type", "")),
            str(row.get("severity", "")),
            status,
        ])
    table = Table(table_data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))

    action = finding.get("recommended_action", {}) or {}
    story.append(Paragraph("Recommended Action", styles["Heading2"]))
    story.append(Paragraph(f"<b>{action.get('action', 'No action recommended.')}</b>", styles["Normal"]))
    story.append(Paragraph(action.get("rationale", ""), styles["Normal"]))
    story.append(Paragraph("This is a recommendation only. No action has been automatically executed.", styles["Italic"]))

    doc = SimpleDocTemplate(str(output_path), pagesize=letter)
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
