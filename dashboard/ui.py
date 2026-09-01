"""Shared UI helpers for the VerdictChain dashboard pages.

Kept separate so app.py and the Live Investigation page render identical
badges, colours and tables instead of drifting apart.
"""

from __future__ import annotations

import json
import sys
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

FINDINGS_PATH = PROJECT_ROOT / "data" / "findings.json"
METRICS_PATH = PROJECT_ROOT / "data" / "metrics.json"
API_URL = "http://127.0.0.1:8000"

RISK_COLORS = {
    "Critical": "#ff4757",
    "High": "#ff8b3d",
    "Medium": "#ffd93d",
    "Low": "#2ed573",
}
RISK_ORDER = ["Critical", "High", "Medium", "Low"]

VERIFIED_COLOR = "#2ed573"
UNVERIFIED_COLOR = "#ff4757"

# Tactic colours follow the kill-chain order, early (blue) to late (red).
TACTIC_COLORS = {
    "TA0001": "#4a9eff", "TA0004": "#8b7cf6", "TA0005": "#a78bfa",
    "TA0006": "#f472b6", "TA0007": "#38bdf8", "TA0008": "#fb923c",
    "TA0009": "#fbbf24", "TA0010": "#f87171", "TA0011": "#c084fc",
    "TA0040": "#ef4444",
}

CSS = """
<style>
  .block-container { padding-top: 2.2rem; max-width: 1500px; }

  .vc-hero {
    background: linear-gradient(135deg, #131a2b 0%, #0e1117 60%);
    border: 1px solid #1f2937; border-left: 4px solid #00d4ff;
    border-radius: 14px; padding: 18px 24px; margin-bottom: 18px;
  }
  .vc-hero h1 { margin: 0; font-size: 1.75rem; color: #e6edf3; letter-spacing: -0.5px; }
  .vc-hero p  { margin: 6px 0 0; color: #8b98a9; font-size: 0.92rem; }

  .vc-tile {
    background: #161b26; border: 1px solid #232b3a; border-radius: 12px;
    padding: 14px 16px; height: 100%;
  }
  .vc-tile .v { font-size: 1.9rem; font-weight: 800; line-height: 1.1; }
  .vc-tile .l { color: #8b98a9; font-size: 0.78rem; text-transform: uppercase;
                letter-spacing: 0.6px; margin-top: 2px; }
  .vc-tile .s { color: #6b7688; font-size: 0.74rem; margin-top: 4px; }

  .vc-badge {
    display: inline-block; padding: 3px 11px; border-radius: 999px;
    font-size: 0.75rem; font-weight: 700; letter-spacing: 0.3px;
  }
  .vc-mitre {
    display: inline-block; padding: 3px 9px; margin: 2px 4px 2px 0;
    border-radius: 6px; font-size: 0.72rem; font-weight: 600;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    border: 1px solid; background: transparent;
  }

  table.vc-ev { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
  table.vc-ev th {
    text-align: left; padding: 7px 10px; color: #8b98a9; font-weight: 600;
    border-bottom: 1px solid #2a3444; font-size: 0.74rem;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  table.vc-ev td { padding: 6px 10px; border-bottom: 1px solid #1b2230; }
  table.vc-ev tr.ok  { background: rgba(46, 213, 115, 0.07); }
  table.vc-ev tr.bad { background: rgba(255, 71, 87, 0.13); }
  table.vc-ev tr.ok  td:first-child { border-left: 3px solid #2ed573; }
  table.vc-ev tr.bad td:first-child { border-left: 3px solid #ff4757; }
  .vc-scroll { max-height: 340px; overflow-y: auto; border: 1px solid #232b3a;
               border-radius: 10px; }

  .vc-lie {
    background: #1d1114; border: 1px solid #7f1d1d; border-left: 4px solid #ff4757;
    border-radius: 10px; padding: 14px 16px; margin: 10px 0;
  }
  .vc-lie .hdr { color: #ff8b8b; font-weight: 700; margin-bottom: 8px; }
  .vc-lie code { background: #2a1518; padding: 2px 6px; border-radius: 4px;
                 color: #ffb4b4; font-size: 0.82rem; }
  .vc-claim { color: #ff8b8b; } .vc-actual { color: #7ee2a8; }
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


# ── data loading ───────────────────────────────────────────────────────────── #

def load_findings(use_api: bool = True) -> List[Dict[str, Any]]:
    """API first, local file second. The dashboard must survive a dead backend."""
    if use_api:
        try:
            import requests
            response = requests.get(f"{API_URL}/incidents", timeout=2)
            if response.ok:
                return response.json()
        except Exception:
            pass
    if FINDINGS_PATH.exists():
        return json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))
    return []


def load_metrics() -> Optional[Dict[str, Any]]:
    if METRICS_PATH.exists():
        try:
            return json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def api_online() -> bool:
    try:
        import requests
        return requests.get(f"{API_URL}/health", timeout=1.5).ok
    except Exception:
        return False


# ── small render helpers ───────────────────────────────────────────────────── #

def hero(title: str, subtitle: str) -> None:
    st.markdown(
        f'<div class="vc-hero"><h1>{escape(title)}</h1><p>{escape(subtitle)}</p></div>',
        unsafe_allow_html=True)


def tile(col, value: Any, label: str, color: str = "#e6edf3", sub: str = "") -> None:
    sub_html = f'<div class="s">{escape(sub)}</div>' if sub else ""
    col.markdown(
        f'<div class="vc-tile"><div class="v" style="color:{color}">{value}</div>'
        f'<div class="l">{escape(label)}</div>{sub_html}</div>',
        unsafe_allow_html=True)


def risk_badge(level: str) -> str:
    color = RISK_COLORS.get(level, "#8b98a9")
    return (f'<span class="vc-badge" style="background:{color}22;color:{color};'
            f'border:1px solid {color}66">{escape(level.upper())}</span>')


def verdict_badge(verified: bool) -> str:
    color = VERIFIED_COLOR if verified else UNVERIFIED_COLOR
    text = "✓ VERIFIED" if verified else "⚠ UNVERIFIED"
    return (f'<span class="vc-badge" style="background:{color}22;color:{color};'
            f'border:1px solid {color}66">{text}</span>')


def mitre_badges(mitre: List[Dict[str, str]]) -> str:
    if not mitre:
        return '<span style="color:#6b7688;font-size:0.8rem">No MITRE mapping</span>'
    out = []
    for entry in mitre:
        color = TACTIC_COLORS.get(entry.get("tactic_id", ""), "#8b98a9")
        label = f"{entry.get('technique_id','')} · {entry.get('technique','')}"
        title = f"{entry.get('tactic_id','')} {entry.get('tactic','')}"
        out.append(f'<span class="vc-mitre" style="color:{color};border-color:{color}55" '
                   f'title="{escape(title)}">{escape(label)}</span>')
    return "".join(out)


def evidence_table(evidence: List[Dict[str, Any]], limit: int = 60) -> str:
    """Evidence rows as coloured HTML: green = verified, red = unverified."""
    head = ("<thead><tr><th>Row ID</th><th>Status</th><th>Timestamp</th>"
            "<th>Source</th><th>Event</th><th>Severity</th><th>Origin</th></tr></thead>")
    body = []
    for row in evidence[:limit]:
        ok = bool(row.get("verified"))
        cells = [
            row.get("row_id", ""),
            "✓ Verified" if ok else "⚠ Unverified",
            row.get("timestamp", ""),
            row.get("source", ""),
            row.get("event_type", ""),
            row.get("severity", ""),
            row.get("source_file", ""),
        ]
        tds = "".join(f"<td>{escape(str(c))}</td>" for c in cells)
        body.append(f'<tr class="{"ok" if ok else "bad"}">{tds}</tr>')
    return (f'<div class="vc-scroll"><table class="vc-ev">{head}'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def render_download(finding: Dict[str, Any]) -> None:
    """PDF download button, with Markdown offered only as a fallback.

    The PDF is built eagerly rather than behind a second click: Streamlit's
    download_button has to hold the bytes before the user presses it, so there
    is no "generate then download" step available.
    """
    incident_id = finding.get("incident_id", "incident")
    pdf_bytes = None
    error = ""
    try:
        from reports.report_generator import save_report
        pdf_bytes = Path(save_report(finding, fmt="pdf")).read_bytes()
    except ImportError:
        error = "reportlab is not installed — run `pip install reportlab`."
    except Exception as exc:
        error = f"PDF build failed: {type(exc).__name__}: {exc}"

    try:
        from reports.report_generator import generate_markdown_report
        markdown = generate_markdown_report(finding)
    except Exception:
        markdown = json.dumps(finding, indent=2, default=str)

    left, right = st.columns([1, 1])
    if pdf_bytes:
        left.download_button("📄 Download report (PDF)", data=pdf_bytes,
                             file_name=f"{incident_id}_report.pdf",
                             mime="application/pdf", type="primary",
                             key=f"pdf_{incident_id}", width="stretch")
    else:
        left.warning(error)
    right.download_button("⬇ Markdown", data=markdown,
                          file_name=f"{incident_id}_report.md",
                          mime="text/markdown", key=f"md_{incident_id}",
                          width="stretch")


def hallucination_panel(evidence: List[Dict[str, Any]]) -> Optional[str]:
    """Side-by-side proof of what the agent claimed vs what the log holds.

    Returns None when every citation verified -- there is nothing to show.
    """
    failed = [e for e in evidence if not e.get("verified")]
    if not failed:
        return None

    blocks = []
    for row in failed:
        rid = escape(str(row.get("row_id", "")))
        if not row.get("exists", True):
            blocks.append(
                f'<div><code>{rid}</code> — cited as evidence, but '
                '<span class="vc-claim">no such row exists in the raw log</span>.</div>')
        for mismatch in row.get("mismatches") or []:
            blocks.append(
                f'<div style="margin-top:6px"><code>{rid}</code> · '
                f'<b>{escape(str(mismatch.get("field","")))}</b><br>'
                f'&nbsp;&nbsp;Agent claimed: <span class="vc-claim">'
                f'{escape(str(mismatch.get("claimed","")))}</span><br>'
                f'&nbsp;&nbsp;Raw log says: <span class="vc-actual">'
                f'{escape(str(mismatch.get("actual","")))}</span></div>')

    return (f'<div class="vc-lie"><div class="hdr">🚨 Verification Layer caught '
            f'{len(failed)} false citation(s)</div>{"".join(blocks)}'
            '<div style="margin-top:10px;color:#8b98a9;font-size:0.8rem">'
            'These claims were excluded from the risk score.</div></div>')
