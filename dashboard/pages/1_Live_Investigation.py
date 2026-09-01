"""Live Investigation — watch the three agents work on a streaming log feed.

Every other team demos a static dashboard of pre-computed results. This page
shows the pipeline thinking: rows arrive one at a time, the detectors stay quiet
through normal traffic, and when a real pattern completes you see Agent 1 raise
a candidate, Agent 2 prove every citation against the raw log, and Agent 3 score
it and recommend an action.

Runs entirely in-process: no HTTP, no Groq, no network. The most demo-critical
screen in the project has the fewest ways to fail.

    streamlit run dashboard/app.py   ->   "Live Investigation" in the sidebar
"""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import time
from html import escape
from pathlib import Path
from typing import Any, Dict, List

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.transcript import transcript_html  # noqa: E402
from dashboard.ui import (  # noqa: E402
    RISK_COLORS, UNVERIFIED_COLOR, VERIFIED_COLOR, evidence_table,
    hallucination_panel, hero, inject_css, mitre_badges, risk_badge,
)

FEED_PATH = PROJECT_ROOT / "data" / "demo_feed.csv"
FEED_COLUMNS = ["row_id", "timestamp", "source", "event_type", "severity",
                "raw_fields", "source_file", "source_row"]

st.set_page_config(page_title="VerdictChain — Live Investigation",
                   page_icon="🔴", layout="wide")
inject_css()

st.markdown("""
<style>
  .vc-feed { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
             font-size: 0.78rem; }
  .vc-row { padding: 5px 10px; margin-bottom: 3px; border-radius: 6px;
            border-left: 3px solid #2a3444; background: #12161f; color: #7d8899; }
  .vc-row.sus { border-left-color: #ff8b3d; background: #1f1710; color: #ffc48b; }
  .vc-row.new { border-left-color: #00d4ff; }
  .vc-stage { padding: 9px 13px; border-radius: 8px; margin-bottom: 6px;
              border: 1px solid #232b3a; background: #12161f; color: #6b7688;
              font-size: 0.83rem; }
  .vc-stage.run  { border-color: #00d4ff; color: #00d4ff; background: #0d1b24; }
  .vc-stage.done { border-color: #2ed573; color: #2ed573; background: #0f1d16; }
  .vc-card { border: 1px solid #232b3a; border-left: 4px solid #888;
             border-radius: 10px; padding: 13px 16px; margin-bottom: 10px;
             background: #12161f; }
</style>
""", unsafe_allow_html=True)


# ── feed loading ───────────────────────────────────────────────────────────── #

@st.cache_data
def load_feed() -> List[Dict[str, Any]]:
    if not FEED_PATH.exists():
        return []
    rows = []
    with FEED_PATH.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            try:
                raw = json.loads(row.get("raw_fields") or "{}")
            except json.JSONDecodeError:
                raw = {}
            row["_phase"] = raw.get("demo_phase", "Unknown")
            row["_suspicious"] = raw.get("demo_expect") == "suspicious"
            row["_message"] = raw.get("message", "")
            rows.append(row)
    return rows


def run_agents_on(rows: List[Dict[str, Any]],
                  drill: bool = False) -> List[Dict[str, Any]]:
    """Run the real three-agent chain over the rows received so far.

    The slice is written to a temp CSV because every agent takes a log path --
    the same code path the batch pipeline uses, not a special demo shortcut.
    """
    from agents import investigation_agent
    from agents.log_analysis_agent import run_log_analysis
    from agents.verification_agent import load_normalized_logs, verify_incidents

    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False,
                                     newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEED_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        temp_path = Path(handle.name)

    try:
        incidents = run_log_analysis(str(temp_path), use_llm=False)
        if not incidents:
            return []
        if drill:
            from agents.redteam_drill import inject_hallucination
            incidents, _ = inject_hallucination(incidents)
        verified = verify_incidents(incidents, load_normalized_logs(str(temp_path)))
        return investigation_agent.investigate_all(verified, log_path=temp_path,
                                                   use_llm=False)
    finally:
        temp_path.unlink(missing_ok=True)


def feed_row_html(row: Dict[str, Any], is_new: bool = False) -> str:
    classes = "vc-row" + (" sus" if row["_suspicious"] else "") + (" new" if is_new else "")
    stamp = row["timestamp"].split("T")[-1]
    mark = "⚠" if row["_suspicious"] else "·"
    return (f'<div class="{classes}">{mark} {escape(stamp)} &nbsp; '
            f'<b>{escape(row["row_id"])}</b> &nbsp; {escape(row["source"]):<15} &nbsp; '
            f'{escape(row["event_type"])} &nbsp; <span style="opacity:.75">'
            f'{escape(row["_message"][:46])}</span></div>')


def stage_html(label: str, state: str, detail: str = "") -> str:
    icon = {"idle": "○", "run": "◐", "done": "●"}.get(state, "○")
    extra = f' <span style="opacity:.8">— {escape(detail)}</span>' if detail else ""
    return f'<div class="vc-stage {state}">{icon} {escape(label)}{extra}</div>'


def incident_card(finding: Dict[str, Any]) -> str:
    color = RISK_COLORS.get(finding["risk_level"], "#888")
    evidence = finding.get("evidence", [])
    n_ok = sum(1 for e in evidence if e.get("verified"))
    return (
        f'<div class="vc-card" style="border-left-color:{color}">'
        f'<div style="display:flex;justify-content:space-between;align-items:center">'
        f'<b style="color:#e6edf3">{escape(finding["incident_id"])}</b>'
        f'{risk_badge(finding["risk_level"])}</div>'
        f'<div style="color:#8b98a9;font-size:0.82rem;margin:7px 0">'
        f'{escape(finding.get("theory", "")[:190])}</div>'
        f'<div style="font-size:0.78rem">'
        f'<span style="color:{VERIFIED_COLOR}">✓ {n_ok}/{len(evidence)} evidence verified</span>'
        f' &nbsp;·&nbsp; <span style="color:#8b98a9">score {finding["risk_score"]:.2f}</span>'
        f'</div><div style="margin-top:7px">{mitre_badges(finding.get("mitre", []))}</div>'
        f'</div>')


# ── page ───────────────────────────────────────────────────────────────────── #

hero("🔴 Live Investigation",
     "Log rows stream in one at a time. Watch the three agents hand off in real time.")

feed = load_feed()
if not feed:
    st.error(f"No feed file at `{FEED_PATH.relative_to(PROJECT_ROOT)}`. "
             "Generate it with `python scripts/make_demo_feed.py`.")
    st.stop()

controls = st.columns([1, 1, 2])
speed = controls[0].select_slider("Feed speed", options=["Slow", "Normal", "Fast"],
                                  value="Normal")
delay = {"Slow": 0.55, "Normal": 0.28, "Fast": 0.10}[speed]
start = controls[1].button("▶ Start live feed", type="primary", width="stretch")
drill = controls[1].toggle(
    "🎯 Red-team drill", value=True,
    help="Injects a false citation into one incident before verification. Leave this "
         "on: a run where everything verifies proves nothing about the checker.")

phases = []
for row in feed:
    if not phases or phases[-1] != row["_phase"]:
        phases.append(row["_phase"])
controls[2].caption(
    f"{len(feed)} rows · phases: {' → '.join(phases)}. "
    "Quiet phases matter: they show the system is discriminating, not alarming on everything.")

st.markdown("---")
left, right = st.columns([3, 2])
left.markdown("##### 📡 Incoming log feed")
feed_box = left.empty()
right.markdown("##### 🤖 Agent pipeline")
stage_box = right.empty()
right.markdown("##### 🚨 Incidents raised")
incident_box = right.empty()

IDLE_STAGES = [("Agent 1 · Log Analysis", "idle", ""),
               ("Agent 2 · Verification", "idle", ""),
               ("Agent 3 · Investigation", "idle", "")]


def paint_stages(stages) -> None:
    stage_box.markdown("".join(stage_html(*s) for s in stages), unsafe_allow_html=True)


if not start:
    feed_box.markdown('<div class="vc-feed">' + "".join(
        feed_row_html(r) for r in feed[:8]) + "</div>", unsafe_allow_html=True)
    paint_stages(IDLE_STAGES)
    incident_box.caption("Press **Start live feed** to begin.")
    st.stop()

# ── the simulation ─────────────────────────────────────────────────────────── #

def signature(finding: Dict[str, Any]) -> tuple:
    """Stable identity for an incident across incremental runs.

    incident_id cannot be used: the Log Analysis Agent assigns INC-001, INC-002…
    by position after sorting on confidence, so ids are reshuffled every time the
    feed grows. A campaign is instead identified by who is doing it and which
    detectors fired -- both stable as more rows of the same attack arrive.
    """
    evidence = finding.get("evidence") or [{}]
    return (evidence[0].get("source", ""), tuple(finding.get("rules_fired", [])))


seen: List[Dict[str, Any]] = []
shown: Dict[tuple, Dict[str, Any]] = {}   # signature -> latest finding
paint_stages(IDLE_STAGES)
incident_box.caption("Waiting for the first correlated pattern…")

for index, row in enumerate(feed):
    seen.append(row)
    window = seen[-14:]
    feed_box.markdown('<div class="vc-feed">' + "".join(
        feed_row_html(r, is_new=(r is row)) for r in window) + "</div>",
        unsafe_allow_html=True)
    time.sleep(delay)

    # A phase ends when the next row belongs to a different phase (or the feed
    # ends). Only then can a burst be complete enough to correlate.
    next_phase = feed[index + 1]["_phase"] if index + 1 < len(feed) else None
    phase_complete = next_phase != row["_phase"]
    if not (phase_complete and row["_suspicious"]):
        continue

    paint_stages([("Agent 1 · Log Analysis", "run", "correlating flagged rows"),
                  ("Agent 2 · Verification", "idle", ""),
                  ("Agent 3 · Investigation", "idle", "")])
    time.sleep(max(delay, 0.35))

    findings = run_agents_on(seen, drill=drill)
    fresh = [f for f in findings if signature(f) not in shown]
    if not fresh:
        # Threshold not met yet -- honest outcome, not a failure.
        paint_stages([("Agent 1 · Log Analysis", "done", "no incident yet"),
                      ("Agent 2 · Verification", "idle", ""),
                      ("Agent 3 · Investigation", "idle", "")])
        continue

    cited = sum(len(f.get("evidence", [])) for f in fresh)
    paint_stages([("Agent 1 · Log Analysis", "done",
                   f"{len(fresh)} candidate(s), {cited} rows cited"),
                  ("Agent 2 · Verification", "run", "checking every citation against the raw log"),
                  ("Agent 3 · Investigation", "idle", "")])
    time.sleep(max(delay, 0.45))

    ok = sum(1 for f in fresh for e in f.get("evidence", []) if e.get("verified"))
    paint_stages([("Agent 1 · Log Analysis", "done",
                   f"{len(fresh)} candidate(s), {cited} rows cited"),
                  ("Agent 2 · Verification", "done", f"{ok}/{cited} citations proven"),
                  ("Agent 3 · Investigation", "run", "scoring risk and choosing an action")])
    time.sleep(max(delay, 0.45))

    worst = max(fresh, key=lambda f: f["risk_score"])
    paint_stages([("Agent 1 · Log Analysis", "done",
                   f"{len(fresh)} candidate(s), {cited} rows cited"),
                  ("Agent 2 · Verification", "done", f"{ok}/{cited} citations proven"),
                  ("Agent 3 · Investigation", "done",
                   f"{worst['risk_level']} · score {worst['risk_score']:.2f}")])

    # Refresh every known campaign from this run, so an incident that grew as
    # more of its rows arrived shows its current score rather than its first one.
    for finding in findings:
        shown[signature(finding)] = finding
    incident_box.markdown("".join(incident_card(f) for f in shown.values()),
                          unsafe_allow_html=True)
    time.sleep(max(delay, 0.5))

# ── wrap-up ────────────────────────────────────────────────────────────────── #

st.markdown("---")
quiet = sum(1 for r in feed if not r["_suspicious"])
st.success(f"Feed complete — {len(feed)} rows processed, {len(shown)} incident(s) "
           f"raised. The {quiet} normal rows raised nothing.")

for finding in sorted(shown.values(), key=lambda f: -f["risk_score"]):
    with st.expander(f"{finding['incident_id']} · {finding['risk_level']} "
                     f"(score {finding['risk_score']:.2f})"):
        st.markdown(f"{risk_badge(finding['risk_level'])} &nbsp; "
                    f"{mitre_badges(finding.get('mitre', []))}", unsafe_allow_html=True)
        st.markdown(f"**Theory** — {finding.get('theory', '')}")
        st.markdown(f"**Explanation** — {finding.get('explanation', '')}")
        action = finding.get("recommended_action", {})
        st.markdown(f"**Recommended action** — {action.get('action', '')}")
        st.caption(f"Auto-executed: **{action.get('auto_executed', False)}** · "
                   f"the analyst decides, the system only advises.")
        panel = hallucination_panel(finding.get("evidence", []))
        if panel:
            st.markdown(panel, unsafe_allow_html=True)
        ev_tab, tr_tab = st.tabs(["Evidence", "Agent transcript"])
        with ev_tab:
            st.markdown(evidence_table(finding.get("evidence", [])), unsafe_allow_html=True)
        with tr_tab:
            st.markdown(transcript_html(finding), unsafe_allow_html=True)
