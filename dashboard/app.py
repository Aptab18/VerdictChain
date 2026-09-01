# Owner: B3
# Streamlit dashboard for the SIH26S01 Cybersecurity Assistant.
"""SOC command view: triage incidents, inspect evidence, prove verification.

    streamlit run dashboard/app.py

Theme lives in .streamlit/config.toml, not in CSS overrides here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.transcript import transcript_html  # noqa: E402
from dashboard.ui import (  # noqa: E402
    API_URL, FINDINGS_PATH, RISK_COLORS, RISK_ORDER, UNVERIFIED_COLOR, VERIFIED_COLOR,
    api_online, evidence_table, hallucination_panel, hero, inject_css, load_findings,
    load_metrics, mitre_badges, render_download, risk_badge, tile, verdict_badge,
)

st.set_page_config(page_title="VerdictChain — SOC Console",
                   page_icon="🛡️", layout="wide")
inject_css()

CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#8b98a9", size=12), margin=dict(l=10, r=10, t=34, b=10),
)


# ── charts ─────────────────────────────────────────────────────────────────── #

def risk_donut(counts: Dict[str, int]) -> go.Figure:
    levels = [lv for lv in RISK_ORDER if counts.get(lv)]
    fig = go.Figure(go.Pie(
        labels=levels, values=[counts[lv] for lv in levels], hole=0.62,
        marker=dict(colors=[RISK_COLORS[lv] for lv in levels],
                    line=dict(color="#0e1117", width=2)),
        textinfo="value", textfont=dict(size=15, color="#0e1117"),
        hovertemplate="%{label}: %{value} incidents<extra></extra>", sort=False,
    ))
    total = sum(counts.values())
    fig.update_layout(
        title=dict(text="Risk distribution", font=dict(size=13, color="#e6edf3")),
        showlegend=True, height=270,
        legend=dict(orientation="h", y=-0.12, font=dict(size=11)),
        annotations=[dict(text=f"<b>{total}</b><br>incidents", showarrow=False,
                          font=dict(size=15, color="#e6edf3"))],
        **CHART_LAYOUT)
    return fig


def verification_donut(verified: int, unverified: int) -> go.Figure:
    fig = go.Figure(go.Pie(
        labels=["Verified", "Unverified"], values=[verified, unverified], hole=0.62,
        marker=dict(colors=[VERIFIED_COLOR, UNVERIFIED_COLOR],
                    line=dict(color="#0e1117", width=2)),
        textinfo="percent", textfont=dict(size=14, color="#0e1117"),
        hovertemplate="%{label}: %{value} rows<extra></extra>", sort=False,
    ))
    total = verified + unverified
    pct = (verified / total * 100) if total else 0
    fig.update_layout(
        title=dict(text="Evidence verification", font=dict(size=13, color="#e6edf3")),
        showlegend=True, height=270,
        legend=dict(orientation="h", y=-0.12, font=dict(size=11)),
        annotations=[dict(text=f"<b>{pct:.0f}%</b><br>proven", showarrow=False,
                          font=dict(size=15, color="#e6edf3"))],
        **CHART_LAYOUT)
    return fig


def incident_timeline(findings: List[Dict[str, Any]]) -> go.Figure | None:
    """How long each incident ran, worst first.

    This was an absolute-time timeline, which cannot work here: the corpus
    mixes CICIDS2017 captures (July 2017) with synthetic demo logs (2026), so
    the axis spanned nine years and every bar collapsed into an invisible
    sliver. Incidents from disjoint captures never overlap in real time
    anyway, so "when" carries no information the analyst can act on.

    Duration does. It separates a 60-minute slow credential campaign from a
    20-minute flood at a glance, and the absolute start time stays available
    on the bar label and in the hover.
    """
    bars = []
    for finding in findings:
        stamps = pd.to_datetime(
            [e.get("timestamp") for e in finding.get("evidence", []) if e.get("timestamp")],
            errors="coerce", format="mixed").dropna()
        if len(stamps) == 0:
            continue
        start, end = stamps.min(), stamps.max()
        seconds = (end - start).total_seconds()
        bars.append((finding, start, max(seconds, 30)))  # a single-row incident still needs width

    if not bars:
        return None

    bars.sort(key=lambda b: -b[0]["risk_score"])

    fig = go.Figure(go.Bar(
        x=[seconds for _, _, seconds in bars],
        y=[finding["incident_id"] for finding, _, _ in bars],
        orientation="h", width=0.6,
        marker=dict(color=[RISK_COLORS.get(f["risk_level"], "#8b98a9") for f, _, _ in bars],
                    line=dict(width=0)),
        text=[f"{seconds:,.0f}s · {start:%d %b %H:%M}" for _, start, seconds in bars],
        textposition="outside", textfont=dict(color="#8b98a9", size=11),
        customdata=[[f["risk_level"], f["risk_score"], len(f.get("evidence", [])),
                     f"{start:%Y-%m-%d %H:%M}"] for f, start, _ in bars],
        hovertemplate=("<b>%{y}</b> · %{customdata[0]} · score %{customdata[1]}"
                       "<br>%{x:,.0f} seconds, %{customdata[2]} evidence rows"
                       "<br>started %{customdata[3]}<extra></extra>"),
    ))
    longest = max(seconds for _, _, seconds in bars)
    fig.update_layout(
        title=dict(text="How long each attack ran",
                   font=dict(size=13, color="#e6edf3")),
        height=max(240, 34 * len(bars)), bargap=0.35,
        xaxis=dict(title=dict(text="attack duration in seconds (first cited row → last)",
                              font=dict(size=11)),
                   range=[0, longest * 1.45], gridcolor="#1b2230", showline=False),
        yaxis=dict(autorange="reversed", gridcolor="rgba(0,0,0,0)"),
        **CHART_LAYOUT)
    return fig


def class_recall_bars(per_class: List[Dict[str, Any]]) -> go.Figure:
    attacks = [c for c in per_class if c["is_attack"]]
    benign = [c for c in per_class if not c["is_attack"]]
    labels = [c["label"] for c in attacks] + [f"{c['label']} (false alarms)" for c in benign]
    values = [c["rate"] * 100 for c in attacks] + [c["rate"] * 100 for c in benign]
    colors = ["#2ed573"] * len(attacks) + ["#ff8b3d"] * len(benign)

    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker=dict(color=colors), width=0.55,
        text=[f"{v:.1f}%" for v in values], textposition="outside",
        textfont=dict(color="#e6edf3", size=11),
        hovertemplate="%{y}: %{x:.1f}%<extra></extra>",
    ))
    fig.update_layout(
        title=dict(text="Detection rate by traffic class (CICIDS2017 ground truth)",
                   font=dict(size=13, color="#e6edf3")),
        height=250, xaxis=dict(range=[0, 112], ticksuffix="%", gridcolor="#1b2230"),
        yaxis=dict(autorange="reversed"), **CHART_LAYOUT)
    return fig


# ── sidebar ────────────────────────────────────────────────────────────────── #

online = api_online()

with st.sidebar:
    st.markdown("### 🛡️ VerdictChain")
    st.caption("Agentic AI Cybersecurity Assistant")
    st.markdown(
        f'<span class="vc-badge" style="background:{"#2ed57322" if online else "#ff8b3d22"};'
        f'color:{"#2ed573" if online else "#ff8b3d"}">'
        f'{"API ONLINE" if online else "OFFLINE MODE"}</span>',
        unsafe_allow_html=True)
    st.markdown("---")

    from agents import llm as _llm
    use_llm = st.toggle(f"Use {(_llm.provider_name() or 'LLM').title()} for explanations",
                        value=False,
                        help="Off = deterministic templates only. The demo never depends "
                             "on the network. Provider: " + _llm.describe())
    drill = st.toggle("🎯 Red-team drill", value=False,
                      help="Injects two false citations before verification, to prove the "
                           "Verification Layer catches them. Clearly labelled as a drill.")

    if st.button("▶ Run Investigation", width="stretch", type="primary"):
        with st.spinner("Running Analysis → Verification → Investigation..."):
            done = False
            if online:
                try:
                    import requests
                    response = requests.post(
                        f"{API_URL}/run-investigation",
                        params={"use_llm": use_llm, "drill": drill}, timeout=180)
                    done = response.ok
                except Exception:
                    done = False
            if not done:                        # offline fallback: run in-process
                from pipeline.langgraph_pipeline import run_pipeline
                state = run_pipeline(use_llm=use_llm, drill=drill)
                FINDINGS_PATH.write_text(
                    json.dumps(state.get("findings", []), indent=2, default=str),
                    encoding="utf-8")
            try:
                from scripts.compute_metrics import compute
                (PROJECT_ROOT / "data" / "metrics.json").write_text(
                    json.dumps(compute(), indent=2), encoding="utf-8")
            except Exception:
                pass                            # metrics are a bonus, never a blocker
        st.rerun()

    st.markdown("---")
    level_filter = st.multiselect("Risk level", RISK_ORDER, default=RISK_ORDER)
    only_unverified = st.checkbox("Only incidents with unverified evidence")
    st.markdown("---")
    st.caption("Every citation is checked against the raw data before it reaches the analyst.")


# ── load ───────────────────────────────────────────────────────────────────── #

all_findings = load_findings(use_api=online)
metrics = load_metrics()

if not all_findings:
    hero("VerdictChain — SOC Console", "No investigation has been run yet.")
    st.info("Click **Run Investigation** in the sidebar to analyse the normalized log.")
    st.stop()

findings = [f for f in all_findings if f["risk_level"] in level_filter]
if only_unverified:
    findings = [f for f in findings
                if any(not e.get("verified") for e in f.get("evidence", []))]

counts = {lv: 0 for lv in RISK_ORDER}
verified_ev = unverified_ev = 0
drill_incidents = []
for finding in all_findings:
    counts[finding["risk_level"]] = counts.get(finding["risk_level"], 0) + 1
    for row in finding.get("evidence", []):
        if row.get("verified"):
            verified_ev += 1
        else:
            unverified_ev += 1
    if any(not e.get("verified") for e in finding.get("evidence", [])):
        drill_incidents.append(finding["incident_id"])

total_ev = verified_ev + unverified_ev

hero("VerdictChain — SOC Console",
     "Log Analysis → Verification → Threat Investigation. Every citation proven against the raw log.")

if unverified_ev:
    st.warning(
        f"⚠️ **{unverified_ev} cited row(s) failed verification** across "
        f"{len(drill_incidents)} incident(s): {', '.join(drill_incidents)}. "
        "Open the incident below to see exactly what the agent claimed versus what the log holds.")

# ── summary tiles ──────────────────────────────────────────────────────────── #

cols = st.columns(6)
tile(cols[0], len(all_findings), "Incidents")
tile(cols[1], counts.get("Critical", 0), "Critical", RISK_COLORS["Critical"])
tile(cols[2], counts.get("High", 0), "High", RISK_COLORS["High"])
tile(cols[3], counts.get("Medium", 0) + counts.get("Low", 0), "Medium + Low",
     RISK_COLORS["Medium"])
tile(cols[4], f"{verified_ev}/{total_ev}", "Evidence verified", VERIFIED_COLOR,
     f"{verified_ev / total_ev * 100:.1f}% proven" if total_ev else "")
if metrics:
    tile(cols[5], f"{metrics['precision']:.0%}", "Detection precision", "#00d4ff",
         f"recall {metrics['recall']:.0%} · ground truth")
else:
    tile(cols[5], "—", "Detection precision", "#6b7688", "run compute_metrics.py")

st.write("")

# ── charts ─────────────────────────────────────────────────────────────────── #

left, right = st.columns(2)
left.plotly_chart(risk_donut(counts), width="stretch",
                  config={"displayModeBar": False})
right.plotly_chart(verification_donut(verified_ev, unverified_ev),
                   width="stretch", config={"displayModeBar": False})

timeline = incident_timeline(all_findings)
if timeline is not None:
    st.plotly_chart(timeline, width="stretch", config={"displayModeBar": False})
    st.caption(
        "How long the attacker stayed active, taken from the log timestamps — not "
        "how long the pipeline took to find it. A long bar is a slow-and-quiet "
        "campaign pacing itself under burst thresholds; a short bar is a loud "
        "flood. Both are caught.")

# ── detection metrics ──────────────────────────────────────────────────────── #

if metrics:
    with st.expander("📈 Detection metrics — measured against CICIDS2017 ground-truth labels",
                     expanded=False):
        confusion = metrics["confusion"]
        consolidation = metrics["consolidation"]

        mcols = st.columns(5)
        tile(mcols[0], f"{metrics['precision']:.1%}", "Precision", "#2ed573",
             "of what we flagged, this much was real attack traffic")
        tile(mcols[1], f"{metrics['recall']:.1%}", "Recall", "#00d4ff",
             "of all attack traffic, this much was surfaced")
        tile(mcols[2], f"{metrics['f1']:.1%}", "F1 score", "#8b7cf6")
        tile(mcols[3], f"{metrics['false_positive_rate']:.1%}", "False-positive rate",
             "#ff8b3d", "on benign traffic")
        tile(mcols[4], f"{consolidation['log_rows_examined']:,}", "Rows examined",
             "#e6edf3", f"consolidated into {consolidation['incidents_raised']} incidents")

        st.write("")
        st.plotly_chart(class_recall_bars(metrics["per_class"]),
                        width="stretch", config={"displayModeBar": False})
        st.caption(
            f"Confusion matrix on {metrics['labelled_rows']:,} labelled rows — "
            f"TP {confusion['tp']} · FP {confusion['fp']} · "
            f"FN {confusion['fn']} · TN {confusion['tn']}. "
            "Only rows from raw_subset.csv are scored; the synthetic demo rows carry "
            "no ground truth, so including them would inflate these numbers.")

st.markdown("---")

# ── incident list ──────────────────────────────────────────────────────────── #

st.subheader(f"Incidents ({len(findings)} shown)")

for finding in findings:
    evidence = finding.get("evidence", [])
    n_verified = sum(1 for e in evidence if e.get("verified"))
    failed = len(evidence) - n_verified
    flag = "🚨 " if failed else ""

    header = (f"{flag}{finding['incident_id']} · {finding['risk_level']} "
              f"(score {finding['risk_score']:.2f}) · {n_verified}/{len(evidence)} evidence verified")

    with st.expander(header, expanded=bool(failed)):
        st.markdown(
            f"{risk_badge(finding['risk_level'])} &nbsp; "
            f"{verdict_badge(finding.get('verified', False))} &nbsp; "
            f"{mitre_badges(finding.get('mitre', []))}",
            unsafe_allow_html=True)

        if finding.get("drill_injected"):
            st.info("🎯 This incident was modified by the red-team drill — "
                    "false citations were injected on purpose to test the Verification Layer.")

        st.markdown(f"**Theory** — {finding.get('theory', 'N/A')}")
        st.markdown(f"**Explanation** — {finding.get('explanation', 'N/A')}")

        source = finding.get("explanation_source", "")
        st.caption(f"Explanation source: `{source}`"
                   + ("  ·  written by Groq, grounded against the verified evidence"
                      if source == "llm" else
                      "  ·  deterministic template (no LLM call was used)"))

        panel = hallucination_panel(evidence)
        if panel:
            st.markdown(panel, unsafe_allow_html=True)

        breakdown = finding.get("score_breakdown", {})
        bcols = st.columns(5)
        tile(bcols[0], f"{breakdown.get('threat_weight', 0):.2f}", "Threat weight")
        tile(bcols[1], f"{breakdown.get('confidence_factor', 0):.2f}", "Confidence")
        tile(bcols[2], f"{breakdown.get('verification_factor', 0):.2f}", "Verification",
             VERIFIED_COLOR if breakdown.get("verification_factor", 0) >= 1 else UNVERIFIED_COLOR)
        tile(bcols[3], f"{breakdown.get('volume_factor', 0):.2f}", "Volume")
        tile(bcols[4], f"{finding['risk_score']:.2f}", "Final score",
             RISK_COLORS.get(finding["risk_level"], "#e6edf3"))
        st.caption("threat × confidence × verification × volume — no black box, every "
                   "factor is inspectable.")

        if breakdown.get("capped_by_verification"):
            st.warning("Risk level was **capped at Medium**: not one cited row could be "
                       "proven against the raw log.")
        if breakdown.get("unmapped_rules"):
            st.caption(f"⚙️ Rules with no risk weight configured: "
                       f"{', '.join(breakdown['unmapped_rules'])}")

        action = finding.get("recommended_action", {})
        st.markdown(f"**Recommended action** — {action.get('action', 'N/A')}")
        st.caption(f"{action.get('rationale', '')}  \n"
                   f"Auto-executed: **{action.get('auto_executed', False)}** · "
                   f"Requires analyst approval: **{action.get('requires_analyst_approval', True)}**")

        ev_tab, tr_tab = st.tabs([f"Evidence ({len(evidence)} rows)", "Agent transcript"])
        with ev_tab:
            st.markdown(evidence_table(evidence), unsafe_allow_html=True)
            if len(evidence) > 60:
                st.caption(f"Showing the first 60 of {len(evidence)} rows.")
        with tr_tab:
            st.markdown(transcript_html(finding), unsafe_allow_html=True)

        render_download(finding)

st.markdown("---")
st.caption("VerdictChain · Every other team's AI can tell you a threat exists. "
           "Ours also proves it.")
