# Owner: B3
# LangGraph pipeline: Log Analysis Agent -> Verification Agent -> Threat Investigation Agent.
"""Three-agent pipeline for SIH26S01.

    python pipeline/langgraph_pipeline.py                  # default: demo, no LLM
    python pipeline/langgraph_pipeline.py --logs data/normalized_logs.csv --llm
    python pipeline/langgraph_pipeline.py --demo --out data/findings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

from agents.log_analysis_agent import run_log_analysis
from agents.verification_agent import load_normalized_logs, verify_incidents
from agents import investigation_agent

DEFAULT_LOG = PROJECT_ROOT / "data" / "normalized_logs.csv"
DEFAULT_OUT = PROJECT_ROOT / "data" / "findings.json"


# ── shared state type ─────────────────────────────────────────────────────── #

class PipelineState(dict):
    """Typed dict-like state flowing through the graph."""
    pass


# ── node wrappers (each catches its own errors) ───────────────────────────── #

def node_analyze(state: PipelineState) -> PipelineState:
    try:
        incidents = run_log_analysis(state["log_path"], use_llm=state.get("use_llm", False))
        state["incidents"] = incidents
    except Exception as e:
        state["incidents"] = []
        state.setdefault("errors", []).append(f"LogAnalysis: {e}")
    return state


def node_drill(state: PipelineState) -> PipelineState:
    """Optional red-team step between analysis and verification.

    Off by default. When on, it injects two false citations so the Verification
    Agent can be seen catching them. See agents/redteam_drill.py.
    """
    if not state.get("drill"):
        state["drill_info"] = {"injected": False, "reason": "drill not requested"}
        return state
    try:
        from agents.redteam_drill import inject_hallucination
        state["incidents"], state["drill_info"] = inject_hallucination(
            state.get("incidents", []), lies=state.get("drill_lies", 2))
    except Exception as e:
        state["drill_info"] = {"injected": False, "reason": str(e)}
        state.setdefault("errors", []).append(f"RedTeamDrill: {e}")
    return state


def node_verify(state: PipelineState) -> PipelineState:
    try:
        df = load_normalized_logs(state["log_path"])
        state["verified_incidents"] = verify_incidents(state.get("incidents", []), df)
    except Exception as e:
        state["verified_incidents"] = state.get("incidents", [])
        state.setdefault("errors", []).append(f"Verification: {e}")
    return state


def node_investigate(state: PipelineState) -> PipelineState:
    try:
        incidents = state.get("verified_incidents") or state.get("incidents") or []
        state["findings"] = investigation_agent.investigate_all(
            incidents,
            log_path=Path(state["log_path"]),
            use_llm=state.get("use_llm", False),
        )
    except Exception as e:
        state["findings"] = []
        state.setdefault("errors", []).append(f"Investigation: {e}")
    return state


# ── graph builder (graceful fallback if langgraph missing) ─────────────────── #

def _run_plain_chain(state: PipelineState) -> PipelineState:
    """Identical logic without LangGraph — same output, always works."""
    state = node_analyze(state)
    state = node_drill(state)
    state = node_verify(state)
    state = node_investigate(state)
    return state


def _run_langgraph(state: PipelineState) -> PipelineState:
    from langgraph.graph import StateGraph, END
    graph = StateGraph(dict)
    graph.add_node("analyze", node_analyze)
    graph.add_node("drill", node_drill)
    graph.add_node("verify", node_verify)
    graph.add_node("investigate", node_investigate)
    graph.add_edge("analyze", "drill")
    graph.add_edge("drill", "verify")
    graph.add_edge("verify", "investigate")
    graph.add_edge("investigate", END)
    graph.set_entry_point("analyze")
    app = graph.compile()
    return PipelineState(app.invoke(dict(state)))


def run_pipeline(log_path: str | Path = DEFAULT_LOG,
                 use_llm: bool = False,
                 force_plain: bool = False,
                 drill: bool = False,
                 drill_lies: int = 2) -> PipelineState:
    state = PipelineState(log_path=str(log_path), use_llm=use_llm,
                          drill=drill, drill_lies=drill_lies, errors=[])
    if force_plain:
        return _run_plain_chain(state)
    try:
        return _run_langgraph(state)
    except ImportError:
        return _run_plain_chain(state)


# ── CLI ────────────────────────────────────────────────────────────────────── #

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Run the 3-agent pipeline.")
    p.add_argument("--logs", default=str(DEFAULT_LOG))
    p.add_argument("--out", default=str(DEFAULT_OUT))
    p.add_argument("--llm", action="store_true")
    p.add_argument("--plain", action="store_true", help="skip LangGraph, use plain chain")
    p.add_argument("--drill", action="store_true",
                   help="red-team drill: inject false citations to prove verification catches them")
    p.add_argument("--drill-lies", type=int, default=2, metavar="N",
                   help="how many false citations the drill injects (default 2)")
    args = p.parse_args(argv)

    state = run_pipeline(args.logs, use_llm=args.llm, force_plain=args.plain,
                         drill=args.drill, drill_lies=args.drill_lies)
    findings = state.get("findings", [])

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(findings, indent=2, default=str), encoding="utf-8")

    print(f"{len(findings)} findings -> {args.out}")
    for f in findings:
        print(f"  {f['incident_id']}  {f['risk_level']:8s}  score={f['risk_score']:.2f}  "
              f"verified={f['verified']}  rows={len(f['evidence'])}")

    if state.get("errors"):
        print("\nErrors:", state["errors"])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
