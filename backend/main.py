# Owner: B3
# FastAPI backend for the SIH26S01 Cybersecurity Assistant.
"""
    uvicorn backend.main:app --reload
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.langgraph_pipeline import run_pipeline
from reports.report_generator import generate_markdown_report, save_report

FINDINGS_PATH = PROJECT_ROOT / "data" / "findings.json"
DEFAULT_LOG = PROJECT_ROOT / "data" / "normalized_logs.csv"

app = FastAPI(title="VerdictChain — Cybersecurity Assistant", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

# In-memory store for the current run, plus the mtime it was loaded from.
_findings: List[Dict[str, Any]] = []
_findings_mtime: float = 0.0


def _load_cached() -> List[Dict[str, Any]]:
    """Return the current findings, reloading if findings.json changed on disk.

    Caching only on "is the list empty" would serve a stale run forever: the
    pipeline can also be run from the CLI or from the dashboard's offline path,
    both of which rewrite findings.json without going through this process. The
    dashboard would then keep showing the previous run with no visible clue.
    """
    global _findings, _findings_mtime
    if not FINDINGS_PATH.exists():
        return _findings
    mtime = FINDINGS_PATH.stat().st_mtime
    if mtime != _findings_mtime or not _findings:
        _findings = json.loads(FINDINGS_PATH.read_text(encoding="utf-8"))
        _findings_mtime = mtime
    return _findings


@app.on_event("startup")
def startup():
    _load_cached()


# ── endpoints ──────────────────────────────────────────────────────────────── #

@app.post("/run-investigation")
def run_investigation(use_llm: bool = False, drill: bool = False):
    """Run the full 3-agent pipeline.

    drill=True injects false citations before verification so the Verification
    Layer can be seen catching them. See agents/redteam_drill.py.
    """
    global _findings, _findings_mtime
    state = run_pipeline(str(DEFAULT_LOG), use_llm=use_llm, drill=drill)
    _findings = state.get("findings", [])
    FINDINGS_PATH.write_text(json.dumps(_findings, indent=2, default=str), encoding="utf-8")
    _findings_mtime = FINDINGS_PATH.stat().st_mtime
    return {
        "status": "ok",
        "incident_count": len(_findings),
        "drill": state.get("drill_info", {"injected": False}),
        "errors": state.get("errors", []),
    }


@app.get("/incidents")
def get_incidents(risk_level: Optional[str] = None, verified: Optional[bool] = None):
    results = _load_cached()
    if risk_level:
        results = [f for f in results if f["risk_level"].lower() == risk_level.lower()]
    if verified is not None:
        results = [f for f in results if f["verified"] == verified]
    return results


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    for f in _load_cached():
        if f["incident_id"] == incident_id:
            return f
    raise HTTPException(404, f"Incident {incident_id} not found")


@app.get("/incidents/{incident_id}/report")
def get_report(incident_id: str, fmt: str = Query("markdown", pattern="^(markdown|pdf)$")):
    finding = None
    for f in _load_cached():
        if f["incident_id"] == incident_id:
            finding = f
            break
    if not finding:
        raise HTTPException(404, f"Incident {incident_id} not found")

    path = save_report(finding, fmt=fmt)
    return FileResponse(str(path), filename=path.name,
                        media_type="application/pdf" if fmt == "pdf" else "text/markdown")


@app.get("/stats")
def stats():
    findings = _load_cached()
    levels = {}
    verified_count = unverified_count = 0
    for f in findings:
        levels[f["risk_level"]] = levels.get(f["risk_level"], 0) + 1
        for e in f.get("evidence", []):
            if e.get("verified"):
                verified_count += 1
            else:
                unverified_count += 1
    return {
        "total_incidents": len(findings),
        "risk_levels": levels,
        "verified_evidence": verified_count,
        "unverified_evidence": unverified_count,
    }


@app.get("/metrics")
def detection_metrics():
    """Precision/recall against the CICIDS2017 ground-truth labels."""
    metrics_path = PROJECT_ROOT / "data" / "metrics.json"
    if not metrics_path.exists():
        raise HTTPException(404, "No metrics yet -- run scripts/compute_metrics.py")
    return json.loads(metrics_path.read_text(encoding="utf-8"))


@app.get("/health")
def health():
    return {"status": "ok", "findings_loaded": len(_load_cached())}
