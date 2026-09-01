# Owner: B2
# Threat Investigation Agent — assigns risk level, writes evidence-backed
# explanation, and recommends a response action for verified incidents.
"""Threat Investigation Agent (Agent 3) for SIH26S01.

Pipeline position:
    Log Analysis Agent (B1) -> Verification Agent (B2) -> THIS AGENT -> Report/Dashboard

Input contract (one dict per incident, as produced by the Verification Agent).
Only ``incident_id`` is strictly required; everything else degrades gracefully::

    {
      "incident_id":  "INC-001",
      "theory":       "Repeated failed logins from a single IP outside office hours",
      "confidence":   0.74,          # confidence AFTER verification adjustment
      "cited_rows":   ["12", "13", "17"],
      "verified":     true,          # false if any cited row failed verification
      "row_checks": [                # optional, richer per-row verification detail
        {"row_id": "12", "verified": true, "row": {...normalized log row...}}
      ]
    }

Output contract (consumed by report_generator.py and the Streamlit dashboard)::

    {
      "incident_id", "risk_level", "risk_score", "confidence", "verified",
      "verified_ratio", "theory", "explanation", "explanation_source",
      "recommended_action": {"action", "rationale", "auto_executed": false},
      "evidence": [{"row_id", "verified", "timestamp", "source", "event_type",
                    "severity", "source_file", "summary"}],
      "score_breakdown", "generated_at"
    }

Design notes:
  * Risk scoring is fully deterministic (no LLM) so the live demo can never fail.
  * The LLM (Groq) only writes the plain-English explanation, and its output is
    ground-checked against the evidence rows before it is accepted.
  * Unverified evidence caps the risk level at Medium -- this is the visible
    payoff of our Verification Layer differentiator.
  * Actions are RECOMMENDED ONLY. Nothing is auto-executed, per the problem statement.
"""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = PROJECT_ROOT / "data" / "normalized_logs.csv"
ENV_PATH = PROJECT_ROOT / ".env"


def load_env(env_path: Optional[Path] = None) -> None:
    """Load GROQ_API_KEY (and friends) from the project .env file.

    Uses python-dotenv when it is installed, otherwise falls back to a tiny
    KEY=VALUE parser so the agent works with no extra dependency. Values
    already present in the real environment always win.
    """
    path = Path(env_path or ENV_PATH)
    try:
        from dotenv import load_dotenv
        load_dotenv(path, override=False)
        return
    except ImportError:
        pass

    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lstrip("﻿")
        if key.lower().startswith("export "):
            key = key[7:].strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


load_env()

GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

RISK_LEVELS = ("Low", "Medium", "High", "Critical")

# How dangerous each event type is on its own (0.0 - 1.0).
EVENT_RISK: Dict[str, float] = {
    "ransomware": 1.00,
    "data_exfiltration": 1.00,
    "privilege_escalation": 0.95,
    "malware": 0.95,
    "ddos": 0.90,
    "brute_force": 0.85,
    "credential_stuffing": 0.85,
    "unauthorized_access": 0.80,
    "lateral_movement": 0.80,
    "port_scan": 0.70,
    "traffic_spike": 0.65,
    "failed_login": 0.55,
    "off_hours_login": 0.50,
    "unusual_login_time": 0.50,
    "new_device": 0.45,
    "unrecognized_device": 0.45,
    "config_change": 0.40,
    "file_access": 0.30,
    "login": 0.20,
    "benign": 0.10,
    "normal": 0.10,
}

# Fallback when event_type is unknown but the row carries a severity label.
SEVERITY_RISK: Dict[str, float] = {
    "critical": 1.00,
    "high": 0.85,
    "warning": 0.55,      # dominant label in data/normalized_logs.csv (D3 schema)
    "warn": 0.55,
    "medium": 0.55,
    "notice": 0.30,
    "low": 0.30,
    "informational": 0.10,
    "info": 0.10,
}

# Recommended response per event family: (event families, action, rationale).
ACTION_PLAYBOOK: List[Tuple[Tuple[str, ...], str, str]] = [
    (("ransomware", "malware"),
     "Isolate the affected host from the network and start malware triage",
     "Malware indicators spread laterally, so containment is the first priority."),
    (("data_exfiltration",),
     "Block outbound traffic to the destination and preserve the host for forensics",
     "Large outbound transfers to an unusual destination suggest data leaving the network."),
    (("privilege_escalation", "unauthorized_access", "lateral_movement"),
     "Suspend the account, force a credential reset, then review its recent activity",
     "The account is behaving outside its normal privilege boundary."),
    (("ddos", "traffic_spike"),
     "Rate-limit or block the source IP at the perimeter and monitor service health",
     "Request volume from this source is far above the normal baseline."),
    (("brute_force", "credential_stuffing", "failed_login"),
     "Block the source IP and flag the targeted account for review",
     "Repeated authentication failures from one source indicate a guessing attack."),
    (("port_scan",),
     "Block the scanning IP and check which ports responded",
     "Port scanning is typically reconnaissance ahead of an intrusion attempt."),
    (("off_hours_login", "unusual_login_time"),
     "Verify the user's identity out-of-band before allowing further access",
     "Access outside the user's normal working hours needs human confirmation."),
    (("new_device", "unrecognized_device"),
     "Flag the device for review and require re-authentication",
     "An unrecognized device on the account may indicate a session or token compromise."),
    (("config_change",),
     "Review the configuration change against the change-management record",
     "Unplanned configuration changes can silently weaken security controls."),
]

# Fallback action when no playbook entry matches the observed event types.
LEVEL_ACTION: Dict[str, Tuple[str, str]] = {
    "Critical": ("Escalate to the on-call security engineer immediately",
                 "Score is in the critical band and needs a human owner now."),
    "High": ("Open a priority ticket and investigate the source within the hour",
             "Score is high enough to warrant same-shift investigation."),
    "Medium": ("Queue for analyst review during this shift",
               "Activity is suspicious but not yet confirmed as an attack."),
    "Low": ("Log for trend analysis; no immediate action required",
            "Signal is weak and consistent with routine noise."),
}

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _norm_key(value: Any) -> str:
    """Lowercase a label and squash separators, e.g. 'Brute Force' -> 'brute_force'."""
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _row_id_variants(row_id: Any) -> set:
    """Accept '12', 12, 'row_12', 'ROW-12' as the same row reference."""
    raw = str(row_id).strip()
    variants = {raw, raw.lower()}
    digits = re.sub(r"^\D*", "", raw)
    if digits.isdigit():
        variants.update({digits, "row_" + digits, "row-" + digits})
    return variants


# --------------------------------------------------------------------------- #
# Evidence assembly
# --------------------------------------------------------------------------- #

def load_log_index(log_path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Index normalized_logs.csv by every plausible row-id form.

    Returns an empty index (never raises) if the file is missing, so the agent
    still runs before the Data team's output is in place.
    """
    path = Path(log_path or DEFAULT_LOG_PATH)
    index: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return index

    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        for position, row in enumerate(csv.DictReader(handle)):
            explicit = row.get("row_id") or row.get("id") or row.get("index")
            for key in _row_id_variants(explicit if explicit else position):
                index.setdefault(key, row)
    return index


def _summarize_row(row: Dict[str, Any]) -> str:
    """One-line human-readable description of a normalized log row."""
    parts = [row.get("timestamp"), row.get("source"), row.get("event_type")]
    text = " | ".join(str(p) for p in parts if p)
    severity = row.get("severity")
    if severity:
        text = text + " (severity: " + str(severity) + ")"
    return text or "no row detail available"


def build_evidence(incident: Dict[str, Any],
                   log_index: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Merge the Verification Agent's per-row results with the raw log rows.

    Preference order for each cited row:
      1. its ``row_checks`` entry from the Verification Agent (carries verified flag)
      2. a lookup in normalized_logs.csv by row id
      3. a placeholder marked unverified
    """
    log_index = log_index if log_index is not None else {}

    # Index the verification agent's per-row detail, whatever it named the list.
    checks_raw = (incident.get("row_checks")
                  or incident.get("verification_details")
                  or incident.get("checks")
                  or [])
    checks: Dict[str, Dict[str, Any]] = {}
    for check in checks_raw:
        if not isinstance(check, dict):
            continue
        for key in _row_id_variants(check.get("row_id", check.get("id"))):
            checks.setdefault(key, check)

    incident_verified = incident.get("verified")

    cited = incident.get("cited_rows")
    if not cited:
        cited = [c.get("row_id") for c in checks_raw if isinstance(c, dict)]

    evidence: List[Dict[str, Any]] = []
    for row_id in cited:
        keys = _row_id_variants(row_id)
        check = next((checks[k] for k in keys if k in checks), None)
        row = (check or {}).get("row") or next((log_index[k] for k in keys if k in log_index), None)

        if check is not None and "verified" in check:
            verified = bool(check.get("verified"))
        elif check is not None and "exists" in check:
            verified = bool(check.get("exists")) and bool(check.get("matched", True))
        elif row is not None:
            # No per-row detail, but the row really is in the log file.
            verified = bool(incident_verified) if incident_verified is not None else True
        else:
            verified = False

        row = row or {}
        evidence.append({
            "row_id": str(row_id),
            "verified": verified,
            "timestamp": row.get("timestamp", ""),
            "source": row.get("source", ""),
            "event_type": row.get("event_type", ""),
            "severity": row.get("severity", ""),
            "source_file": row.get("source_file", ""),
            "summary": _summarize_row(row) if row else "row not found in normalized_logs.csv",
        })
    return evidence


# --------------------------------------------------------------------------- #
# Risk scoring (deterministic, demo-safe)
# --------------------------------------------------------------------------- #

def _row_weight(row: Dict[str, Any]) -> float:
    """Danger weight for a single evidence row, from event_type AND severity.

    Both signals are consulted and the strongest wins. Returning on the first
    event_type hit (the previous behaviour) under-rated real data badly: our
    normalized logs use generic event types where the danger is carried by the
    severity column, so a "login_success" marked severity=warning -- the actual
    breach login in INC-001, straight after 10 failed attempts -- scored 0.20
    off the generic "login" key and never looked at its severity, ranking it
    *below* the failed logins around it.
    """
    candidates = [0.0]

    event = _norm_key(row.get("event_type"))
    if event in EVENT_RISK:
        candidates.append(EVENT_RISK[event])
    elif event:
        # Partial match, e.g. "ssh_brute_force" -> brute_force, "dos_hulk" -> ddos.
        # Take the strongest match, not whichever the dict happens to yield first.
        candidates.extend(
            weight for known, weight in EVENT_RISK.items()
            if known in event or event in known
        )

    severity = _norm_key(row.get("severity"))
    if severity in SEVERITY_RISK:
        candidates.append(SEVERITY_RISK[severity])

    best = max(candidates)
    # Nothing recognised at all: middling, never harmless.
    return best if best > 0.0 else 0.5


def score_incident(incident: Dict[str, Any],
                   evidence: List[Dict[str, Any]]) -> Tuple[float, str, Dict[str, Any]]:
    """Return (risk_score, risk_level, breakdown).

    score = threat_weight * confidence_factor * verification_factor * volume_factor

    The verification factor is what makes our Verification Layer visible in the
    numbers: evidence that could not be matched back to the raw log file drags
    the score down, and a fully unverified incident is capped at Medium.
    """
    verified_rows = [e for e in evidence if e["verified"]]
    # Score on verified evidence when we have any; unverified rows only penalise.
    scoring_rows = verified_rows or evidence
    threat_weight = max((_row_weight(r) for r in scoring_rows), default=0.5)

    confidence = _clamp(_to_float(incident.get("confidence"), 0.5))
    confidence_factor = 0.55 + 0.45 * confidence

    total = len(evidence)
    verified_ratio = (len(verified_rows) / total) if total else 0.0
    verification_factor = (0.40 + 0.60 * verified_ratio) if total else 0.60

    # A correlated cluster of rows is more convincing than a single row.
    volume_factor = 1.0 + min(0.15, 0.05 * max(0, len(verified_rows) - 1))

    score = _clamp(threat_weight * confidence_factor * verification_factor * volume_factor)

    if score >= 0.80:
        level = "Critical"
    elif score >= 0.60:
        level = "High"
    elif score >= 0.35:
        level = "Medium"
    else:
        level = "Low"

    capped = False
    if not verified_rows and RISK_LEVELS.index(level) > RISK_LEVELS.index("Medium"):
        # Nothing in this incident could be proved against the raw logs.
        level, capped = "Medium", True

    breakdown = {
        "threat_weight": round(threat_weight, 3),
        "confidence_factor": round(confidence_factor, 3),
        "verification_factor": round(verification_factor, 3),
        "volume_factor": round(volume_factor, 3),
        "verified_rows": len(verified_rows),
        "total_rows": total,
        "capped_by_verification": capped,
    }
    return round(score, 3), level, breakdown


# --------------------------------------------------------------------------- #
# Recommended action (recommend only, never execute)
# --------------------------------------------------------------------------- #

def recommend_action(evidence: List[Dict[str, Any]],
                     risk_level: str,
                     verified_ratio: float) -> Dict[str, Any]:
    events = {_norm_key(e.get("event_type")) for e in evidence if e.get("event_type")}

    action = rationale = None
    for families, act, why in ACTION_PLAYBOOK:
        if any(fam in ev or ev in fam for fam in families for ev in events if ev):
            action, rationale = act, why
            break

    if action is None:
        action, rationale = LEVEL_ACTION[risk_level]

    if verified_ratio < 1.0:
        rationale += (" Some cited evidence could not be verified against the raw"
                      " logs, so confirm the evidence before acting.")

    return {
        "action": action,
        "rationale": rationale,
        "auto_executed": False,          # explicit: the system never acts on its own
        "requires_analyst_approval": True,
    }


# --------------------------------------------------------------------------- #
# Explanation: template baseline + optional Groq LLM with grounding check
# --------------------------------------------------------------------------- #

def _template_explanation(incident: Dict[str, Any],
                          evidence: List[Dict[str, Any]],
                          risk_level: str,
                          risk_score: float) -> str:
    verified = [e for e in evidence if e["verified"]]
    unverified = [e for e in evidence if not e["verified"]]
    theory = (incident.get("theory") or "Anomalous activity detected in the logs.").strip()

    sources = sorted({e["source"] for e in verified if e.get("source")})
    events = sorted({e["event_type"] for e in verified if e.get("event_type")})

    lines = ["{} This incident is rated {} (risk score {:.2f}).".format(
        theory, risk_level, risk_score)]

    if sources or events:
        lines.append(
            "The activity involves "
            + (("source(s) " + ", ".join(sources)) if sources else "an unidentified source")
            + ((" and event type(s) " + ", ".join(events) + ".") if events else ".")
        )
    if verified:
        cited = ", ".join(
            "row {} ({})".format(e["row_id"], e["summary"]) for e in verified[:5]
        )
        lines.append("Verified supporting evidence: " + cited + ".")
    else:
        lines.append("No cited row could be matched back to the raw log file.")
    if unverified:
        lines.append(
            "Warning: {} cited row(s) failed verification ({}); their claims were"
            " excluded from the risk score.".format(
                len(unverified), ", ".join(e["row_id"] for e in unverified))
        )
    return " ".join(lines)


def _ground_check(text: str,
                  evidence: List[Dict[str, Any]],
                  extra_context: str = "") -> bool:
    """Reject an explanation that cites an IP we never showed the model.

    A cheap hallucination guard on top of the Verification Agent: the LLM may
    only talk about data we actually handed it. ``extra_context`` must carry
    every other part of the prompt (notably B1's theory, which routinely names
    IPs that are not in an evidence column) -- otherwise a faithful summary
    gets thrown away as ungrounded just for repeating its own input.
    """
    allowed = " ".join(json.dumps(e) for e in evidence if e["verified"])
    allowed += " " + (extra_context or "")
    return all(ip in allowed for ip in set(IPV4_RE.findall(text)))


def _llm_explanation(incident: Dict[str, Any],
                     evidence: List[Dict[str, Any]],
                     risk_level: str,
                     risk_score: float) -> Tuple[Optional[str], str]:
    """Ask Groq for the analyst-facing explanation. Returns (text, source_tag)."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None, "template_no_api_key"
    try:
        from groq import Groq  # imported lazily so the agent runs without the SDK
    except ImportError:
        return None, "template_groq_not_installed"

    verified = [e for e in evidence if e["verified"]]
    if not verified:
        return None, "template_no_verified_evidence"

    payload = {
        "theory": incident.get("theory", ""),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "verified_evidence": verified,
        "unverified_row_ids": [e["row_id"] for e in evidence if not e["verified"]],
    }
    system = (
        "You are a SOC analyst writing an incident summary. Use ONLY the JSON "
        "given to you. Never invent an IP address, timestamp, username or row id "
        "that is not in the verified_evidence list. Write 3-5 plain-English "
        "sentences: what happened, which verified rows show it, and why it is "
        "rated at this risk level. Do not recommend an action. No markdown."
    )
    try:
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            temperature=0.2,
            max_tokens=400,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, default=str)},
            ],
        )
        text = (response.choices[0].message.content or "").strip()
    except Exception as exc:                       # network / quota / model errors
        return None, "template_llm_error:" + type(exc).__name__

    if not text:
        return None, "template_empty_response"
    if not _ground_check(text, evidence, json.dumps(payload, default=str)):
        # The model referenced data that is not in the verified evidence.
        return None, "template_llm_ungrounded"
    return text, "llm"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def investigate(incident: Dict[str, Any],
                log_index: Optional[Dict[str, Dict[str, Any]]] = None,
                log_path: Optional[Path] = None,
                use_llm: bool = True) -> Dict[str, Any]:
    """Turn one verified incident into a risk-rated, evidence-backed finding."""
    if log_index is None:
        log_index = load_log_index(log_path)

    evidence = build_evidence(incident, log_index)
    risk_score, risk_level, breakdown = score_incident(incident, evidence)

    total = len(evidence)
    verified_ratio = (sum(1 for e in evidence if e["verified"]) / total) if total else 0.0

    explanation, source = (None, "template")
    if use_llm:
        explanation, source = _llm_explanation(incident, evidence, risk_level, risk_score)
    if explanation is None:
        explanation = _template_explanation(incident, evidence, risk_level, risk_score)

    return {
        "incident_id": incident.get("incident_id", "UNKNOWN"),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "confidence": round(_clamp(_to_float(incident.get("confidence"), 0.5)), 3),
        "verified": bool(incident.get("verified", total > 0 and verified_ratio == 1.0)),
        "verified_ratio": round(verified_ratio, 3),
        "theory": incident.get("theory", ""),
        "explanation": explanation,
        "explanation_source": source,
        "recommended_action": recommend_action(evidence, risk_level, verified_ratio),
        "evidence": evidence,
        "score_breakdown": breakdown,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def investigate_all(incidents: Iterable[Dict[str, Any]],
                    log_path: Optional[Path] = None,
                    use_llm: bool = True) -> List[Dict[str, Any]]:
    """Investigate a batch of incidents, worst first (handy for the dashboard)."""
    log_index = load_log_index(log_path)
    findings = [investigate(inc, log_index=log_index, use_llm=use_llm) for inc in incidents]
    findings.sort(key=lambda f: (RISK_LEVELS.index(f["risk_level"]), f["risk_score"]),
                  reverse=True)
    return findings


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node adapter for B3's pipeline.

    Reads ``state['verified_incidents']`` (falls back to ``state['incidents']``)
    and writes ``state['findings']``.
    """
    incidents = state.get("verified_incidents") or state.get("incidents") or []
    findings = investigate_all(
        incidents,
        log_path=state.get("log_path"),
        use_llm=state.get("use_llm", True),
    )
    return {**state, "findings": findings}


# --------------------------------------------------------------------------- #
# Standalone smoke test: python agents/investigation_agent.py
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    sample_incidents = [
        {
            "incident_id": "INC-001",
            "theory": "Repeated failed logins from 10.0.0.55 followed by a success at 02:14.",
            "confidence": 0.86,
            "verified": True,
            "cited_rows": ["12", "13", "14"],
            "row_checks": [
                {"row_id": "12", "verified": True,
                 "row": {"timestamp": "2026-08-30T02:11:07", "source": "10.0.0.55",
                         "event_type": "failed_login", "severity": "medium",
                         "source_file": "demo_logs.csv"}},
                {"row_id": "13", "verified": True,
                 "row": {"timestamp": "2026-08-30T02:12:41", "source": "10.0.0.55",
                         "event_type": "brute_force", "severity": "high",
                         "source_file": "demo_logs.csv"}},
                {"row_id": "14", "verified": True,
                 "row": {"timestamp": "2026-08-30T02:14:02", "source": "10.0.0.55",
                         "event_type": "off_hours_login", "severity": "high",
                         "source_file": "demo_logs.csv"}},
            ],
        },
        {
            "incident_id": "INC-002",
            "theory": "Traffic spike from 192.168.1.9 consistent with a DDoS attempt.",
            "confidence": 0.91,
            "verified": False,
            "cited_rows": ["77", "78"],
            "row_checks": [
                {"row_id": "77", "verified": True,
                 "row": {"timestamp": "2026-08-30T09:04:00", "source": "192.168.1.9",
                         "event_type": "traffic_spike", "severity": "medium",
                         "source_file": "raw_subset.csv"}},
                # Hallucinated citation: the Log Analysis Agent cited a row that
                # does not exist in normalized_logs.csv.
                {"row_id": "78", "verified": False, "row": None},
            ],
        },
    ]

    results = investigate_all(sample_incidents, use_llm=bool(os.getenv("GROQ_API_KEY")))
    print(json.dumps(results, indent=2))
