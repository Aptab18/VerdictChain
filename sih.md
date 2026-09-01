# SIH26S01 — Agentic AI Cybersecurity Assistant
## Team Blueprint — Architecture, Data Plan, Tech Stack & Task Assignment

**Problem Statement:** SIH26S01 — Agentic AI Cybersecurity Assistant for Automated Threat Investigation and Incident Response
**Team split:** 6 people — 3 on Data, 3 on Build
**Prototype scope:** minimum 2 collaborating AI agents (we are building 3 — see "Our Unique Edge" below), which is explicitly allowed since the PS says "at least two"

---

## 1. Our Unique Edge — how we stand out among 40 teams

Every other team will build the literal PS requirement: a **Log Analysis Agent** that detects anomalies, and a **Threat Investigation Agent** that explains and recommends. That is the baseline everyone will submit.

Our differentiator: **a Self-Verifying Evidence Layer.**

LLM-based agents can hallucinate — they can cite a log row, a user, or a value that doesn't actually exist in the data, and a judge has no easy way to know that happened. Our system adds a lightweight **Verification Agent** (a mini version of a Watchdog) that sits between the two required agents. Before any risk score or report is finalized, every piece of evidence the Log Analysis Agent cited is **cross-checked against the raw log file** — did that row actually exist, does the timestamp match, does the value match. If a claim doesn't check out, its confidence is downgraded and it's flagged before it ever reaches the report.

**Why this wins on stage:**
- It directly addresses a real, well-known LLM weakness (hallucination) that judges will immediately understand and respect
- It's cheap to build (a simple lookup/match function, not a new ML model) — high impact, low implementation cost
- It shows up visually on the dashboard as a "✓ Verified" / "⚠ Unverified" badge next to every piece of evidence — instantly demoable, no explanation needed
- It turns "we detect threats" into "we detect threats and we don't lie about our evidence" — a genuinely different pitch from the other 39 teams

Keep this line ready for the pitch: *"Every other team's AI can tell you a threat exists. Ours also proves it — every citation is checked against the raw data before it reaches the analyst."*

---

## 2. Full System Architecture

```
Raw Logs (CSV)
      │
      ▼
[STEP 1] Log Ingestion & Normalization
      │  → converts all logs into one common schema
      ▼
[STEP 2] Log Analysis Agent  (Agent 1)
      │  → detects anomalies, correlates related events
      │  → outputs: incident candidate + cited evidence rows
      ▼
[STEP 3] Verification Layer  (Agent 2 — our unique edge)
      │  → cross-checks every cited row against the raw CSV
      │  → attaches a verified/unverified tag + confidence adjustment
      ▼
[STEP 4] Threat Investigation Agent  (Agent 3)
      │  → assigns risk level (Low/Medium/High/Critical)
      │  → writes an evidence-backed explanation
      │  → recommends a response action
      │  → generates a downloadable incident report
      ▼
[STEP 5] Dashboard (Streamlit)
      → shows incidents, risk badges, evidence with verification status,
        recommended actions, and a "Download Report" button
```

All three agent steps run through **LangGraph** as a linear pipeline, wrapped by a **FastAPI** backend. The dashboard calls the FastAPI endpoints.

---

## 3. Tech Stack (fast to build, still genuinely modern — not a "toy" stack)

| Layer | Choice | Why |
|---|---|---|
| LLM backend | **Groq (free-tier API)** | Extremely fast inference, free, zero local setup time |
| Agent orchestration | **LangGraph** | Industry-standard, simple linear pipeline for this scope |
| Backend API | **FastAPI** | Fast to build, clean endpoints for the dashboard to call |
| Data handling | **Pandas + CSV** | No database setup needed for a prototype — keeps build time low |
| Dashboard | **Streamlit** | Fastest way to get a working, demo-ready UI |
| Report generation | **ReportLab or Markdown→PDF** | Produces the downloadable incident report |
| Version control | **GitHub** | Team coordination, one repo, clear folder structure (see below) |

No database server, no message queue, no Docker required for this prototype — that infrastructure is for the major project, not this hackathon scope. Keep it lean.

---

## 4. Suggested Repo Structure

```
sih26s01-cyber-assistant/
├── data/
│   ├── raw_subset.csv          ← D1
│   ├── demo_logs.csv           ← D2
│   ├── normal_baseline.csv     ← D2
│   └── normalized_logs.csv     ← D3 (output)
├── agents/
│   ├── log_analysis_agent.py   ← B1
│   ├── verification_agent.py   ← B2
│   └── investigation_agent.py  ← B2
├── pipeline/
│   └── langgraph_pipeline.py   ← B3
├── backend/
│   └── main.py (FastAPI)       ← B3
├── dashboard/
│   └── app.py (Streamlit)      ← B3
├── reports/
│   └── report_generator.py     ← B2
└── README.md
```

---

## 5. Data Team — Detailed Tasks (3 people)

### D1 — Real Dataset Curator
**Goal:** produce a small, clean, credible subset of a real intrusion dataset.

1. Download CICIDS2017 or UNSW-NB15 (pick one, don't mix formats)
2. In Pandas, filter down to **2,000–3,000 rows only** — do not use the full dataset, it will slow everything down for no benefit at prototype scale
3. Keep only 2–3 clearly labeled attack types (e.g. DDoS, port-scan) plus a chunk of normal traffic — roughly 60% normal, 40% attack rows, so the agents have to actually distinguish, not just flag everything
4. Keep only the columns that matter: timestamp, source IP, destination IP, protocol, packet/byte count, label
5. Export as `data/raw_subset.csv`
6. Write a short `data/raw_subset_README.md` noting which dataset, which attack types, and row count — B1 will need this to know what to expect

### D2 — Synthetic Demo-Log Builder (critical for a reliable live demo)
**Goal:** hand-craft a small, guaranteed-to-work demo file so the live presentation never depends on random real-dataset behavior.

1. Manually write **10–15 log rows** with obvious, clean anomalies — e.g. one row showing a login at an unusual hour, a few rows showing a traffic spike from one IP, one row showing an unrecognized device
2. Make sure every anomalous row has a clear, explainable reason a human could point to — this is what your agents will "discover" live on stage
3. Also write **10–15 normal rows** that look similar in structure but have nothing suspicious — this proves the system isn't just flagging everything
4. Save as `data/demo_logs.csv` (anomalies) and `data/normal_baseline.csv` (clean rows)
5. Keep a private notes file for your own team listing exactly which row is which anomaly and why — you'll want this during Q&A

### D3 — Normalization & Schema Builder
**Goal:** make sure both real-subset and synthetic data speak the same "language" before they reach the agents.

1. Define one common schema, e.g.: `timestamp, source, event_type, severity, raw_fields (JSON)`
2. Write a Python script that reads `raw_subset.csv`, `demo_logs.csv`, and `normal_baseline.csv`, and converts each into that common schema
3. Output a single combined file: `data/normalized_logs.csv`
4. Add a `source_file` column so it's always traceable which row came from which original file — useful for debugging and for the Verification Agent later
5. (If time allows) build a small `log_streamer.py` that replays rows from `normalized_logs.csv` one at a time with a short delay, to simulate a "live feed" for the demo — this is optional polish, not required for the core PS

---

## 6. Build Team — Detailed Tasks (3 people)

### B1 — Log Analysis Agent
**Goal:** detect anomalies and correlate related events into incidents.

1. Load `normalized_logs.csv`
2. Build a simple rule-based first pass (e.g. request-rate thresholds, off-hours logins, repeated failed attempts) — this gives you a fast, explainable baseline that always works even if the LLM call fails
3. Pass flagged rows + surrounding context to Groq (via LangGraph node) to get a natural-language anomaly theory and a confidence score
4. **Correlation step:** group multiple related flagged rows (same source/user within a time window) into a single "incident candidate" instead of reporting every row separately
5. Output format (JSON), per incident:
   ```json
   {
     "incident_id": "...",
     "theory": "...",
     "confidence": 0.0,
     "cited_rows": ["row_id_1", "row_id_2"]
   }
   ```
6. Hand this JSON to the Verification Agent (B2) — do not let it go straight to the report

### B2 — Verification Agent + Threat Investigation Agent + Report Generator
**Goal:** this is where our unique edge lives — build it carefully, it's your strongest talking point.

**Part A — Verification Agent**
1. For every `cited_rows` entry from B1's output, look up that row directly in `normalized_logs.csv`
2. Check that the row exists and that the specific values the agent's theory referenced (timestamp, IP, event type) actually match
3. Tag each incident: `"verified": true/false`, and if any cited row fails the check, reduce the confidence score accordingly
4. This should be a simple, fast function — no LLM call needed here, it's a direct data lookup, which also makes it fast and demo-safe

**Part B — Threat Investigation Agent**
1. Take only verified (or confidence-adjusted) incidents
2. Assign a risk level: Low / Medium / High / Critical, based on confidence + severity of the event type
3. Generate an evidence-backed explanation in plain English, citing the exact verified rows
4. Recommend a response action (e.g. "block source IP," "flag account for review," "verify identity") — **recommend only, do not auto-execute**, per the PS wording

**Part C — Report Generator**
1. Build a function that takes a finalized incident and generates a clean, downloadable report (PDF or well-formatted Markdown)
2. Report must include: incident summary, risk level, evidence (with verification status), recommended action, timestamp
3. Wire a "Download Report" trigger the dashboard can call

### B3 — Orchestration, Backend & Dashboard
**Goal:** wire everything together and make it look sharp for the demo.

1. Build the LangGraph pipeline: Log Analysis Agent → Verification Agent → Threat Investigation Agent, as a linear graph
2. Wrap the pipeline in FastAPI with clean endpoints, e.g.:
   - `POST /run-investigation` — runs the full pipeline on the log file
   - `GET /incidents` — returns all processed incidents
   - `GET /incidents/{id}/report` — returns the downloadable report
3. Build the Streamlit dashboard with:
   - A summary view: total incidents, risk-level breakdown
   - An incidents list with color-coded risk badges (red/amber/green)
   - A detail view per incident: theory, evidence rows **with a clear "✓ Verified" / "⚠ Unverified" badge next to each one** — this is the differentiator, make it visually obvious
   - A "Download Report" button per incident
4. Test the full flow end-to-end with both `demo_logs.csv` (for guaranteed live-demo results) and `raw_subset.csv` (for credibility/breadth) before the final run-through

---

## 7. Build Order (do it in this sequence, not in parallel chaos)

1. **D1, D2, D3 work in parallel from day one** — they don't block each other, and B1 cannot start meaningfully without at least a first draft of `normalized_logs.csv`
2. **B3 starts the LangGraph + FastAPI skeleton immediately**, using dummy/fake data — don't wait for real data to start wiring the pipeline shape
3. **B1 starts as soon as D3's first normalized file is ready** (even a small draft is enough to start)
4. **B2 starts as soon as B1 produces its first real output JSON** — the Verification Agent's logic can be tested even before B1 is fully polished
5. **B3 integrates B1 + B2 into the pipeline**, then connects it to the dashboard
6. **Final pass, all 6 together:** run the full pipeline on both the synthetic demo file and the real-data subset, fix anything broken, rehearse the pitch line from Section 1

---

## 8. Final Deliverables Checklist

- [ ] Working dashboard (Streamlit)
- [ ] Sample-log pipeline (ingest → normalize → detect → correlate → verify → investigate)
- [ ] Threat classification with risk score
- [ ] Evidence-backed explanation, with verification status shown
- [ ] Recommended response action (not auto-executed)
- [ ] Downloadable incident report
- [ ] Rehearsed pitch line on the Verification Layer as the unique differentiator