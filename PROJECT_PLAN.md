# VerdictChain — Build Plan (SIH26S01)

Agentic AI Cybersecurity Assistant for Automated Threat Investigation and Incident Response.
Working plan and task tracker. Tick boxes as phases land.

---

## Current state (audited 2026-09-01)

### Done

| Component | File | Status |
|---|---|---|
| D1 real dataset | `data/raw_subset.csv` | 5,000 CICIDS2017 flow rows |
| D2 synthetic demo | `data/anomaly_logs.csv` (200), `data/normal_baseline.csv` (200) | 4 explainable anomaly patterns, notes in `D2_notes.md` |
| D3 normalizer | `data/normalize.py` | CICIDS + demo -> common schema, validation, CSV + JSONL out |
| Agent 1 — Log Analysis | `agents/log_analysis_agent.py` | ~20 rule detectors, correlation, optional Groq theory |
| Agent 2 — Verification | `agents/verification_agent.py` | Row existence + field-claim check, confidence adjustment |
| Agent 3 — Investigation | `agents/investigation_agent.py` | Risk scoring, grounded explanation, recommended action |
| Report generator | `reports/report_generator.py` | Markdown + PDF, verification badges |

### Not started

| Component | File | Status |
|---|---|---|
| LangGraph pipeline | `pipeline/langgraph_pipeline.py` | stub comment only |
| FastAPI backend | `backend/main.py` | stub comment only |
| Streamlit dashboard | `dashboard/app.py` | stub comment only |
| Project README | `README.md` | empty |

### Blocker

- `data/normalized_logs.csv` contains **unresolved git merge conflict markers**
  (`<<<<<<< HEAD` line 1, `=======` line 5403, `>>>>>>>` line 5476).
  Every agent reads this file, so nothing downstream can run until it is fixed.

**Bottom line:** the three agents and the data layer are built. What is missing is
the wiring (pipeline -> API -> UI) and the demo surface — which is exactly what
gets judged on stage.

---

## Phase 0 — Repair the foundation  ✅ DONE

Goal: every existing piece provably runs on real data before new code is written.

- [ ] **0.1** Fix `normalized_logs.csv` by re-running `python data/normalize.py`
      (deterministic regeneration — resolves the conflict at the source instead
      of hand-editing 5,476 lines). Verify: no conflict markers, expected row
      count, `row_id` unique.
- [ ] **0.2** Update `requirements.txt` — add `fastapi`, `uvicorn[standard]`,
      `streamlit`, `langgraph`, `requests`. Pin nothing yet; pin before the demo.
- [ ] **0.3** Run each agent standalone on the real normalized data and record
      what comes out: how many incidents, which rule types fire, how many are
      verified. Tune thresholds if the count is unusable (200 incidents is as
      bad a demo as 0).
- [ ] **0.4** Write `scripts/smoke_e2e.py` — chains the three agents by hand and
      asserts the contracts actually line up (B1 keys -> B2 keys -> B3 keys).
      This is the safety net for every later refactor.

**Exit criteria:** one command produces a list of risk-rated findings from the
real CSV, with no manual steps.

---

## Phase 1 — LangGraph pipeline

Goal: the three agents become one declared graph, which is the "agentic" claim
the problem statement is judged on.

- [ ] **1.1** Define the shared `PipelineState` (log path, incidents, verified
      incidents, findings, run metadata, errors).
- [ ] **1.2** Wrap each agent as a graph node — `analyze -> verify -> investigate`.
      Load the normalized log once per run and pass it through state; do not
      re-read the CSV three times.
- [ ] **1.3** Per-node error capture: a failing node degrades the run and records
      the error instead of killing the process. Demo must never show a traceback.
- [ ] **1.4** Graceful fallback: if `langgraph` is not installed or fails to
      import, run the same three functions as a plain chain. Identical output.
- [ ] **1.5** CLI: `python pipeline/langgraph_pipeline.py --logs <csv> --out
      data/findings.json [--no-llm] [--demo]`.

**Exit criteria:** `python pipeline/langgraph_pipeline.py` writes
`data/findings.json` with correct, verified findings.

---

## Phase 2 — FastAPI backend

Goal: a clean HTTP surface so the dashboard holds no business logic.

- [ ] **2.1** `POST /run-investigation` — runs the pipeline (accepts a dataset
      choice: `demo` / `real` / `all`, and an LLM on/off flag), returns a summary.
- [ ] **2.2** `GET /incidents` — all findings, sorted worst-first; filterable by
      `risk_level` and `verified`.
- [ ] **2.3** `GET /incidents/{id}` — one finding with full evidence and
      `score_breakdown`.
- [ ] **2.4** `GET /incidents/{id}/report?format=markdown|pdf` — streams the file
      from `report_generator.py` with correct download headers.
- [ ] **2.5** `GET /stats` — totals, risk-level counts, verified vs unverified
      counts. Feeds the dashboard summary tiles in one call.
- [ ] **2.6** `GET /health` + startup load of `data/findings.json` so the API
      answers instantly after a restart without a re-run.
- [ ] **2.7** CORS enabled for the Streamlit origin.

**Exit criteria:** every endpoint verified with real requests, not just imports.

---

## Phase 3 — Streamlit dashboard

Goal: the demo surface. This is what the judges actually look at.

- [ ] **3.1** Summary view — total incidents, risk-level breakdown, and a
      **Verified vs Unverified evidence** counter (the differentiator, stated in
      numbers on the first screen).
- [ ] **3.2** Incident list — colour-coded risk badges (red / amber / green),
      sortable, filterable, showing verification status per incident.
- [ ] **3.3** Detail view — theory, plain-English explanation, and each evidence
      row with a large **✓ Verified / ⚠ Unverified** badge. Show the
      `score_breakdown` so the risk number is explainable, not magic.
- [ ] **3.4** Hallucination callout — where a cited row failed verification, show
      plainly what the agent claimed and what the log actually said. This is the
      single most convincing screen in the demo.
- [ ] **3.5** Download Report button per incident (Markdown + PDF).
- [ ] **3.6** "Run investigation" control with a dataset switch (demo dataset for
      the guaranteed live run, real dataset for credibility).
- [ ] **3.7** Offline mode — if the API is unreachable, read `data/findings.json`
      directly so the UI still demos. No dead screen on stage.

**Exit criteria:** full click-through works with the backend running, and again
with the backend deliberately killed.

---

## Phase 4 — Demo hardening and documentation

- [ ] **4.1** `README.md` — problem, architecture diagram, the Verification Layer
      differentiator, setup, run commands, screenshots.
- [ ] **4.2** `run_all` script (single command: pipeline -> API -> dashboard).
- [ ] **4.3** Full rehearsal on the demo dataset **and** the real dataset;
      record the timings. Fix anything slower than ~10s on the demo path.
- [ ] **4.4** Failure drills — no API key, no network, Groq rate-limited,
      `langgraph` missing, backend down. Each must degrade visibly but keep working.
- [ ] **4.5** Freeze a known-good `data/findings.json` as the emergency fallback,
      and pin `requirements.txt` versions.
- [ ] **4.6** Rehearse the pitch line:
      *"Every other team's AI can tell you a threat exists. Ours also proves it —
      every citation is checked against the raw data before it reaches the analyst."*

---

## Phase 6 — 9.7 upgrade (audit response)  ✅ DONE

Built in response to the senior-SOC-engineer audit. Every number below was
measured, not estimated.

- [x] **6.1 Red-team drill** — `agents/redteam_drill.py`, a `drill` node in the
      pipeline, `?drill=true` on the API, a sidebar toggle. Injects a ghost row
      **and** a false claim about a real row, so the Verification Layer can be
      seen catching both failure modes. Covered by smoke test stage 5.
- [x] **6.2 Detection metrics** — `scripts/compute_metrics.py` + `/metrics` +
      dashboard panel. Measured: **precision 89.5%, recall 47.3%, FP rate 3.7%**
      on 5,000 labelled CICIDS rows.
- [x] **6.3 Credential-attack detector** — `detect_auth_service_flood`, with its
      own 30-minute window because Patator campaigns pace themselves under the
      5-minute burst window. FTP-Patator 0% → 56.4%, SSH-Patator 0% → 55.8%,
      with no increase in false positives.
- [x] **6.4 MITRE ATT&CK mapping** — `MITRE_MAP` covering all 22 rules; tactic
      and technique carried through to the finding and shown as badges.
- [x] **6.5 Dashboard rebuild** — dark theme via `.streamlit/config.toml` (not
      CSS overrides), risk donut, verification donut, incident timeline,
      per-class detection bars, colour-coded evidence table, and the
      claimed-vs-actual hallucination panel.
- [x] **6.6 Live Investigation page** — `dashboard/pages/1_Live_Investigation.py`
      streams `data/demo_feed.csv` (41 curated rows) and shows the three agents
      handing off in real time. Runs fully in-process: no HTTP, no Groq.
- [x] **6.7 Exact-name rule risk table** — `RULE_RISK` in the Investigation
      Agent replaces substring matching; unmapped rules are surfaced rather than
      silently mis-scored.

### Bugs found and fixed while building this phase

| Bug | Impact if shipped |
|---|---|
| `high_packet_rate` fired on 3-packet flows | 719 incidents, 90% of that rule's hits were BENIGN; the demo anomalies ranked 717–719 |
| Investigation Agent scored on `event_type` only | A 41-port scan and the CICIDS DDoS source both rated **Low** |
| `build_evidence` mishandled rich (dict) citations | False claims about real rows were invisible — the differentiator silently failed |
| Backend cached findings forever | Running the pipeline from the CLI left the dashboard showing the previous run |
| Live sim de-duplicated on `incident_id` | Incident ids are positional and reshuffle each run, so incidents were dropped or duplicated |
| `pd.Timedelta` passed to plotly | Timeline chart crashed the whole dashboard page |

---

## Phase 5 — Optional polish (only if Phases 0–4 are green)

- [ ] **5.1** `log_streamer.py` — replay rows on a delay to simulate a live feed.
- [ ] **5.2** Timeline visual of an incident's correlated rows.
- [ ] **5.3** Metrics slide: detection counts on the labelled CICIDS subset
      (we have ground-truth `Label`, so real precision/recall numbers are possible
      — a strong, checkable claim).

---

## Order of execution

Strictly sequential: 0 -> 1 -> 2 -> 3 -> 4. Each phase's exit criteria must pass
before the next begins. Phase 5 only if there is time left over.
