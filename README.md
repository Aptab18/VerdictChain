# 🛡️ VerdictChain — Agentic AI Cybersecurity Assistant

> **SIH26S01** — Automated Threat Investigation and Incident Response

## Our Unique Edge

*"Every other team's AI can tell you a threat exists. Ours also proves it — every citation is checked against the raw data before it reaches the analyst."*

VerdictChain adds a **Self-Verifying Evidence Layer** between log analysis and threat investigation. Before any risk score or report is finalized, every piece of evidence is cross-checked against the raw log file. If a claim doesn't check out, its confidence is downgraded and it's flagged as **⚠ Unverified**.

## Architecture

```
Raw Logs (CSV)
      │
      ▼
[Agent 1] Log Analysis Agent     → detects anomalies, correlates events
      │
      ▼
[Agent 2] Verification Agent     → cross-checks every cited row against raw CSV
      │                            (our differentiator — no LLM, pure data lookup)
      ▼
[Agent 3] Investigation Agent    → risk scoring, explanation, recommended action
      │
      ▼
[Dashboard] Streamlit UI         → incidents, risk badges, ✓/⚠ evidence badges,
                                   downloadable reports
```

All three agents run through **LangGraph** as a linear pipeline, wrapped by a **FastAPI** backend.

## Quick Start

```bash
# 1. Install
pip install -r requirements.txt

# 2. (Optional) Set Groq API key for LLM-enhanced explanations
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# 3. Run the pipeline
python pipeline/langgraph_pipeline.py

# 4. Start the API server
uvicorn backend.main:app --reload &

# 5. Launch the dashboard
streamlit run dashboard/app.py
```

## Tech Stack

| Layer | Choice |
|---|---|
| LLM | Groq (free-tier, optional — works without it) |
| Agent Orchestration | LangGraph |
| Backend | FastAPI |
| Dashboard | Streamlit |
| Data | Pandas + CSV |
| Reports | Markdown + ReportLab PDF |

## Project Structure

```
VerdictChain/
├── agents/
│   ├── log_analysis_agent.py     # Agent 1 — anomaly detection & correlation
│   ├── verification_agent.py     # Agent 2 — evidence cross-checking
│   └── investigation_agent.py    # Agent 3 — risk scoring & recommendations
├── pipeline/
│   └── langgraph_pipeline.py     # 3-agent LangGraph pipeline
├── backend/
│   └── main.py                   # FastAPI server
├── dashboard/
│   └── app.py                    # Streamlit UI
├── data/
│   ├── normalized_logs.csv       # Combined normalized dataset
│   ├── raw_subset.csv            # CICIDS2017 subset (5,000 rows)
│   ├── anomaly_logs.csv          # Hand-crafted demo anomalies
│   └── normal_baseline.csv       # Clean baseline rows
├── reports/
│   └── report_generator.py       # Markdown + PDF report generation
└── scripts/
    └── smoke_e2e.py              # End-to-end contract test
```

## Key Design Decisions

- **Risk scoring is deterministic** — no LLM dependency, demo can never fail
- **LLM is optional** — only used for natural-language explanations, with grounding check
- **Unverified evidence caps risk at Medium** — the Verification Layer visibly affects outcomes
- **Actions are RECOMMENDED ONLY** — nothing auto-executes, per the problem statement
- **Offline mode** — dashboard works even if the API is down (reads findings.json directly)

## Team Blueprint

Team of 6 — 3 on Data, 3 on Build. Full architecture and task breakdown in `sih.md`.
