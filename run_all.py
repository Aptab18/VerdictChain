"""One-command launcher: pipeline -> API -> dashboard.

    python run_all.py           # run pipeline, start API + dashboard
    python run_all.py --llm     # same, with Groq explanations
"""
import subprocess, sys, time, json
from pathlib import Path

ROOT = Path(__file__).parent
FINDINGS = ROOT / "data" / "findings.json"


def main():
    use_llm = "--llm" in sys.argv

    # 1. Run pipeline
    print("=" * 60)
    print("Step 1: Running 3-agent pipeline...")
    print("=" * 60)
    cmd = [sys.executable, "pipeline/langgraph_pipeline.py"]
    if use_llm:
        cmd.append("--llm")
    rc = subprocess.call(cmd, cwd=str(ROOT))
    if rc != 0:
        print("Pipeline failed!")
        return 1

    findings = json.loads(FINDINGS.read_text())
    print(f"\n✅ {len(findings)} incidents ready.\n")

    # 2. Start FastAPI
    print("=" * 60)
    print("Step 2: Starting FastAPI on http://127.0.0.1:8000 ...")
    print("=" * 60)
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(ROOT)
    )
    time.sleep(2)

    # 3. Start Streamlit
    print("=" * 60)
    print("Step 3: Starting Streamlit on http://localhost:8501 ...")
    print("=" * 60)
    dash = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "dashboard/app.py",
         "--server.port", "8501", "--server.headless", "true"],
        cwd=str(ROOT)
    )

    print("\n" + "=" * 60)
    print("🛡️  VerdictChain is running!")
    print("   Dashboard: http://localhost:8501")
    print("   API:       http://127.0.0.1:8000/docs")
    print("   Press Ctrl+C to stop.")
    print("=" * 60)

    try:
        api.wait()
    except KeyboardInterrupt:
        print("\nShutting down...")
        api.terminate()
        dash.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
