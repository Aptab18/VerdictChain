"""Detection metrics against the CICIDS2017 ground-truth labels.

The D1 subset carries a `label` field per flow (BENIGN / DDoS / FTP-Patator /
SSH-Patator), so detection quality is measurable rather than asserted. This
script scores the pipeline's cited evidence against those labels and writes
`data/metrics.json` for the dashboard.

    python scripts/compute_metrics.py                 # uses data/findings.json
    python scripts/compute_metrics.py --rerun         # re-run the pipeline first

Scope and honesty
-----------------
  * Only rows from `raw_subset.csv` are scored. The synthetic demo rows have no
    ground truth, so including them would inflate the numbers.
  * A row counts as DETECTED if any finding cites it as evidence.
  * Metrics are row-level, not incident-level: the question answered is
    "of the attack traffic in this log, how much did we surface to the analyst,
    and how much of what we surfaced was actually attack traffic".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

LOG_PATH = PROJECT_ROOT / "data" / "normalized_logs.csv"
FINDINGS_PATH = PROJECT_ROOT / "data" / "findings.json"
METRICS_PATH = PROJECT_ROOT / "data" / "metrics.json"
LABELLED_SOURCE = "raw_subset.csv"
BENIGN_LABEL = "BENIGN"


def compute(log_path: Path = LOG_PATH,
            findings_path: Path = FINDINGS_PATH) -> Dict[str, Any]:
    df = pd.read_csv(log_path, dtype=str)
    findings: List[Dict[str, Any]] = json.loads(
        findings_path.read_text(encoding="utf-8"))

    cited = {e["row_id"] for f in findings for e in f.get("evidence", [])}

    labelled = df[df["source_file"] == LABELLED_SOURCE].copy()
    if labelled.empty:
        raise SystemExit(f"No rows from {LABELLED_SOURCE} in {log_path}")

    labelled["label"] = labelled["raw_fields"].apply(
        lambda s: json.loads(s).get("label"))
    labelled = labelled.dropna(subset=["label"])
    labelled["detected"] = labelled["row_id"].isin(cited)
    labelled["is_attack"] = labelled["label"] != BENIGN_LABEL

    tp = int((labelled.detected & labelled.is_attack).sum())
    fp = int((labelled.detected & ~labelled.is_attack).sum())
    fn = int((~labelled.detected & labelled.is_attack).sum())
    tn = int((~labelled.detected & ~labelled.is_attack).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    per_class = []
    for label in sorted(labelled["label"].unique()):
        rows = labelled[labelled["label"] == label]
        per_class.append({
            "label": label,
            "rows": int(len(rows)),
            "detected": int(rows.detected.sum()),
            "rate": round(float(rows.detected.mean()), 4),
            "is_attack": label != BENIGN_LABEL,
        })

    # Alert-consolidation ratio: the analyst reads incidents, not rows.
    total_rows = int(len(df))
    metrics = {
        "dataset": LABELLED_SOURCE,
        "labelled_rows": int(len(labelled)),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(labelled), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "per_class": per_class,
        "consolidation": {
            "log_rows_examined": total_rows,
            "evidence_rows_cited": len(cited),
            "incidents_raised": len(findings),
        },
    }
    return metrics


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rerun", action="store_true",
                        help="run the pipeline before scoring")
    parser.add_argument("--out", default=str(METRICS_PATH))
    args = parser.parse_args(argv)

    if args.rerun:
        from pipeline.langgraph_pipeline import run_pipeline
        state = run_pipeline(str(LOG_PATH), use_llm=False)
        FINDINGS_PATH.write_text(
            json.dumps(state.get("findings", []), indent=2, default=str),
            encoding="utf-8")

    metrics = compute()
    Path(args.out).write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    c = metrics["confusion"]
    print(f"Scored {metrics['labelled_rows']} labelled rows from {metrics['dataset']}")
    print(f"  TP={c['tp']}  FP={c['fp']}  FN={c['fn']}  TN={c['tn']}")
    print(f"  precision {metrics['precision']:.1%}   recall {metrics['recall']:.1%}   "
          f"F1 {metrics['f1']:.1%}")
    print(f"  false-positive rate on benign traffic: {metrics['false_positive_rate']:.1%}")
    print("\nper class:")
    for row in metrics["per_class"]:
        kind = "attack" if row["is_attack"] else "benign"
        print(f"  {row['label']:14s} ({kind:6s})  {row['detected']:5d}/{row['rows']:5d}"
              f"  = {row['rate']:6.1%}")
    con = metrics["consolidation"]
    print(f"\n{con['log_rows_examined']:,} log rows -> {con['evidence_rows_cited']:,} "
          f"cited rows -> {con['incidents_raised']} incidents for the analyst")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
