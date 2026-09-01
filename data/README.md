# data/

Expected files (owners in blueprint section 5):

- `raw_subset.csv` — D1, real dataset subset (2,000–3,000 rows, CICIDS2017 or UNSW-NB15)
- `raw_subset_README.md` — D1, notes on source dataset/attack types/row count
- `anomaly_logs.csv` — D2, hand-crafted anomaly rows for the live demo (blueprint name: `demo_logs.csv`)
- `normal_baseline.csv` — D2, hand-crafted clean rows for the live demo
- `normalized_logs.csv` — D3, combined output in the common schema (output of `normalize.py`)
- `normalized_logs.jsonl` — D3, same rows with `raw_fields` as a real JSON object
- `D3_notes.md` — D3, schema contract, field mapping and handoff notes for B1/B2/B3

Regenerate the normalized output with:

```bash
python data/normalize.py          # add --strict to fail on any validation warning
```
