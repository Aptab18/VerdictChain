# D3 — Normalization Notes & Handoff

**SIH26S01 — Agentic AI Cybersecurity Assistant (VerdictChain)**

Owner: D3 · Script: [normalize.py](normalize.py) · Run: `python data/normalize.py`

---

## What this produces

| File | Rows | Notes |
|---|---:|---|
| `normalized_logs.csv` | 5,400 | Canonical artefact. `raw_fields` is a **JSON string** in one column. |
| `normalized_logs.jsonl` | 5,400 | Same rows, one JSON object per line, `raw_fields` a **real object**. Use this if you don't want to `json.loads` by hand. |

Inputs consumed:

| Input | Rows | Owner |
|---|---:|---|
| `anomaly_logs.csv` | 200 | D2 |
| `normal_baseline.csv` | 200 | D2 |
| `raw_subset.csv` (CICIDS2017) | 5,000 | D1 |

---

## Common schema

Eight columns, identical for every row regardless of source:

| Field | Type | Meaning |
|---|---|---|
| `row_id` | string | Globally unique, stable. `D001`–`D200`, `N001`–`N200`, `R000001`–`R005000`. |
| `timestamp` | string | ISO-8601 `YYYY-MM-DDTHH:MM:SS`. Empty string if unparseable (never `NaN`). |
| `source` | string | Source IP / actor. |
| `event_type` | string | lowercase snake_case. |
| `severity` | string | One of `info` \| `low` \| `medium` \| `high` \| `critical`. |
| `raw_fields` | JSON object | Source-specific detail. Keys exactly as agreed with D1 (below). |
| `source_file` | string | Origin file name — traceability for the Verification Agent. |
| `source_row` | int | 1-based row number in that file, header excluded. |

Example row (CICIDS):

```json
{
  "row_id": "R000001",
  "timestamp": "2017-07-04T02:44:00",
  "source": "192.168.10.16",
  "event_type": "network_flow",
  "severity": "info",
  "raw_fields": {
    "dest_ip": "195.54.48.9", "dest_port": 443, "src_port": 50998,
    "protocol": 6, "protocol_name": "TCP",
    "fwd_packets": 2, "bwd_packets": 0, "fwd_bytes": 0, "bwd_bytes": 0,
    "flow_duration": 33958, "flow_packets_per_s": 58.89628364,
    "syn_flag_count": 0, "label": "BENIGN",
    "timestamp_raw": "4/7/2017 2:44"
  },
  "source_file": "raw_subset.csv",
  "source_row": 1
}
```

---

## Mapping 1 — CICIDS2017 (`raw_subset.csv`)

Exactly the contract D1 specified.

| CICIDS column | → normalized field |
|---|---|
| `Timestamp` | `timestamp` |
| `Source IP` | `source` |
| — | `event_type` = `"network_flow"` *(fixed)* |
| — | `severity` = `"info"` *(fixed — **not** derived from Label)* |
| `Destination IP` | `raw_fields.dest_ip` |
| `Destination Port` | `raw_fields.dest_port` |
| `Source Port` | `raw_fields.src_port` |
| `Protocol` | `raw_fields.protocol` |
| `Total Fwd Packets` | `raw_fields.fwd_packets` |
| `Total Backward Packets` | `raw_fields.bwd_packets` |
| `Total Length of Fwd Packets` | `raw_fields.fwd_bytes` |
| `Total Length of Bwd Packets` | `raw_fields.bwd_bytes` |
| `Flow Duration` | `raw_fields.flow_duration` |
| `Flow Packets/s` | `raw_fields.flow_packets_per_s` |
| `SYN Flag Count` | `raw_fields.syn_flag_count` |
| `Label` | `raw_fields.label` ← **evaluation only** |

Two extra keys D3 adds (ignore them if you don't need them, they break nothing):

- `raw_fields.protocol_name` — `6 → "TCP"`, `17 → "UDP"`, `1 → "ICMP"`. Convenience only; `protocol` still holds the IANA number.
- `raw_fields.timestamp_raw` — the original untouched timestamp string, for audit.

> **`label` is never used to set `severity`.** It is carried only so we can score detection accuracy afterwards. If severity were derived from Label, the detector would be reading the answer key out of its own input.

Label distribution in the 5,000 flows: `BENIGN` 3000 · `DDoS` 1790 · `FTP-Patator` 133 · `SSH-Patator` 77.

## Mapping 2 — D2 synthetic logs (`anomaly_logs.csv`, `normal_baseline.csv`)

| D2 column | → normalized field |
|---|---|
| `row_id` | `row_id` (kept as-is — `D001`, `N001`, …) |
| `timestamp` | `timestamp` |
| `source_ip` | `source` |
| `event_type` | `event_type` (snake_cased: `NETWORK_REQUEST` → `network_request`) |
| `severity` | `severity` (lowercased onto the five-level scale) |
| `destination_ip` | `raw_fields.dest_ip` |
| `username` | `raw_fields.username` |
| `protocol` | `raw_fields.protocol` (string here — `HTTPS`/`TCP`, not a number) |
| `bytes` | `raw_fields.bytes` |
| `status` | `raw_fields.status` |
| `device` | `raw_fields.device` |
| `message` | `raw_fields.message` |
| — | `raw_fields.timestamp_raw` |

---

## The three gotchas D1 flagged — how each is handled

**1. Leading spaces in CICIDS headers.**
`df.columns = df.columns.str.strip()` runs inside `read_csv()`, the first thing that happens to any dataframe in the module. Every lookup afterwards uses the clean name.

**2. Day-first timestamps, sometimes without seconds.**
`parse_timestamps()` tries ten explicit formats in order (`%d/%m/%Y %H:%M:%S`, `%d/%m/%Y %H:%M`, `%m/%d/%Y %H:%M:%S`, ISO variants, …). Each format only sees the cells the previous ones failed on, so a single column may legitimately mix layouts. Anything still unparsed falls back to `pd.to_datetime(..., dayfirst=True, format="mixed")`.

*Day-first verified:* every parsed CICIDS date lands on **4, 5 or 7 July 2017** — the real CICIDS2017 capture week. Under a month-first read, `4/7/2017` would become 7 April and the dates would scatter across April/May/July. 0 rows failed to parse.

**3. `Infinity` / `NaN` in `Flow Packets/s`.**
`_number()` returns `None` for `inf`, `-inf`, `NaN`, empty and junk cells, and `_put()` then **omits the key entirely** rather than writing a poison value. So `flow_packets_per_s` is simply absent on those rows — `row["raw_fields"].get("flow_packets_per_s")` gives `None`, `json.dumps` never emits bare `Infinity`, and nothing downstream crashes. `df.replace([np.inf, -np.inf], np.nan)` also runs in `read_csv()` as a second layer.

Affected rows in this subset: **2** (`R002672`, `R002976`). Everything else has a real value.

---

## Notes for B1 / B2 / B3

**Reading the file.** `raw_fields` is a JSON string in the CSV:

```python
import csv, json
with open("data/normalized_logs.csv", newline="", encoding="utf-8") as fh:
    rows = [{**r, "raw_fields": json.loads(r["raw_fields"])} for r in csv.DictReader(fh)]
```

Or skip the parse entirely and read `normalized_logs.jsonl`:

```python
rows = [json.loads(line) for line in open("data/normalized_logs.jsonl", encoding="utf-8")]
```

**Missing keys are normal.** `raw_fields` only carries keys that had a real value. Always use `.get()`, never `[...]`, on `raw_fields`.

**Cite `row_id` in incidents.** `cited_rows` should hold `row_id` values (`"D051"`, `"R000123"`). `investigation_agent.load_log_index()` indexes on it and round-trips correctly — verified end-to-end, including the "cited row does not exist" path, which correctly comes back `verified: false`.

**⚠️ B1, read this one.** D2's brute-force pattern (D051–D100) arrives from the source CSV as `event_type = "login"` with `raw_fields.status = "FAILED"` — the source has no `failed_login` event type, and D3 deliberately does not invent one (same reasoning as `label`: classification is B1's job, not the normalizer's). But `investigation_agent.EVENT_RISK` weights `login` at 0.20, so a genuine brute-force incident currently scores **Low**.

The 50 failed-login rows are cleanly identifiable:

```python
r["event_type"] == "login" and r["raw_fields"].get("status") == "FAILED"
```

B1 should classify those into `failed_login` / `brute_force` when building the incident candidate, or B2/B3 should read `status` when scoring. Data is all there; it just needs the detection step.

**D2 event/status breakdown (400 rows):**

| source_file | event_type | status | count |
|---|---|---|---:|
| anomaly_logs.csv | login | SUCCESS | 75 |
| anomaly_logs.csv | login | FAILED | 50 |
| anomaly_logs.csv | network_request | SUCCESS | 50 |
| anomaly_logs.csv | file_access | SUCCESS | 25 |
| normal_baseline.csv | login | SUCCESS | 67 |
| normal_baseline.csv | network_request | SUCCESS | 67 |
| normal_baseline.csv | file_access | SUCCESS | 66 |

**File naming.** The blueprint calls D2's anomaly file `demo_logs.csv`; D2 shipped `anomaly_logs.csv`. The script accepts either (plus the `*_200_rows.csv` names), so nobody has to rename anything.

---

## Run output

```
normalized 5400 rows

by source_file:
  anomaly_logs.csv         200
  normal_baseline.csv      200
  raw_subset.csv           5000

by event_type:
  network_flow             5000
  login                    192
  network_request          117
  file_access               91

by severity:
  info                     5200
  high                      185
  critical                   15

raw_fields.label (evaluation only, not used for severity):
  BENIGN                   3000
  DDoS                     1790
  FTP-Patator               133
  SSH-Patator                77

flow_packets_per_s dropped (Infinity/NaN): 2

validation: OK
```

`--strict` makes the script exit non-zero on any validation warning — use it in CI.

---

## Validation performed

`validate()` runs on every execution and checks:

- [x] `row_id` globally unique across all three files — no collisions
- [x] `row_id`, `event_type`, `severity`, `source_file` non-blank on every row
- [x] `severity` only ever within `info/low/medium/high/critical`
- [x] `timestamp` parsed on all 5,400 rows — 0 failures
- [x] `source` non-empty on all 5,400 rows
- [x] `raw_fields` serializes with `allow_nan=False` — no `Infinity`/`NaN` can reach the JSON

Additionally verified by hand:

- [x] Day-first parsing correct (dates fall in the real CICIDS2017 capture week)
- [x] `severity` is `info` on 100% of CICIDS rows, independent of `label`
- [x] Round-trip through `investigation_agent.load_log_index()` + `investigate()`
- [x] Hallucinated-citation path returns `verified: false`, not a crash

## D3 checklist

- [x] All three source files normalized into one schema
- [x] Exact `raw_fields` key names per the D1 contract
- [x] `event_type` / `severity` fixed for CICIDS; `label` isolated to evaluation
- [x] Header stripping, day-first timestamps, Infinity/NaN handled
- [x] Traceability preserved (`row_id`, `source_file`, `source_row`, `timestamp_raw`)
- [x] CSV + JSONL outputs
- [x] Self-validating script with `--strict` mode
- [x] Handoff notes for B1/B2/B3
