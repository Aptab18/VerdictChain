# D2 — Synthetic Demo Dataset Notes

## Project

**SIH26S01 — Agentic AI Cybersecurity Assistant**

## Purpose

This dataset is the controlled synthetic dataset prepared for the D2 (Synthetic Demo-Log Builder) task.

It contains:

- 200 intentionally suspicious/anomalous rows in `demo_logs_200_rows.csv`
- 200 normal baseline rows in `normal_baseline_200_rows.csv`
- Four clearly explainable anomaly patterns
- Related rows that can be correlated into incident candidates

The purpose is to provide deterministic and explainable results during the live demonstration.

---

## Dataset Files

| File | Rows | Purpose |
|---|---:|---|
| `demo_logs_200_rows.csv` | 200 | Suspicious/anomalous events |
| `normal_baseline_200_rows.csv` | 200 | Normal/clean baseline events |

---

# Anomaly Patterns

## 1. Off-Hours Admin Login

**Rows:** D001–D050

**Source IP:** `185.72.44.19`

**Username:** `admin`

**Device:** `Unknown-Laptop`

### Reason

The admin account is accessed during unusual hours, mainly between approximately 02:00 AM and 03:00 AM.

### Expected Detection

- Off-hours login
- Suspicious administrative access

### Expected Risk

**High**

### Expected Incident

These related events should ideally be correlated into one incident rather than being reported as 50 independent incidents.

---

## 2. Repeated Failed Login Attempts

**Rows:** D051–D100

**Source IP:** `91.203.44.17`

**Username:** `admin`

**Device:** `Unknown-Device`

### Reason

Multiple failed login attempts originate from the same source IP within a short period.

### Expected Detection

- Repeated authentication failures
- Possible brute-force activity

### Expected Risk

**High to Critical**

### Expected Incident

D051–D100 represent a repeated-login pattern and should ideally be correlated into a single incident candidate.

---

## 3. Traffic Spike

**Rows:** D101–D150

**Source IP:** `45.77.21.90`

**Destination:** `10.0.0.20`

**Event Type:** `NETWORK_REQUEST`

### Reason

The same source generates unusually large network requests, with traffic volumes far above the normal baseline.

### Expected Detection

- Traffic spike
- Possible flooding / DDoS-like behavior

### Expected Risk

**High**

### Expected Incident

D101–D150 should ideally be correlated into one traffic-related incident.

---

## 4. Unrecognized Device

**Rows:** D151–D200

**Source IP:** `103.44.82.11`

**Username:** `employee01`

**Device:** `Unknown-Android`

### Reason

The employee account performs login and file-access activity from an unrecognized device.

### Expected Detection

- Unrecognized device
- Potentially compromised credentials

### Expected Risk

**High**

### Expected Incident

D151–D200 should ideally be treated as related events from the same source/user/device pattern.

---

# Normal Baseline

**Rows:** N001–N200

The normal baseline represents ordinary activity during normal working hours.

### Characteristics

- Normal working-hour activity
- Known office laptops
- Successful authentication
- Moderate network traffic
- Normal file access
- No repeated authentication failures
- No unusual devices

### Purpose

These rows are included to ensure that the system does not flag every event as suspicious.

The Log Analysis Agent should be able to distinguish the anomalous patterns from normal activity.

---

# Common CSV Schema

Both D2 CSV files use the same structure:

| Column | Description |
|---|---|
| `row_id` | Unique row identifier |
| `timestamp` | Event timestamp |
| `source_ip` | Source IP address |
| `destination_ip` | Destination IP address |
| `event_type` | Type of event |
| `username` | User involved |
| `protocol` | Network protocol |
| `bytes` | Traffic/data size |
| `status` | Event status |
| `device` | Device involved |
| `severity` | Event severity |
| `message` | Human-readable event description |

---

# Expected Incident Groups

1. **Incident 001 — Off-Hours Administrative Access**
   - D001–D050
   - Off-hours admin login

2. **Incident 002 — Repeated Authentication Failures**
   - D051–D100
   - Possible brute-force activity

3. **Incident 003 — Network Traffic Spike**
   - D101–D150
   - Possible flooding / DDoS-like behavior

4. **Incident 004 — Unrecognized Device Access**
   - D151–D200
   - Potentially compromised credentials

The exact number of final incidents may depend on the correlation logic implemented by the Log Analysis Agent.

---

# D2 → D3 Handoff

D2 provides:

```text
demo_logs_200_rows.csv
normal_baseline_200_rows.csv
D2_notes.md
```

D3 is responsible for converting these datasets into the project's common normalized schema and producing:

```text
normalized_logs.csv
```

The normalized data should retain traceability to the original source file and row.

---

# Verification Support

Every anomaly has a unique `row_id`.

This allows the Verification Agent to directly check whether cited evidence actually exists in the underlying data.

Example:

```text
Agent cites: D075

Verification:
- Row exists: YES
- Timestamp matches: YES
- Source IP matches: YES
- Event type matches: YES

Result: VERIFIED
```

This supports the project's Self-Verifying Evidence Layer.

---

# D2 Checklist

- [x] 200 anomaly rows created
- [x] 200 normal baseline rows created
- [x] Off-hours login pattern
- [x] Repeated failed-login pattern
- [x] Traffic-spike pattern
- [x] Unrecognized-device pattern
- [x] Unique row IDs
- [x] Consistent CSV schema
- [x] Related rows for incident correlation
- [x] Explainable anomaly reasons
- [x] Normal baseline for comparison
- [x] Notes prepared for testing and Q&A
