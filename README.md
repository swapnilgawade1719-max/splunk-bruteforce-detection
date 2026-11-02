# Splunk SSH Brute-Force Detection Lab

A self-directed SOC analyst project: ingesting authentication logs into **Splunk**, using **SPL** (Splunk's search language) to hunt a brute-force attack hidden in realistic noise, visualising the attack over time, and building a scheduled **detection alert**.

> **Note:** This is a hands-on home lab built on a simulated log dataset — not a production environment.

---

## Scenario

A day of SSH authentication logs (216 events) from a gateway host, containing normal user activity, a benign scanner, occasional password typos — and, buried in the noise, a concentrated brute-force attack that succeeds. The goal: find the attacker, confirm the compromise, and turn the hunt into an automated detection.

## Skills & tools demonstrated

- **Splunk** — data ingestion, Search & Reporting, alerts (local Splunk Enterprise / Free)
- **SPL (Search Processing Language)** — filtering, field extraction, aggregation, time-series
- **`rex`** — regex field extraction with a named capture group (`src_ip`)
- **`stats count by`** — aggregation to rank sources by failure count
- **`timechart`** — time-series visualisation of the attack spike
- **Detection engineering** — a threshold-based scheduled alert
- **MITRE ATT&CK** — T1110 Brute Force

## Key SPL used

**Rank source IPs by failed-login count (find the attacker):**
```spl
sourcetype="auth_log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip
| sort -count
```

**Confirm the compromise (failures → success from the same IP):**
```spl
sourcetype="auth_log" "193.27.14.88" ("Failed password" OR "Accepted password")
| sort _time
```

**Visualise the attack over time:**
```spl
sourcetype="auth_log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| timechart span=5m count by src_ip
```

**Detection logic (threshold) — saved as a scheduled alert:**
```spl
sourcetype="auth_log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip
| where count > 20
```

## Findings

- **Attacker identified:** `193.27.14.88` with **64 failed logins** — far above the 3–4 seen from legitimate users (typos) and a benign scanner. The gap is the detection.
- **Compromise confirmed:** after 64 failures, a single `Accepted password for swapnil from 193.27.14.88` — the brute force succeeded.
- **Visualised:** a flat baseline all day, then a sharp spike at ~14:22 where the attacker IP dominates.
- **Automated:** a scheduled alert (`SSH Brute Force - Excessive Failed Logins`) fires when any source IP exceeds 20 failures.

## MITRE ATT&CK

`T1110` — Brute Force

---

## Repository contents

| File | Description |
|------|-------------|
| [`LAB6_REPORT.md`](LAB6_REPORT.md) | Full write-up — ingestion, SPL, detection, alert, lessons |
| `splunk_auth_sample.log` | The sample dataset analysed |
| `images/` | Screenshots: ranked IPs, compromise, timechart spike, saved alert |

**➡️ Read the full investigation in [LAB6_REPORT.md](LAB6_REPORT.md).**
