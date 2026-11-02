# Lab 6 — Splunk SSH Brute-Force Detection

| Field | Detail |
|---|---|
| **Project** | Hunt a brute-force attack in Splunk and build a detection alert |
| **Platform** | Splunk Enterprise / Free (local install, Windows) |
| **Data** | 216 SSH authentication events (simulated), ingested via file upload |
| **Attacker** | `193.27.14.88` — 64 failed logins, then a successful compromise |
| **Status** | Complete |

---

## 1. Objective

Take a day of noisy authentication logs, ingest them into Splunk, and use SPL to find a brute-force attack hidden among normal activity — then confirm the compromise, visualise it, and convert the hunt into an automated detection. This moves from manual command-line analysis (earlier labs) to a real enterprise SIEM.

## 2. Setup

- Installed Splunk Enterprise locally on Windows (runs at `http://localhost:8000`), used in free mode.
- Ingested `splunk_auth_sample.log` via **Add Data → Upload**, sourcetype `auth_log`, index `main`.
- Confirmed 216 events parsed with correct timestamps.

## 3. The dataset

A realistic mix designed to require real analysis, not a single grep:
- Normal logins from legitimate users on internal IPs, plus two remote workers.
- Occasional single password failures (human typos).
- A benign scanner probing invalid usernames a handful of times.
- **The attack:** a concentrated brute force against user `swapnil` from `193.27.14.88`, ending in a successful login.

## 4. Investigation (SPL)

**Step 1 — Filter to failures.**
```spl
sourcetype="auth_log" "Failed password"
```
86 failed-login events.

**Step 2 — Extract the source IP and rank by count.**
```spl
sourcetype="auth_log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip
| sort -count
```
The IP was not auto-parsed for the custom sourcetype, so `rex` with a named capture group extracted it into `src_ip`. Result: `193.27.14.88` at **64 failures**, with all legitimate sources at 3–4. The gap identifies the attacker.

**Step 3 — Confirm the compromise.**
```spl
sourcetype="auth_log" "193.27.14.88" ("Failed password" OR "Accepted password")
| sort _time
```
Chronological view: a wall of failures followed by a single `Accepted password for swapnil from 193.27.14.88` — the brute force succeeded.

**Step 4 — Visualise the attack.**
```spl
sourcetype="auth_log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| timechart span=5m count by src_ip
```
A flat baseline across the day with a sharp spike at ~14:22 where `193.27.14.88` dominates — the attack made visible.

## 5. Detection engineering (the alert)

Converted the hunt into an automated rule:
```spl
sourcetype="auth_log" "Failed password"
| rex "from (?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| stats count by src_ip
| where count > 20
```
Saved as a scheduled alert, **`SSH Brute Force - Excessive Failed Logins`**, Medium severity, triggering when any source IP exceeds 20 failures (a threshold normal users never reach). In production the alert action would be an email or ticket to the analyst queue.

**Note on validation:** scheduled alerts evaluate a live time window, so on static historical data the detection is validated by running the search directly rather than waiting for a scheduled trigger.

## 6. Findings summary

| Finding | Detail |
|---|---|
| Attacker IP | `193.27.14.88` (64 failed logins) |
| Targeted account | `swapnil` |
| Compromise | Successful login from the attacker IP after the brute force |
| Benign noise correctly excluded | Scanner `45.9.120.3`, internal typos (3–4 failures each) |

## 7. MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |

## 8. What I learned

- `stats count by` is the workhorse of SPL — it turns thousands of raw events into a ranked finding in one line.
- `rex` lets you extract and name fields that aren't auto-parsed — essential when a sourcetype isn't recognised.
- A SIEM's value is correlation and automation: the same logic that took several grep commands becomes one SPL query, and then a scheduled alert that runs on its own.
- Detection thresholds separate signal from noise — 64 failures is an attack; 3 is a typo.

---

*Prepared as a hands-on SOC analyst lab exercise (Lab 6 — Splunk Detection Lab).*
