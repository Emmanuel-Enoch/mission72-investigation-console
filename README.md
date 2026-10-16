# Mission 72 — Suspicious Login and Activity Detector
## Mission 02: Context-Aware Alert Detection & False-Positive Reduction

An offline cybersecurity authentication log analysis and incident triage platform. It profiles user behavior strictly from training-period history, validates ingestion quality, evaluates contextual organizational policies (IT maintenance windows, account roles, and recognized corporate VPNs), detects threats across all six required categories, correlates events into security incidents, computes explainable 0–100 risk scores, and generates offline CSV and interactive HTML investigation reports.

---

## Current Status: Mission 02 Context-Aware Implementation Complete

The project is fully implemented, strictly deterministic, air-gapped capable, and validated with **62 passing automated tests** across all 13 challenge scenarios:

1. **Context Policy Engine (`src/mission72/context.py` & `config/context_config.json`):**
   - **Declared IT Maintenance Windows:** Supports start/end timestamps (strict UTC ISO-8601 normalization), exact boundary matching (`start <= ts <= end`), scoped target host globbing (`srv-patch-*`), permitted activity types (`AUTHENTICATION`, `ADMIN_LOGON`), and authorized account/role permissions. Inverted or zero-duration windows are rejected at configuration time.
   - **Account Roles & Scoped Authorizations:** Distinct roles (`helpdesk`, `sysadmin`, `standard_user`) with granular allowed target footprints and activity validity windows. Helpdesk roles do not receive blanket access to unapproved targets.
   - **Recognized Corporate VPN Registry:** CIDR subnet and discrete IP matching (`198.51.100.0/24`), geolocation tagging, and explicit trust flags (`is_trusted=True` vs untrusted proxies/anonymizers). Provides evidence-based location risk mitigation without blind trust.

2. **Context-Aware Threat Detections (`src/mission72/detections.py`):**
   - `RULE-01-REPEATED-FAILURES`: Repeated authentication failures against a single user within sliding window.
   - `RULE-02-BURST-THEN-SUCCESS`: Failure burst followed by a successful login within minutes (credential compromise indicator).
   - `RULE-03-PASSWORD-SPRAY`: Distributed authentication failures targeting multiple distinct user accounts from a single source IP.
   - `RULE-04-UNUSUAL-TIME`: Login attempts at anomalous hours relative to the user's established baseline (*strictly evaluated only for users with established normal history*).
   - `RULE-05-UNFAMILIAR-IP`: Context-aware source IP evaluation. Connections from verified corporate VPNs have severity reduced to `LOW` with explicit mitigating explanation; connections from untrusted proxies are escalated to `HIGH`; unknown IPs retain standard `MEDIUM` severity.
   - `RULE-06-UNFAMILIAR-HOSTS`: Context-aware lateral movement evaluation. Access by authorized helpdesk staff to approved hosts during active maintenance is classified with severity `LOW` and flagged as `(Approved IT Maintenance Window)`. Access outside windows or to unapproved hosts retains full severity and logs explicit mismatch audits.

3. **Incident Grouping & Explainable 0–100 Risk Scoring (`src/mission72/incidents.py`):**
   - Correlates discrete alerts by account or source IP within temporal clustering windows.
   - Preserves complete evidence provenance: original source filename, row numbers, timestamps, and contextual match/mismatch reasons.
   - Computes deterministic, bounded [0, 100] risk scores with a transparent mathematical explanation:
     $$\text{Score} = \max\Big(0, \min\big(100, \text{Base}(\text{MaxSeverity}) + \text{MultiCategoryBonus} + \text{EvidenceVolumeBonus} + \text{SensitiveTargetBonus} - \text{ContextMitigationDiscount}\big)\Big)$$
   - Mitigations:
     - Approved IT Maintenance Window: $-35$ points (full approval on all activity).
     - Verified Corporate VPN Gateway: $-15$ points (mitigates unfamiliar location risk).
     - Scope Violations / Mismatches: $0$ points discount (preserves full suspicious indicators).

4. **Investigator Interface & Reporting (`src/mission72/reporting.py`, `src/mission72/server.py`):**
   - **Interactive Local & Cloud Dashboard:** Clean dark-mode UI with summary metrics, dynamic filtering, contextual policy status badges (`APPROVED_MAINTENANCE`, `VERIFIED_VPN`, `APPROVAL_MISMATCH`), expandable score breakdowns, and raw evidence tables.
   - **CSV Exports:** Exports `incidents.csv`, `evidence.csv`, and `user_risk_profiles.csv` via in-memory streaming with zero temporary disk writes.
   - **HTML Report:** Self-contained, printable single-file HTML report with contextual badges and evidence audits.
   - **Dual Cloud Ready:** Native support for persistent hosts (Render / Railway via `render.yaml` & `Procfile`) and serverless functions (Vercel via `vercel.json` & `api/index.py`).

---

## Scenario Verification Matrix (Section 4 Requirements)

All 13 required scenarios are covered by deterministic tests in `tests/test_mission02_context.py`:

| # | Scenario | Expected Outcome | Implemented Behaviour & Status | Test Method |
|---|---|---|---|---|
| 1 | Authorized helpdesk on approved hosts during active maintenance | Appropriate contextual risk reduction with explicit explanation; evidence preserved | Rule 6 severity reduced to `LOW`; $-35$ pts maintenance discount applied; evidence preserved (`context_status = APPROVED_MAINTENANCE`) | `test_scenario_01_authorized_helpdesk_approved_hosts_during_maintenance` |
| 2 | Helpdesk accessing hosts outside approved window | No maintenance-based exemption; suspicious evidence remains | Out-of-window timestamp flagged; no discount granted; full risk score maintained ($\ge 35$) | `test_scenario_02_helpdesk_accessing_hosts_outside_maintenance_window` |
| 3 | Helpdesk accessing unapproved host during maintenance | Approval mismatch remains visible; affects risk appropriately | Target host mismatch recorded (`APPROVAL_MISMATCH`); $0$ maintenance discount granted; risk preserved | `test_scenario_03_helpdesk_accessing_unapproved_host_during_maintenance` |
| 4 | Travelling employee using recognized company VPN | VPN context influences score without blindly declaring event safe | Alert severity reduced to `LOW`; $-15$ pts discount applied (`VERIFIED_VPN`); subsequent attacks remain alertable | `test_scenario_04_travelling_employee_using_company_vpn` |
| 5 | New-location login without VPN evidence | Standard location anomaly remains detectable | Alert triggered at `MEDIUM` severity; no VPN discount; full risk score applied (35 pts) | `test_scenario_05_new_location_without_vpn_evidence` |
| 6 | Unknown or untrusted VPN endpoint | Treated as unverified/rogue; flagged for review; no automatic discount | Flagged as `Untrusted VPN / Proxy`; escalated to `HIGH` severity; $0$ discount; risk score 55 | `test_scenario_06_login_from_untrusted_vpn_endpoint` |
| 7 | Regular user accessing many unfamiliar hosts during maintenance | Suspicious-access detection remains effective; non-IT user not exempt | Role authorization checked; regular user rejected for maintenance exemption; alert remains active | `test_scenario_07_regular_user_accessing_many_unfamiliar_hosts` |
| 8 | Maintenance window with invalid/inverted timestamps | Configuration rejected or clearly reported; normal alerting proceeds safely | Inverted window (`start >= end`) raises `ValueError` and is rejected with warning; registry operates safely | `test_scenario_08_maintenance_window_with_invalid_timestamps_rejected` |
| 9 | Event at exact maintenance-window boundary | Deterministic, documented boundary behavior applied consistently | Inclusive boundary policy (`start <= ts <= end`): events exactly at `start` and `end` match; outside by $1$s fails | `test_scenario_09_exact_maintenance_window_boundary_behavior` |
| 10 | Missing account, host, timestamp, or VPN fields | Safe, deterministic handling with visible uncertainty | Missing/empty fields evaluate without crashing; fall back to unmitigated alerting | `test_scenario_10_missing_fields_safe_handling` |
| 11 | Conflicting context signals | Balanced scoring reflecting mitigating and aggravating factors | Incident captures both Rule 5 (unfamiliar IP) and Rule 6 (mitigated hosts); math breakdown explains net score | `test_scenario_11_conflicting_context_signals` |
| 12 | Duplicate event ingested | Documented, deterministic duplicate behavior without unintended score inflation | Flagged in `DataQualityReport.duplicate_candidate_count`; raw evidence preserved with exact line numbers | `test_scenario_12_duplicate_event_ingestion_behavior` |
| 13 | Unrelated events with similar attributes during maintenance | Correctly attributed to separate incidents; no incorrect merge | Clustered by distinct entity (`frank.helpdesk` vs `alice.smith`), yielding two separate incidents | `test_scenario_13_unrelated_events_not_incorrectly_merged` |

---

## Project Structure

```text
Missionathon/
├── main.py                                  # Root execution entrypoint
├── README.md                                # Project documentation & scenario matrix
├── vercel.json                              # Vercel serverless routing configuration
├── render.yaml                              # Render Web Service blueprint
├── Procfile                                 # Process file for cloud container deployment
├── api/
│   └── index.py                             # Vercel serverless function entrypoint (handler)
├── config/
│   ├── default_rules.yaml                   # Rule parameters and detection thresholds
│   └── context_config.json                  # Maintenance windows, account roles, and VPN endpoints
├── data/
│   └── synthetic/                           # Clearly labelled synthetic benchmark data
│       ├── README.md                        # Synthetic dataset notice & manifest
│       ├── synthetic_training_auth.csv      # Baseline training dataset (Oct 1 - Oct 10)
│       └── synthetic_evaluation_auth.csv    # Chronologically sorted evaluation dataset
├── reports/                                 # Generated audit reports (HTML, CSV)
│   ├── investigation_report.html
│   ├── incidents.csv
│   ├── evidence.csv
│   └── user_risk_profiles.csv
├── src/
│   └── mission72/
│       ├── __init__.py
│       ├── models.py                        # Canonical AuthEvent, UserBaseline, DataQualityReport
│       ├── context.py                       # MaintenanceWindow, AccountAuthorization, VpnEndpoint, ContextRegistry
│       ├── ingestion.py                     # CSV parser, timestamp normalizer, quality validator (utf-8-sig)
│       ├── baseline.py                      # Leak-free training baseline profiler & coverage engine
│       ├── detections.py                    # All six detection rules with context awareness
│       ├── incidents.py                     # Incident clustering & explainable [0, 100] risk scoring
│       ├── reporting.py                     # Standalone HTML dashboard and in-memory CSV exporters
│       ├── server.py                        # Python 3.13-compatible local & cloud web dashboard
│       ├── cli.py                           # CLI entrypoint for analysis and server commands
│       └── synthetic.py                     # Deterministic synthetic data generator with active seed
└── tests/
    ├── __init__.py
    ├── test_stage1.py                       # 16 ingestion, baseline & quality regression tests
    ├── test_mvp.py                          # 20 rule, scoring, grouping, and end-to-end tests
    ├── test_server.py                       # 13 server HTTP, multipart & cloud/serverless tests
    └── test_mission02_context.py            # 13 deterministic tests covering Mission 02 scenarios
```

---

## Configuration Examples

### Maintenance Windows (`config/context_config.json`)

```json
{
  "maintenance_windows": [
    {
      "window_id": "MW-2026-10-PATCH",
      "start_time_utc": "2026-10-15T02:00:00Z",
      "end_time_utc": "2026-10-15T06:00:00Z",
      "approved_hosts": ["srv-patch-*", "srv-db-01", "srv-app-01"],
      "permitted_activities": ["AUTHENTICATION", "ADMIN_LOGON", "LOGON", "NETWORK"],
      "authorized_accounts": ["frank.helpdesk", "sarah.admin"],
      "authorized_roles": ["helpdesk", "sysadmin"],
      "description": "Quarterly OS security patching and database indexing",
      "change_reference": "CHG-98421"
    }
  ]
}
```

### Account Roles & Authorizations

```json
{
  "account_authorizations": [
    {
      "username": "frank.helpdesk",
      "role": "helpdesk",
      "permitted_targets": ["srv-patch-*", "srv-db-01", "srv-app-01", "ws-hd-01"],
      "approved_activities": ["AUTHENTICATION", "LOGON", "NETWORK"],
      "is_active": true
    },
    {
      "username": "alice.smith",
      "role": "standard_user",
      "permitted_targets": ["corp-workstation-01"],
      "approved_activities": ["AUTHENTICATION", "LOGON", "NETWORK"],
      "is_active": true
    }
  ]
}
```

### Recognized Corporate VPN Gateways

```json
{
  "vpn_endpoints": [
    {
      "endpoint_id": "VPN-LON-01",
      "cidr_or_ip": "198.51.100.0/24",
      "name": "London Corporate VPN Gateway",
      "location": "London, UK",
      "is_trusted": true
    },
    {
      "endpoint_id": "VPN-ROGUE-01",
      "cidr_or_ip": "203.0.113.200/32",
      "name": "Untrusted Public Anonymizer",
      "location": "Untrusted Public Anonymizer",
      "is_trusted": false
    }
  ]
}
```

---

## Explainable Risk Scoring Formula

Incident risk scores ($0 \le \text{Score} \le 100$) are calculated deterministically:

1. **Base Score by Maximum Alert Severity:**
   - `CRITICAL`: 75 points
   - `HIGH`: 55 points
   - `MEDIUM`: 35 points
   - `LOW`: 15 points
2. **Multi-Category Correlation Bonus:**
   - 2 distinct categories: $+10$ points
   - 3 or more distinct categories: $+20$ points
3. **Evidence Volume Bonus:**
   - $\ge 5$ correlated events: $+5$ points
   - $\ge 10$ correlated events: $+10$ points
4. **Sensitive Asset Targeting Bonus:**
   - Targeting assets matching sensitive identifiers (`domain-controller`, `dc`, `admin`, `sec-ops`, `vault`): $+10$ points
5. **Contextual Mitigation Discount:**
   - Approved IT Maintenance: $-35$ points (when all events match authorized window, hosts, and role).
   - Verified Corporate VPN Gateway: $-15$ points (mitigates unfamiliar location risk).
   - Mismatches or scope violations: $0$ points discount.
6. **Clamping:** Score is strictly bounded between $0$ and $100$.

---

## Execution Instructions

### 1. Run Complete Automated Test Suite (62 Tests)

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -p "test_*.py" -v
```

### 2. Run Context-Aware Offline Analysis (CLI)

```powershell
$env:PYTHONPATH = "src"
python main.py analyze `
  --train data/synthetic/synthetic_training_auth.csv `
  --eval data/synthetic/synthetic_evaluation_auth.csv `
  --context-config config/context_config.json `
  --html-out reports/investigation_report.html `
  --csv-out reports/incidents.csv `
  --evidence-csv-out reports/evidence.csv `
  --user-csv-out reports/users.csv
```

### 3. Launch Local Investigator Web Console

```powershell
$env:PYTHONPATH = "src"
python main.py serve --host 127.0.0.1 --port 8072
```

Navigate to `http://127.0.0.1:8072` in any browser:
- Upload any evaluation CSV (with optional training CSV).
- Click **"Load Synthetic Benchmark"** to test immediately.
- Inspect contextual badges (`APPROVED_MAINTENANCE`, `VERIFIED_VPN`, `APPROVAL_MISMATCH`) in the incident detail panel.
- Export correlated incident, evidence, user profile CSVs, or standalone HTML reports.

---

## Cloud Deployment (Vercel & Render)

The project includes dual native deployment support for both serverless and persistent cloud container hosting:

### Option A: Vercel Serverless Function Deployment
- **Files:** `vercel.json` (URL routing rewrite to `/api/index`), `api/index.py` (Vercel Python runtime entrypoint).
- **Auto-Preload:** Automatically detects the `VERCEL` environment variable and auto-populates synthetic benchmark data so judges and visitors immediately see the full interactive investigation dashboard.
- **Vercel Deployment Protection (Crucial):** If Vercel displays a login/SSO redirect screen, disable Deployment Protection for public judge access:
  1. Open the project on [Vercel Dashboard](https://vercel.com).
  2. Navigate to **Settings** $\to$ **Deployment Protection**.
  3. Under **Vercel Authentication**, toggle it to **Disabled**.

### Option B: Render / Persistent Container Deployment (Recommended for Full Session State)
- **Files:** `render.yaml` (Render Infrastructure-as-Code Blueprint), `Procfile` (`web: python main.py serve --host 0.0.0.0`).
- **Persistent State:** Long-running `ThreadingHTTPServer` preserves `GLOBAL_STATE` in memory across page refreshes and uploads with zero cold starts and no authentication walls.
- **Port Binding:** Automatically binds to `$PORT` passed by Render, Heroku, or Railway.

---

## Limitations & Assumptions

1. **No External Network Connectivity:** The system is air-gapped; geolocation and VPN lookups are performed solely against local configuration data without external WHOIS or IP-lookup calls.
2. **Context as Evidence, Not Proof:** A connection from a company VPN verifies network egress through corporate infrastructure; it does not prove the session is benign if credential-stuffing or password-spraying signatures are present.
3. **Inclusive Boundary Policy:** Window checks evaluate `start <= timestamp <= end`. Events occurring precisely on the start or end timestamp are treated as within the window.
4. **Non-destructive Ingestion:** Invalid or malformed rows are segregated into `DataQualityReport.malformed_records` and preserved without halting analysis.
