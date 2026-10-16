# Mission 72 — Suspicious Login and Activity Detector

An offline cybersecurity authentication log analysis and incident triage platform. It profiles user behavior strictly from training-period history, validates ingestion quality, detects threats across all six required categories, correlates events into security incidents, computes explainable 0–100 risk scores, and generates offline CSV and interactive HTML investigation reports.

---

## Current Status: Working End-to-End MVP

The project has reached a fully functional, testable local MVP with zero external dependencies:

1. **Six Implemented Detection Categories (`src/mission72/detections.py`):**
   - `RULE-01-REPEATED-FAILURES`: Repeated authentication failures against a single user within a sliding window.
   - `RULE-02-BURST-THEN-SUCCESS`: Failure burst followed by a successful login within minutes (credential compromise indicator).
   - `RULE-03-PASSWORD-SPRAY`: Distributed authentication failures targeting multiple distinct user accounts from a single source IP.
   - `RULE-04-UNUSUAL-TIME`: Login attempts at anomalous hours relative to the user's established baseline (*strictly evaluated only for users with established normal history*).
   - `RULE-05-UNFAMILIAR-IP`: Access originating from source IPs never observed during training, enriched with geo-location metadata when lookup tables are supplied.
   - `RULE-06-UNFAMILIAR-HOSTS`: Sudden access targeting destination hosts outside the user's established normal footprint, with elevated severity for critical assets (e.g. domain controllers).

2. **Incident Grouping & Explainable 0–100 Risk Scoring (`src/mission72/incidents.py`):**
   - Correlates discrete alerts by account or source IP within temporal clustering windows.
   - Preserves complete evidence provenance: original source filename, row numbers, and raw timestamps.
   - Computes deterministic, bounded (0–100) risk scores with a transparent mathematical explanation:
     $$\text{Score} = \min\Big(100, \text{Base}(\text{MaxSeverity}) + \text{MultiCategoryBonus} + \text{EvidenceVolumeBonus} + \text{SensitiveTargetBonus}\Big)$$
   - Supplies concrete, actionable triage recommendations for each incident.

3. **Local Investigator Interface & Exporters (`src/mission72/reporting.py`, `src/mission72/server.py`):**
   - **Offline HTML Dashboard:** Fully self-contained single-page report with responsive layout, metric cards, incident filter controls, per-user risk breakdown, and collapsible evidence tables. Zero external CDN/font/script dependencies.
   - **CSV Exports:** Exports `incidents.csv`, `evidence.csv`, and `user_risk_profiles.csv`.
   - **Local Web Console:** Python built-in `http.server` running locally at `http://127.0.0.1:8072` supporting interactive log uploads, synthetic benchmark analysis, and live downloads.

4. **Preserved Stage 1 Guarantees:**
   - Training-only baselining with strict cutoff enforcement (zero data leakage from evaluation records).
   - Baseline safety: only successful authentications establish normal behavior; failed attempts are not learned.
   - Ambiguous timestamp detection (slash dates where day and month $\le 12$ are flagged rather than guessed).
   - Schema validation distinguishes missing columns from missing cell values.
   - Duplicate candidate fingerprinting preserves raw evidence without claiming physical identity.

---

## Project Structure

```text
Missionathon/
├── main.py                                  # Root execution script
├── README.md                                # Setup, usage, and submission guide
├── config/
│   └── default_rules.yaml                   # Rule parameters and thresholds
├── data/
│   └── synthetic/                           # Clearly labelled synthetic benchmark data
│       ├── README.md                        # Synthetic dataset notice & manifest
│       ├── synthetic_training_auth.csv      # Baseline training dataset (Oct 1 - Oct 10)
│       └── synthetic_evaluation_auth.csv    # Chronologically sorted evaluation dataset
├── reports/                                 # Generated reports (HTML, CSV)
│   ├── investigation_report.html
│   ├── incidents.csv
│   ├── evidence.csv
│   └── user_risk_profiles.csv
├── src/
│   └── mission72/
│       ├── __init__.py
│       ├── models.py                        # Canonical AuthEvent, UserBaseline, DataQualityReport
│       ├── ingestion.py                     # CSV parser, timestamp normalizer, quality validator (utf-8-sig)
│       ├── baseline.py                      # Safe training baseline profiler & coverage engine
│       ├── detections.py                    # All six mandatory detection rules
│       ├── incidents.py                     # Incident grouping & explainable 0-100 risk scoring
│       ├── reporting.py                     # Standalone HTML dashboard and CSV exporters
│       ├── server.py                        # Zero-dependency local web dashboard (http.server)
│       ├── cli.py                           # CLI entrypoint for analysis and server commands
│       └── synthetic.py                     # Deterministic synthetic data generator with active seed
└── tests/
    ├── __init__.py
    ├── test_stage1.py                       # 17 ingestion, baseline & quality regression tests
    ├── test_mvp.py                          # 11 rule, scoring, grouping, and end-to-end tests
    └── test_server.py                       # 11 server HTTP, Python 3.13 multipart & regression tests
```

---

## Prerequisites & Setup

- **Python:** Python 3.10+ (tested on Python 3.13.15).
- **Dependencies:** Standard library only (`csv`, `datetime`, `dataclasses`, `email`, `http.server`, `hashlib`, `unittest`, `pathlib`, `typing`, `random`).
- **Network Access:** None. Fully offline and air-gapped capable.

---

## Usage Instructions

### 1. Run Offline End-to-End Analysis (CLI)

Run full analysis on training and evaluation CSVs and generate HTML and CSV reports:

```powershell
python main.py analyze `
  --train data/synthetic/synthetic_training_auth.csv `
  --eval data/synthetic/synthetic_evaluation_auth.csv `
  --html-out reports/investigation_report.html `
  --csv-out reports/incidents.csv `
  --evidence-csv-out reports/evidence.csv `
  --user-csv-out reports/user_risk_profiles.csv
```

### 2. Launch Local Web Investigator Console

Start the built-in offline server and open in any browser:

```powershell
python main.py serve --port 8072
```

Navigate to `http://127.0.0.1:8072` in your browser. From the interface you can:
- Upload any training and evaluation CSVs.
- Click **"Load Synthetic Benchmark"** to test pre-packaged scenarios.
- Filter incidents dynamically by username, severity, and minimum risk score.
- Expand correlated evidence rows with exact line provenance.
- Download `incidents.csv`, `evidence.csv`, `user_risk_profiles.csv`, or the standalone `report.html`.

### 3. Run the Automated Test Suite

Run all 39 automated unit, regression, server, and end-to-end integration tests:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 4. Regenerate Synthetic Test Datasets

Regenerate the deterministic benchmark datasets:

```powershell
python main.py synthetic --output-dir data/synthetic --seed 42
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
   - Targeting assets matching sensitive identifiers (`domain-controller`, `dc`, `admin`, `sec-ops`, `mail-gateway`, `vault`): $+10$ points
5. **Clamping:** Score is strictly bounded between $0$ and $100$.

---

## Shortest Route to Submission Deliverables

Once official competition dataset files and submission portal stages are published:
1. **Schema Alignment:** Compare the official CSV column headers to the canonical aliases in `FIELD_ALIASES` in [`src/mission72/ingestion.py`](file:///C:/Users/Emmy/Desktop/Missionathon/src/mission72/ingestion.py) and add any unique headers if necessary.
2. **Geo-Location Data:** If official evaluation includes an IP-to-country lookup CSV, pass it into `DetectionEngine(ip_location_map=...)`.
3. **Execute Official Run:** Run `python main.py analyze --train <official_train.csv> --eval <official_eval.csv> --html-out submission_report.html --csv-out submission_incidents.csv`.
4. **Package Deliverables:** Submit the generated HTML report, CSV incident table, and clean repository code.
