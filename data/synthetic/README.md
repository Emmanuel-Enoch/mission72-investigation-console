# Synthetic Test Datasets for Mission 72

> [!IMPORTANT]
> **NOT OFFICIAL DATA**: The files in this directory are purely synthetic test fixtures
> generated deterministically (fixed seed) for local testing and pipeline validation.

## Files
- `synthetic_training_auth.csv`: 57 normal baseline events (Oct 1 - Oct 10, 2026).
- `synthetic_evaluation_auth.csv`: 37 evaluation events (Oct 11 - Oct 15, 2026), strictly chronologically sorted:
  - Normal continued activity for established users
  - Repeated login failures (brute force pattern)
  - Failure burst followed by success
  - Multi-account password spraying from a single source IP
  - Unusual login hours (off-hours relative to baseline)
  - Unfamiliar source IPs
  - Sudden access to unfamiliar destination hosts
  - Ingestion anomalies (missing field, malformed timestamp, duplicate candidate rows)
