"""
Command-line interface for Mission 72 Suspicious Login and Activity Detector.
Supports offline log analysis, CSV/HTML report generation, synthetic benchmarking,
and launching the local investigator dashboard.
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from mission72.baseline import build_user_baselines
from mission72.context import ContextRegistry, create_default_context_registry
from mission72.detections import DetectionEngine, RuleConfig
from mission72.incidents import (
    compute_user_risk_profiles,
    group_alerts_into_incidents,
)
from mission72.ingestion import parse_csv_file
from mission72.reporting import (
    export_evidence_to_csv,
    export_incidents_to_csv,
    export_report_to_html,
    export_user_risk_to_csv,
)
from mission72.synthetic import generate_synthetic_datasets


def run_analysis(
    train_file: str,
    eval_file: str,
    html_out: Optional[str] = None,
    csv_out: Optional[str] = None,
    evidence_csv_out: Optional[str] = None,
    user_csv_out: Optional[str] = None,
    date_format: Optional[str] = None,
    context_config: Optional[str] = None,
) -> int:
    """Runs complete offline pipeline: Ingestion -> Baseline -> Context -> 6 Rules -> Incidents -> Reports."""
    context_reg = None
    if context_config:
        context_reg = ContextRegistry.from_file(context_config)
        print(f"[*] Loaded contextual policy from {context_config} ({len(context_reg.maintenance_windows)} windows, {len(context_reg.accounts)} accounts, {len(context_reg.vpn_endpoints)} VPNs)")
    elif Path("config/context_config.json").exists():
        context_reg = ContextRegistry.from_file("config/context_config.json")
        print(f"[*] Loaded default contextual policy from config/context_config.json ({len(context_reg.maintenance_windows)} windows, {len(context_reg.accounts)} accounts, {len(context_reg.vpn_endpoints)} VPNs)")

    print(f"[*] Ingesting training baseline: {train_file}")
    train_events, train_quality = parse_csv_file(train_file, configured_date_format=date_format)
    print(f"    Loaded {train_quality.valid_records} valid baseline records ({train_quality.malformed_records} malformed)")

    print(f"[*] Building leak-free user behavioral baselines...")
    baseline_repo = build_user_baselines(train_events, min_training_events=5)
    cov = baseline_repo.coverage_summary()
    print(f"    Profiled {cov['total_users_profiled']} users ({cov['established_baselines']} established, {cov['coverage_percentage']}% coverage)")

    print(f"[*] Ingesting evaluation logs: {eval_file}")
    eval_events, eval_quality = parse_csv_file(eval_file, configured_date_format=date_format)
    print(f"    Loaded {eval_quality.valid_records} valid records ({eval_quality.malformed_records} malformed, {eval_quality.duplicate_candidate_count} duplicate candidates)")

    print(f"[*] Executing 6 detection rules (context-aware)...")
    engine = DetectionEngine(baseline_repo=baseline_repo, context_registry=context_reg)
    alerts = engine.run_all(eval_events)
    print(f"    Triggered {len(alerts)} alerts across categories.")

    print(f"[*] Correlating alerts and computing explainable 0–100 risk scores...")
    incidents = group_alerts_into_incidents(alerts, context_registry=context_reg)
    user_profiles = compute_user_risk_profiles(incidents, baseline_repo, eval_events, context_registry=context_reg)
    print(f"    Formed {len(incidents)} security incidents.")

    # Console summary
    print("\n" + "=" * 60)
    print("TOP DETECTED INCIDENTS")
    print("=" * 60)
    for inc in incidents[:5]:
        print(f"[{inc.severity}] {inc.incident_id}: {inc.title} (Risk: {inc.risk_score}/100)")
        print(f"    {inc.risk_explanation}")
        print(f"    Action: {inc.recommended_action}\n")

    # Outputs
    if html_out:
        export_report_to_html(incidents, user_profiles, eval_quality, html_out)
        print(f"[+] Exported HTML investigation report: {html_out}")

    if csv_out:
        export_incidents_to_csv(incidents, csv_out)
        print(f"[+] Exported incidents CSV: {csv_out}")

    if evidence_csv_out:
        export_evidence_to_csv(incidents, evidence_csv_out)
        print(f"[+] Exported evidence rows CSV: {evidence_csv_out}")

    if user_csv_out:
        export_user_risk_to_csv(user_profiles, user_csv_out)
        print(f"[+] Exported user risk profiles CSV: {user_csv_out}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Mission 72 — Suspicious Login and Activity Detector")
    subparsers = parser.add_subparsers(dest="command")

    # Subcommand: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Run offline log analysis on training and evaluation CSVs")
    analyze_parser.add_argument("--train", required=True, help="Path to training CSV log file")
    analyze_parser.add_argument("--eval", required=True, help="Path to evaluation CSV log file")
    analyze_parser.add_argument("--html-out", help="Path to write standalone HTML report")
    analyze_parser.add_argument("--csv-out", help="Path to write incidents CSV summary")
    analyze_parser.add_argument("--evidence-csv-out", help="Path to write correlated evidence rows CSV")
    analyze_parser.add_argument("--user-csv-out", help="Path to write user risk profiles CSV")
    analyze_parser.add_argument("--date-format", help="Explicit date format if timestamps are ambiguous")
    analyze_parser.add_argument("--context-config", help="Path to JSON file containing maintenance windows, authorized accounts, and VPN endpoints")

    # Subcommand: serve
    serve_parser = subparsers.add_parser("serve", help="Launch investigator dashboard")
    serve_parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Host address to bind to (default: 127.0.0.1, or $HOST env var)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8072")),
        help="Port to serve on (default: 8072, or $PORT env var)",
    )

    # Subcommand: synthetic
    synthetic_parser = subparsers.add_parser("synthetic", help="Generate synthetic benchmark datasets")
    synthetic_parser.add_argument("--output-dir", default="data/synthetic", help="Output directory")
    synthetic_parser.add_argument("--seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()

    if args.command == "analyze":
        return run_analysis(
            train_file=args.train,
            eval_file=args.eval,
            html_out=args.html_out,
            csv_out=args.csv_out,
            evidence_csv_out=args.evidence_csv_out,
            user_csv_out=args.user_csv_out,
            date_format=args.date_format,
            context_config=args.context_config,
        )
    elif args.command == "serve":
        from mission72.server import start_server
        start_server(port=args.port, host=args.host)
        return 0
    elif args.command == "synthetic":
        t, e = generate_synthetic_datasets(output_dir=args.output_dir, seed=args.seed)
        print(f"Generated synthetic training dataset: {t}")
        print(f"Generated synthetic evaluation dataset: {e}")
        return 0
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
