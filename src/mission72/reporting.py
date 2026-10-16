"""
Reporting engine for Mission 72.
Generates CSV exports (incidents, evidence, user risk profiles) and a fully self-contained,
offline HTML investigation dashboard with filtering and collapsible evidence rows.
"""

import csv
import html
import json
from pathlib import Path
from typing import Dict, List, Optional, Union

from mission72.incidents import Incident, UserRiskProfile
from mission72.models import DataQualityReport


def export_incidents_to_csv(incidents: List[Incident], file_path: Union[str, Path]) -> None:
    """Exports summary of security incidents to CSV."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "incident_id",
        "title",
        "primary_entity",
        "severity",
        "risk_score",
        "risk_explanation",
        "rule_ids",
        "categories",
        "alert_count",
        "evidence_count",
        "start_time_utc",
        "end_time_utc",
        "source_ips",
        "destination_hosts",
        "triage_summary",
        "recommended_action",
        "context_status",
        "context_summary",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for inc in incidents:
            writer.writerow({
                "incident_id": inc.incident_id,
                "title": inc.title,
                "primary_entity": inc.primary_entity,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "risk_explanation": inc.risk_explanation,
                "rule_ids": "; ".join(inc.rule_ids),
                "categories": "; ".join(inc.categories),
                "alert_count": len(inc.alerts),
                "evidence_count": len(inc.evidence_records),
                "start_time_utc": inc.start_time_utc.isoformat(),
                "end_time_utc": inc.end_time_utc.isoformat(),
                "source_ips": "; ".join(inc.source_ips),
                "destination_hosts": "; ".join(inc.destination_hosts),
                "triage_summary": inc.triage_summary,
                "recommended_action": inc.recommended_action,
                "context_status": getattr(inc, "context_status", "NORMAL_EVALUATION"),
                "context_summary": getattr(inc, "context_summary", ""),
            })


def export_evidence_to_csv(incidents: List[Incident], file_path: Union[str, Path]) -> None:
    """Exports raw evidence rows across all incidents with exact row/file provenance."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "incident_id",
        "source_file",
        "row_number",
        "timestamp_utc",
        "username",
        "source_ip",
        "destination_host",
        "event_type",
        "result",
        "logon_type",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for inc in incidents:
            for ev in inc.evidence_records:
                row_dict = ev.to_dict()
                row_dict["incident_id"] = inc.incident_id
                writer.writerow(row_dict)


def export_user_risk_to_csv(profiles: List[UserRiskProfile], file_path: Union[str, Path]) -> None:
    """Exports consolidated per-user 0-100 risk profiles to CSV."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "username",
        "risk_score",
        "baseline_status",
        "incident_count",
        "highest_severity",
        "rules_triggered",
        "score_rationale",
    ]

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for p in profiles:
            writer.writerow({
                "username": p.username,
                "risk_score": p.risk_score,
                "baseline_status": p.baseline_status,
                "incident_count": p.incident_count,
                "highest_severity": p.highest_severity,
                "rules_triggered": "; ".join(p.rules_triggered),
                "score_rationale": p.score_rationale,
            })


def generate_html_report(
    incidents: List[Incident],
    user_profiles: List[UserRiskProfile],
    quality_report: Optional[DataQualityReport] = None,
    report_title: str = "Mission 72 — Investigation & Activity Dashboard",
) -> str:
    """
    Generates a completely self-contained, offline HTML report with inline CSS and vanilla JS.
    Includes metric cards, user risk tables, filterable incident list, and expandable evidence tables.
    """
    total_incidents = len(incidents)
    max_risk = max([inc.risk_score for inc in incidents], default=0)
    critical_count = sum(1 for inc in incidents if inc.severity == "CRITICAL")
    high_count = sum(1 for inc in incidents if inc.severity == "HIGH")
    total_evidence = sum(len(inc.evidence_records) for inc in incidents)

    q_summary = quality_report.summary() if quality_report else {
        "total_records": 0, "valid_records": 0, "malformed_records": 0,
        "missing_columns": [], "duplicate_candidate_count": 0
    }

    # Incident cards generation
    incident_cards_html = []
    for inc in incidents:
        sev_class = inc.severity.lower()
        score_color = "#dc2626" if inc.risk_score >= 70 else ("#f59e0b" if inc.risk_score >= 40 else "#10b981")

        # Evidence table rows
        ev_rows = []
        for ev in inc.evidence_records:
            res_badge = f'<span class="badge badge-{ev.result.lower()}">{html.escape(ev.result)}</span>'
            ev_rows.append(
                f"<tr>"
                f"<td><code>{html.escape(Path(ev.source_file).name)}:{ev.row_number}</code></td>"
                f"<td>{html.escape(ev.timestamp_utc)}</td>"
                f"<td><strong>{html.escape(ev.username)}</strong></td>"
                f"<td><code>{html.escape(ev.source_ip)}</code></td>"
                f"<td><code>{html.escape(ev.destination_host)}</code></td>"
                f"<td>{html.escape(ev.event_type)}</td>"
                f"<td>{res_badge}</td>"
                f"<td>{html.escape(ev.logon_type)}</td>"
                f"</tr>"
            )
        ev_table_html = "".join(ev_rows)

        rule_badges = ", ".join([f'<span class="badge badge-rule">{html.escape(r)}</span>' for r in inc.rule_ids])
        cat_badges = "".join([f'<span class="badge badge-cat">{html.escape(c)}</span>' for c in inc.categories])

        context_status_badge = ""
        c_status = getattr(inc, "context_status", "NORMAL_EVALUATION")
        c_summary = getattr(inc, "context_summary", "")
        if c_status == "APPROVED_MAINTENANCE":
            context_status_badge = '<span class="badge" style="background:#064e3b;color:#34d399;border:1px solid #059669;margin-right:6px">APPROVED MAINTENANCE</span>'
        elif c_status == "VERIFIED_VPN":
            context_status_badge = '<span class="badge" style="background:#1e3a8a;color:#60a5fa;border:1px solid #3b82f6;margin-right:6px">VERIFIED VPN</span>'
        elif c_status == "APPROVAL_MISMATCH":
            context_status_badge = '<span class="badge" style="background:#78350f;color:#fbbf24;border:1px solid #d97706;margin-right:6px">APPROVAL MISMATCH</span>'

        context_html = ""
        if c_summary:
            context_html = f'<div class="card-explanation" style="border-left: 3px solid #6366f1; margin-top: 6px;"><strong>Context Evaluation:</strong> {context_status_badge}{html.escape(c_summary)}</div>'

        card_html = f"""
        <div class="incident-card" data-severity="{inc.severity}" data-entity="{html.escape(inc.primary_entity.lower())}" data-score="{inc.risk_score}">
            <div class="card-header">
                <div>
                    <span class="badge badge-{sev_class}">{inc.severity}</span>
                    <span class="incident-id">{html.escape(inc.incident_id)}</span>
                    <h3 class="incident-title">{html.escape(inc.title)}</h3>
                </div>
                <div class="score-box" style="border-color: {score_color}; color: {score_color}">
                    <span class="score-val">{inc.risk_score}</span>
                    <span class="score-label">RISK SCORE</span>
                </div>
            </div>
            <div class="card-meta">
                <div><strong>Primary Entity:</strong> <code>{html.escape(inc.primary_entity)}</code></div>
                <div><strong>Time Window:</strong> {html.escape(inc.start_time_utc.strftime('%Y-%m-%d %H:%M:%S'))} to {html.escape(inc.end_time_utc.strftime('%H:%M:%S'))} UTC</div>
                <div><strong>Rules:</strong> {rule_badges}</div>
                <div><strong>Categories:</strong> {cat_badges}</div>
            </div>
            <div class="card-explanation">
                <strong>Score Derivation:</strong> {html.escape(inc.risk_explanation)}
            </div>
            {context_html}
            <div class="card-action">
                <strong>Recommended Triage:</strong> {html.escape(inc.recommended_action)}
            </div>
            <details class="evidence-details">
                <summary>View Correlated Evidence Rows ({len(inc.evidence_records)} events)</summary>
                <div class="table-container">
                    <table class="evidence-table">
                        <thead>
                            <tr>
                                <th>Source : Line</th>
                                <th>Timestamp (UTC)</th>
                                <th>User</th>
                                <th>Source IP</th>
                                <th>Destination Host</th>
                                <th>Event Type</th>
                                <th>Result</th>
                                <th>Logon Type</th>
                            </tr>
                        </thead>
                        <tbody>
                            {ev_table_html}
                        </tbody>
                    </table>
                </div>
            </details>
        </div>
        """
        incident_cards_html.append(card_html)

    # User risk table rows
    user_rows = []
    for p in user_profiles:
        score_color = "#dc2626" if p.risk_score >= 70 else ("#f59e0b" if p.risk_score >= 40 else "#10b981")
        sev_badge = f'<span class="badge badge-{p.highest_severity.lower()}">{p.highest_severity}</span>' if p.highest_severity != "NONE" else '<span class="badge badge-normal">CLEAN</span>'
        user_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(p.username)}</strong></td>"
            f"<td><span style='color: {score_color}; font-weight: bold;'>{p.risk_score} / 100</span></td>"
            f"<td><span class='badge badge-status'>{html.escape(p.baseline_status)}</span></td>"
            f"<td>{p.incident_count}</td>"
            f"<td>{sev_badge}</td>"
            f"<td><code>{html.escape(', '.join(p.rules_triggered) if p.rules_triggered else 'None')}</code></td>"
            f"<td class='small-text'>{html.escape(p.score_rationale)}</td>"
            f"</tr>"
        )
    user_table_html = "".join(user_rows)

    all_cards_html = "\n".join(incident_cards_html) if incident_cards_html else "<div class='empty-state'>No security incidents detected matching the current criteria.</div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(report_title)}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f1f5f9;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --primary: #38bdf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.5;
            padding: 24px;
        }}
        .header {{ margin-bottom: 24px; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; }}
        .header h1 {{ font-size: 24px; color: var(--primary); display: flex; align-items: center; gap: 8px; }}
        .header p {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }}
        .metric-title {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
        .metric-value {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}

        .filter-panel {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            align-items: center;
        }}
        .filter-group {{ display: flex; flex-direction: column; gap: 4px; }}
        .filter-group label {{ font-size: 12px; color: var(--text-muted); font-weight: 600; }}
        .filter-group input, .filter-group select {{
            background: #0f172a;
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
        }}

        .tabs {{ display: flex; gap: 8px; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); }}
        .tab-btn {{
            background: none;
            border: none;
            color: var(--text-muted);
            padding: 10px 16px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }}
        .tab-btn.active {{ color: var(--primary); border-bottom-color: var(--primary); }}

        .incident-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}
        .card-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
        .incident-id {{ font-size: 12px; color: var(--text-muted); font-family: monospace; }}
        .incident-title {{ font-size: 18px; font-weight: 600; color: #fff; margin-top: 4px; }}
        .score-box {{
            border: 2px solid;
            border-radius: 8px;
            padding: 6px 12px;
            text-align: center;
            min-width: 90px;
        }}
        .score-val {{ font-size: 22px; font-weight: 800; display: block; line-height: 1; }}
        .score-label {{ font-size: 9px; font-weight: 700; letter-spacing: 0.5px; }}

        .card-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 8px;
            font-size: 13px;
            margin-bottom: 12px;
            background: #0f172a80;
            padding: 10px;
            border-radius: 6px;
        }}
        .card-explanation, .card-action {{
            font-size: 13px;
            margin-bottom: 8px;
            padding: 8px 12px;
            border-radius: 6px;
        }}
        .card-explanation {{ background: #1e293b; border-left: 3px solid var(--primary); }}
        .card-action {{ background: #0f172a; border-left: 3px solid var(--warning); }}

        .badge {{
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #831843; color: #fbcfe8; }}
        .badge-medium {{ background: #78350f; color: #fde68a; }}
        .badge-low {{ background: #064e3b; color: #a7f3d0; }}
        .badge-rule {{ background: #312e81; color: #c7d2fe; margin-right: 4px; }}
        .badge-cat {{ background: #1e1b4b; color: #e0e7ff; margin-right: 4px; }}
        .badge-success {{ background: #065f46; color: #a7f3d0; }}
        .badge-failure {{ background: #991b1b; color: #fecaca; }}
        .badge-status {{ background: #334155; color: #cbd5e1; }}
        .badge-normal {{ background: #064e3b; color: #6ee7b7; }}

        details.evidence-details {{ margin-top: 12px; }}
        details.evidence-details summary {{
            cursor: pointer;
            color: var(--primary);
            font-size: 13px;
            font-weight: 600;
            padding: 4px 0;
        }}
        .table-container {{ overflow-x: auto; margin-top: 8px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            text-align: left;
        }}
        th, td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background: #0f172a; color: var(--text-muted); font-weight: 600; }}
        tr:hover td {{ background: #1e293b80; }}
        code {{ font-family: monospace; font-size: 11px; }}
        .small-text {{ font-size: 11px; color: var(--text-muted); }}
        .empty-state {{ padding: 32px; text-align: center; color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{html.escape(report_title)}</h1>
        <p>Offline Authentication Log Security Audit & Incident Timeline | Generated Locally</p>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-title">Total Incidents</div>
            <div class="metric-value" style="color: var(--primary)">{total_incidents}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Critical / High</div>
            <div class="metric-value" style="color: var(--danger)">{critical_count + high_count}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Max Risk Score</div>
            <div class="metric-value" style="color: {'#ef4444' if max_risk >= 70 else '#f59e0b'}">{max_risk} / 100</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Correlated Evidence</div>
            <div class="metric-value" style="color: #cbd5e1">{total_evidence} rows</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Data Ingestion</div>
            <div class="metric-value" style="color: {'#10b981' if q_summary.get('malformed_records', 0) == 0 else '#f59e0b'}">
                {q_summary.get('valid_records', 0)} / {q_summary.get('total_records', 0)}
            </div>
        </div>
    </div>

    <div class="filter-panel">
        <div class="filter-group">
            <label for="filter-entity">Filter by Entity / User</label>
            <input type="text" id="filter-entity" placeholder="e.g. alice, charlie, IP..." oninput="applyFilters()">
        </div>
        <div class="filter-group">
            <label for="filter-severity">Severity</label>
            <select id="filter-severity" onchange="applyFilters()">
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>
        </div>
        <div class="filter-group">
            <label for="filter-min-score">Minimum Risk Score</label>
            <input type="number" id="filter-min-score" min="0" max="100" value="0" oninput="applyFilters()" style="width: 80px;">
        </div>
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('incidents-tab', this)">Security Incidents ({total_incidents})</button>
        <button class="tab-btn" onclick="switchTab('users-tab', this)">Per-User Risk Profiles ({len(user_profiles)})</button>
        <button class="tab-btn" onclick="switchTab('quality-tab', this)">Data Quality Audit</button>
    </div>

    <div id="incidents-tab" class="tab-content">
        <div id="incidents-container">
            {all_cards_html}
        </div>
    </div>

    <div id="users-tab" class="tab-content" style="display: none;">
        <div class="metric-card">
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>User Account</th>
                            <th>Risk Score (0–100)</th>
                            <th>Baseline Status</th>
                            <th>Incidents</th>
                            <th>Highest Severity</th>
                            <th>Rules Triggered</th>
                            <th>Score Rationale</th>
                        </tr>
                    </thead>
                    <tbody>
                        {user_table_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="quality-tab" class="tab-content" style="display: none;">
        <div class="metric-card">
            <h3 style="margin-bottom: 12px; color: var(--primary);">Ingestion Quality & Provenance Summary</h3>
            <p style="margin-bottom: 8px;"><strong>Total Raw Records Read:</strong> {q_summary.get('total_records', 0)}</p>
            <p style="margin-bottom: 8px;"><strong>Valid Records Normalized:</strong> {q_summary.get('valid_records', 0)}</p>
            <p style="margin-bottom: 8px;"><strong>Malformed / Corrupted Records:</strong> {q_summary.get('malformed_records', 0)}</p>
            <p style="margin-bottom: 8px;"><strong>Missing Header Columns:</strong> {html.escape(str(q_summary.get('missing_columns', [])))}</p>
            <p style="margin-bottom: 8px;"><strong>Candidate Duplicate Rows Flagged:</strong> {q_summary.get('duplicate_candidate_count', 0)}</p>
            <p style="margin-top: 12px; font-size: 12px; color: var(--text-muted);">
                * Note: In compliance with cybersecurity audit rules, malformed and duplicate candidate rows are preserved for forensic completeness and are never silently discarded.
            </p>
        </div>
    </div>

    <script>
        function switchTab(tabId, btn) {{
            document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).style.display = 'block';
            btn.classList.add('active');
        }}

        function applyFilters() {{
            const entityQuery = document.getElementById('filter-entity').value.toLowerCase().trim();
            const severityFilter = document.getElementById('filter-severity').value;
            const minScore = parseInt(document.getElementById('filter-min-score').value, 10) || 0;

            const cards = document.querySelectorAll('.incident-card');
            let visibleCount = 0;

            cards.forEach(card => {{
                const entity = card.getAttribute('data-entity') || '';
                const severity = card.getAttribute('data-severity') || '';
                const score = parseInt(card.getAttribute('data-score'), 10) || 0;

                const matchEntity = !entityQuery || entity.includes(entityQuery);
                const matchSeverity = severityFilter === 'ALL' || severity === severityFilter;
                const matchScore = score >= minScore;

                if (matchEntity && matchSeverity && matchScore) {{
                    card.style.display = 'block';
                    visibleCount++;
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
    return html_content


def export_report_to_html(
    incidents: List[Incident],
    user_profiles: List[UserRiskProfile],
    quality_report: Optional[DataQualityReport] = None,
    file_path: Union[str, Path] = "report.html",
) -> None:
    """Writes the self-contained HTML report to disk."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_html_report(incidents, user_profiles, quality_report)
    path.write_text(content, encoding="utf-8")
