"""
Local investigator interface and server for Mission 72.
Provides a zero-dependency, local web dashboard running on Python's built-in http.server.
Supports log upload, interactive analysis across all 6 detection rules, incident filtering,
evidence inspection, and CSV/HTML report downloads.
"""

import email
from email.policy import default as email_default
import io
import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mission72.baseline import build_user_baselines
from mission72.context import ContextRegistry, create_default_context_registry
from mission72.detections import DetectionEngine, RuleConfig
from mission72.incidents import (
    compute_user_risk_profiles,
    group_alerts_into_incidents,
)
from mission72.ingestion import parse_csv_stream
from mission72.reporting import (
    export_evidence_to_csv,
    export_incidents_to_csv,
    export_user_risk_to_csv,
    generate_html_report,
)


def get_active_context_registry() -> ContextRegistry:
    cfg_path = Path("config/context_config.json")
    if cfg_path.exists():
        try:
            return ContextRegistry.from_file(cfg_path)
        except Exception:
            pass
    return create_default_context_registry()


class InvestigatorState:
    """Holds active analysis state in memory for the local server session."""
    def __init__(self) -> None:
        self.incidents = []
        self.user_profiles = []
        self.quality_report = None
        self.training_events_count = 0
        self.evaluation_events_count = 0


GLOBAL_STATE = InvestigatorState()


# ---------------------------------------------------------------------------
# Dashboard HTML template
# Placeholders replaced by _render_dashboard:
#   __INCIDENT_JSON__   — JSON array of incident objects
#   __METRICS_JSON__    — JSON object with summary stats
#   __HAS_RESULTS__     — JSON boolean (true/false)
# All log-sourced data is embedded as JSON (json.dumps) and read by JavaScript
# using textContent / createElement — never innerHTML — for XSS safety.
# ---------------------------------------------------------------------------
SERVER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mission 72 — Authentication Threat Investigation</title>
    <style>
        :root {
            --bg:       #0d1117;
            --surface:  #161b27;
            --surface2: #1c2333;
            --border:   #30363d;
            --border2:  #21262d;
            --text:     #e6edf3;
            --muted:    #7d8590;
            --accent:   #3b82f6;
            --danger:   #f85149;
            --high:     #f0883e;
            --medium:   #d29922;
            --low:      #7d8590;
            --success:  #3fb950;
            --focus:    #388bfd;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            font-size: 14px;
            line-height: 1.5;
            min-height: 100vh;
        }
        :focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
        code { font-family: ui-monospace, "Cascadia Code", "Fira Code", monospace;
               font-size: 12px; }

        /* Shell */
        .app-shell { max-width: 1440px; margin: 0 auto; padding: 0 20px 48px; }

        /* ── Header ── */
        .page-header {
            display: flex; align-items: center;
            padding: 14px 0; border-bottom: 1px solid var(--border);
        }
        .brand h1 {
            font-size: 16px; font-weight: 700; color: var(--text); letter-spacing: -0.2px;
        }
        .brand h1 span {
            font-size: 13px; font-weight: 400; color: var(--muted); margin-left: 10px;
        }

        /* ── Upload section ── */
        .upload-section { border-bottom: 1px solid var(--border); }
        .upload-toggle {
            display: flex; align-items: center; gap: 7px;
            padding: 10px 0; background: transparent; border: none;
            color: var(--muted); font-size: 13px; font-weight: 500;
            cursor: pointer; width: 100%; text-align: left; font-family: inherit;
        }
        .upload-toggle:hover { color: var(--text); }
        .toggle-icon { font-size: 10px; }
        .upload-body { padding: 4px 0 20px; }
        .upload-grid {
            display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 16px;
        }
        @media (max-width: 640px) { .upload-grid { grid-template-columns: 1fr; } }
        .upload-field label {
            font-size: 13px; font-weight: 600; display: block; margin-bottom: 3px;
        }
        .field-hint { font-size: 12px; color: var(--muted); margin-bottom: 8px; line-height: 1.5; }
        .opt-label  { font-weight: 400; color: var(--muted); font-size: 12px; }
        .req-label  {
            font-size: 11px; color: var(--accent); font-weight: 600;
            background: #1e2a4a; padding: 1px 6px; border-radius: 3px; margin-left: 5px;
        }
        input[type="file"] { font-size: 13px; color: var(--text); width: 100%; }
        .file-name {
            font-size: 12px; color: var(--muted); margin-top: 4px;
            display: block; font-style: italic; min-height: 18px;
        }
        .upload-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .upload-or { font-size: 13px; color: var(--muted); }
        .btn-primary {
            background: var(--accent); color: #fff; border: none;
            padding: 9px 20px; border-radius: 6px; font-size: 14px; font-weight: 600;
            cursor: pointer; font-family: inherit; letter-spacing: -0.1px;
        }
        .btn-primary:hover { background: #2563eb; }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-secondary {
            font-size: 13px; color: var(--muted); text-decoration: none;
            border: 1px solid var(--border); padding: 8px 14px; border-radius: 6px;
            display: inline-block; font-weight: 500;
        }
        .btn-secondary:hover { color: var(--text); border-color: var(--accent); }
        .upload-error { font-size: 13px; color: var(--danger); margin-top: 8px; min-height: 20px; }

        /* ── Summary bar ── */
        .summary-bar {
            display: flex; gap: 28px; align-items: center;
            padding: 12px 0; border-bottom: 1px solid var(--border); flex-wrap: wrap;
        }
        .stat { display: flex; flex-direction: column; }
        .stat-val   { font-size: 22px; font-weight: 700; line-height: 1.1; }
        .stat-label {
            font-size: 10px; color: var(--muted); text-transform: uppercase;
            letter-spacing: 0.6px; margin-top: 2px; font-weight: 600;
        }
        .sev-danger { color: var(--danger); }

        /* ── Filter bar ── */
        .filter-bar {
            display: flex; gap: 10px; align-items: center;
            padding: 10px 0; flex-wrap: wrap;
        }
        .filter-label { font-size: 11px; color: var(--muted); white-space: nowrap; }
        .filter-bar input[type="search"],
        .filter-bar input[type="number"],
        .filter-bar select {
            background: var(--surface); border: 1px solid var(--border);
            color: var(--text); padding: 7px 10px; border-radius: 6px;
            font-size: 13px; font-family: inherit;
        }
        .filter-bar input[type="search"]  { width: 220px; }
        .filter-bar select                { min-width: 130px; }
        .filter-bar input[type="number"]  { width: 72px; }
        .filter-bar input::placeholder    { color: var(--muted); }
        .btn-reset {
            background: transparent; border: 1px solid var(--border);
            color: var(--muted); padding: 7px 12px; border-radius: 6px;
            font-size: 13px; cursor: pointer; font-family: inherit;
        }
        .btn-reset:hover { color: var(--text); }
        .filter-count { font-size: 12px; color: var(--muted); margin-left: auto; }

        /* ── Workspace ── */
        .workspace { display: flex; min-height: 400px; align-items: flex-start; }
        .incident-table-area { flex: 1; overflow: hidden; min-width: 0; }
        .incident-table-area.panel-open { border-right: 1px solid var(--border); }

        /* ── Incident table ── */
        .incident-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .incident-table thead th {
            padding: 8px 12px; text-align: left; color: var(--muted);
            font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
            position: sticky; top: 0; background: var(--bg); white-space: nowrap;
        }
        .incident-table tbody tr {
            border-bottom: 1px solid var(--border2); cursor: pointer;
        }
        .incident-table tbody tr:hover  { background: var(--surface); }
        .incident-table tbody tr.active { background: var(--surface2); }
        .incident-table tbody td { padding: 10px 12px; vertical-align: middle; }
        .sev-dot {
            display: inline-block; width: 8px; height: 8px;
            border-radius: 50%; margin-right: 7px; vertical-align: middle; flex-shrink: 0;
        }
        .sev-cell { display: flex; align-items: center; white-space: nowrap; }
        .sev-text { font-size: 11px; font-weight: 700; }
        .inc-id   { font-family: monospace; font-size: 11px; color: var(--muted); margin-right: 6px; }
        .inc-title { font-weight: 500; }
        .score-pill { font-size: 12px; font-weight: 700; font-variant-numeric: tabular-nums; }
        .time-cell { color: var(--muted); font-size: 12px; white-space: nowrap; }
        .cats-cell {
            font-size: 12px; color: var(--muted);
            max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }

        /* ── Empty state ── */
        .empty-state { text-align: center; padding: 60px 20px; color: var(--muted); }
        .empty-title { font-size: 17px; font-weight: 600; color: var(--text); margin-bottom: 6px; }
        .empty-sub   { font-size: 14px; }

        /* ── Detail panel ── */
        .detail-panel {
            width: 440px; min-width: 440px; max-width: 440px;
            border-left: 1px solid var(--border);
            padding: 20px 20px 32px;
            overflow-y: auto; display: none;
            align-self: stretch;
            max-height: calc(100vh - 160px);
            position: sticky; top: 0;
        }
        @media (max-width: 920px) {
            .workspace      { flex-direction: column; }
            .detail-panel   {
                width: 100%; min-width: 0; max-width: 100%;
                border-left: none; border-top: 1px solid var(--border);
                position: static; max-height: none;
            }
            .incident-table-area.panel-open { border-right: none; }
        }
        .panel-header {
            display: flex; justify-content: space-between;
            align-items: flex-start; margin-bottom: 12px;
        }
        .panel-close {
            background: transparent; border: none;
            color: var(--muted); font-size: 22px; cursor: pointer;
            line-height: 1; padding: 0; flex-shrink: 0; font-family: inherit;
        }
        .panel-close:hover { color: var(--text); }
        .panel-inc-id   { font-family: monospace; font-size: 12px; color: var(--muted); }
        .panel-sev-badge { font-size: 12px; font-weight: 700; margin-left: 8px; }
        .panel-score       { font-size: 44px; font-weight: 800; line-height: 1; }
        .panel-score-label {
            font-size: 10px; color: var(--muted); text-transform: uppercase;
            letter-spacing: 0.6px; margin-top: 2px; margin-bottom: 10px;
        }
        .panel-title   { font-size: 15px; font-weight: 600; margin-bottom: 4px; line-height: 1.4; }
        .panel-section { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--border2); }
        .panel-section-title {
            font-size: 10px; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.6px; color: var(--muted); margin-bottom: 6px;
        }
        .panel-value { font-size: 13px; }
        .badge-rule {
            font-size: 11px; padding: 2px 8px; border-radius: 4px;
            background: #1e2a4a; color: #7da3f5; border: 1px solid #2d4070;
            display: inline-block; margin-right: 4px; margin-bottom: 4px;
        }
        .badge-cat {
            font-size: 11px; padding: 2px 8px; border-radius: 4px;
            background: #152a1e; color: #3fb950; border: 1px solid #1f4030;
            display: inline-block; margin-right: 4px; margin-bottom: 4px;
        }
        .badge-context-approved {
            font-size: 11px; padding: 2px 8px; border-radius: 4px;
            background: #152a1e; color: #3fb950; border: 1px solid #1f4030;
            display: inline-block; font-weight: 600;
        }
        .badge-context-vpn {
            font-size: 11px; padding: 2px 8px; border-radius: 4px;
            background: #1e2a4a; color: #7da3f5; border: 1px solid #2d4070;
            display: inline-block; font-weight: 600;
        }
        .badge-context-mismatch {
            font-size: 11px; padding: 2px 8px; border-radius: 4px;
            background: #3d1c1c; color: #f85149; border: 1px solid #5a2424;
            display: inline-block; font-weight: 600;
        }
        .action-box {
            background: var(--surface); border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius: 6px; padding: 10px 12px;
            font-size: 13px; line-height: 1.6;
        }
        details.tech-details > summary {
            cursor: pointer; font-size: 12px; color: var(--muted);
            padding: 10px 0; border-top: 1px solid var(--border2); margin-top: 14px;
            list-style: none; display: flex; align-items: center; gap: 6px;
        }
        details.tech-details > summary::before      { content: "\\25B8"; font-size: 10px; }
        details.tech-details[open] > summary::before { content: "\\25BE"; }
        details.tech-details > summary:hover { color: var(--text); }
        .tech-content { font-size: 12px; color: var(--muted); padding: 8px 0; }
        .score-breakdown {
            font-family: monospace; font-size: 11px;
            white-space: pre-wrap; word-break: break-word; line-height: 1.7;
        }

        /* Evidence table inside panel */
        .ev-table-wrap { overflow-x: auto; margin-top: 8px; }
        .ev-table { width: 100%; border-collapse: collapse; font-size: 11px; }
        .ev-table thead th {
            color: var(--muted); padding-bottom: 5px; text-align: left;
            font-weight: 600; font-size: 10px; text-transform: uppercase;
            border-bottom: 1px solid var(--border); white-space: nowrap; padding-right: 10px;
        }
        .ev-table tbody td {
            padding: 4px 10px 4px 0; border-bottom: 1px solid var(--border2);
            vertical-align: top; white-space: nowrap;
        }
        .result-fail    { color: var(--danger);  font-weight: 600; }
        .result-success { color: var(--success); font-weight: 600; }

        /* ── Exports ── */
        .exports-section { border-top: 1px solid var(--border); margin-top: 16px; }
        .exports-section > summary {
            padding: 11px 0; font-size: 13px; color: var(--muted);
            cursor: pointer; list-style: none;
            display: flex; align-items: center; gap: 6px; user-select: none;
        }
        .exports-section > summary::marker { display: none; }
        .exports-section > summary:hover { color: var(--text); }
        .exports-section > summary::before { content: "\\2193"; font-size: 12px; }
        .export-links { display: flex; gap: 10px; padding: 6px 0 14px; flex-wrap: wrap; }
        .export-link {
            color: var(--muted); font-size: 13px; text-decoration: none;
            border: 1px solid var(--border); padding: 6px 14px;
            border-radius: 6px; display: inline-block;
        }
        .export-link:hover { color: var(--text); border-color: var(--accent); }
    </style>
</head>
<body>
<div class="app-shell">

    <!-- Page header -->
    <header class="page-header">
        <div class="brand">
            <h1>Mission 72 <span>Authentication Threat Investigation</span></h1>
        </div>
    </header>

    <!-- Upload section (collapsible) -->
    <section class="upload-section">
        <button type="button" class="upload-toggle" id="upload-toggle"
                onclick="toggleUpload()" aria-expanded="false" aria-controls="upload-body">
            <span class="toggle-icon" id="toggle-icon">&#9658;</span>
            Analyze new logs
        </button>
        <div class="upload-body" id="upload-body" style="display:none">
            <form id="analyze-form" action="/analyze" method="POST"
                  enctype="multipart/form-data" onsubmit="return handleSubmit(event)">
                <div class="upload-grid">
                    <div class="upload-field">
                        <label for="train_file">
                            Training log <span class="opt-label">(optional)</span>
                        </label>
                        <p class="field-hint">Establishes each user&rsquo;s normal working hours,
                        source IPs, and destination hosts. Leave blank to run detection without
                        a behavioral baseline.</p>
                        <input type="file" id="train_file" name="train_file" accept=".csv"
                               onchange="showName(this,'train-name')">
                        <span class="file-name" id="train-name"></span>
                    </div>
                    <div class="upload-field">
                        <label for="eval_file">
                            Evaluation log <span class="req-label">Required</span>
                        </label>
                        <p class="field-hint">The authentication activity under investigation.
                        All six detection categories are applied to this dataset.</p>
                        <input type="file" id="eval_file" name="eval_file" accept=".csv"
                               onchange="showName(this,'eval-name')">
                        <span class="file-name" id="eval-name"></span>
                    </div>
                </div>
                <div class="upload-actions">
                    <button type="submit" class="btn-primary" id="submit-btn">Analyze logs</button>
                    <span class="upload-or">or</span>
                    <a href="/analyze-synthetic" class="btn-secondary">Load synthetic benchmark</a>
                </div>
                <div class="upload-error" id="upload-error"></div>
            </form>
        </div>
    </section>

    <!-- Summary bar -->
    <div class="summary-bar" id="summary-bar" style="display:none">
        <div class="stat">
            <span class="stat-val" id="st-total">0</span>
            <span class="stat-label">Incidents</span>
        </div>
        <div class="stat">
            <span class="stat-val sev-danger" id="st-crithigh">0</span>
            <span class="stat-label">Critical / High</span>
        </div>
        <div class="stat">
            <span class="stat-val" id="st-maxscore">0</span>
            <span class="stat-label">Highest Score</span>
        </div>
        <div class="stat">
            <span class="stat-val" id="st-users">0</span>
            <span class="stat-label">Profiled Users</span>
        </div>
    </div>

    <!-- Filter bar -->
    <div class="filter-bar" id="filter-bar" style="display:none">
        <span class="filter-label">Filter:</span>
        <input type="search" id="q-entity"
               placeholder="User, entity, or IP&hellip;"
               oninput="applyFilters()"
               aria-label="Search incidents by entity, user, or IP">
        <select id="q-sev" onchange="applyFilters()" aria-label="Filter by severity">
            <option value="ALL">All severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
        </select>
        <input type="number" id="q-score" min="0" max="100" value="0"
               oninput="applyFilters()"
               aria-label="Minimum risk score" title="Minimum risk score">
        <button class="btn-reset" onclick="resetFilters()" type="button">Reset</button>
        <span class="filter-count" id="filter-count" aria-live="polite"></span>
    </div>

    <!-- Main workspace: incident table + detail panel -->
    <div class="workspace" id="workspace">
        <div class="incident-table-area" id="table-area">
            <div class="empty-state" id="empty-state">
                <div class="empty-title">No analysis loaded</div>
                <div class="empty-sub">Upload authentication logs above to begin,
                    or load the synthetic benchmark.</div>
            </div>
            <div id="table-container" style="display:none">
                <table class="incident-table" id="incident-table">
                    <thead>
                        <tr>
                            <th scope="col">Severity</th>
                            <th scope="col">Incident</th>
                            <th scope="col">Entity</th>
                            <th scope="col">Score</th>
                            <th scope="col">Start&nbsp;Time (UTC)</th>
                            <th scope="col">Categories</th>
                        </tr>
                    </thead>
                    <tbody id="incident-tbody"></tbody>
                </table>
            </div>
        </div>

        <!-- Detail panel (hidden until a row is selected) -->
        <aside class="detail-panel" id="detail-panel" aria-label="Incident details">
            <div class="panel-header">
                <div>
                    <span class="panel-inc-id" id="p-id"></span>
                    <span class="panel-sev-badge" id="p-sev"></span>
                </div>
                <button class="panel-close" onclick="closePanel()"
                        aria-label="Close detail panel">&times;</button>
            </div>
            <div class="panel-score" id="p-score"></div>
            <div class="panel-score-label">Risk Score / 100</div>
            <h2 class="panel-title" id="p-title"></h2>

            <div class="panel-section">
                <div class="panel-section-title">Entity</div>
                <div class="panel-value" id="p-entity"
                     style="font-family:monospace;font-size:13px"></div>
            </div>
            <div class="panel-section">
                <div class="panel-section-title">Time Range</div>
                <div class="panel-value" id="p-time"></div>
            </div>
            <div class="panel-section">
                <div class="panel-section-title">Detection Rules</div>
                <div id="p-rules"></div>
            </div>
            <div class="panel-section">
                <div class="panel-section-title">Categories</div>
                <div id="p-cats"></div>
            </div>
            <div class="panel-section" id="p-context-sec">
                <div class="panel-section-title">Context Policy Status</div>
                <div id="p-context-badge"></div>
                <div id="p-context-summary" style="font-size:12px;color:var(--muted);margin-top:6px;line-height:1.4"></div>
            </div>
            <div class="panel-section">
                <div class="panel-section-title">Recommended Action</div>
                <div class="action-box" id="p-action"></div>
            </div>

            <details class="tech-details">
                <summary>Technical details</summary>
                <div class="tech-content">
                    <div class="panel-section-title" style="margin-top:6px">Score Breakdown</div>
                    <div class="score-breakdown" id="p-explanation"></div>
                    <div class="panel-section-title" style="margin-top:14px">Supporting Evidence</div>
                    <div class="ev-table-wrap">
                        <table class="ev-table">
                            <thead><tr>
                                <th>Source&thinsp;:&thinsp;Line</th>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Source IP</th>
                                <th>Host</th>
                                <th>Event</th>
                                <th>Result</th>
                                <th>Logon</th>
                            </tr></thead>
                            <tbody id="p-ev-body"></tbody>
                        </table>
                    </div>
                </div>
            </details>
        </aside>
    </div>

    <!-- Export section (collapsed by default) -->
    <details class="exports-section">
        <summary>Download reports</summary>
        <div class="export-links">
            <a href="/export/incidents.csv" class="export-link">Incidents CSV</a>
            <a href="/export/evidence.csv"  class="export-link">Evidence CSV</a>
            <a href="/export/users.csv"     class="export-link">User Risk CSV</a>
            <a href="/export/report.html"   class="export-link" target="_blank">Full HTML Report</a>
        </div>
    </details>

</div><!-- /.app-shell -->

<script>
/* ── Data injected by Python (safe JSON; never raw log content) ── */
const INCIDENTS   = __INCIDENT_JSON__;
const METRICS     = __METRICS_JSON__;
const HAS_RESULTS = __HAS_RESULTS__;

/* ── Severity / score color maps ── */
const SEV_DOT   = {CRITICAL:'#f85149', HIGH:'#f0883e', MEDIUM:'#d29922', LOW:'#7d8590'};
const SEV_COLOR = {
    CRITICAL:'var(--danger)', HIGH:'var(--high)',
    MEDIUM:'var(--medium)',   LOW:'var(--low)'
};
function sevColor(s)   { return SEV_COLOR[s] || 'var(--muted)'; }
function scoreColor(n) { return n >= 70 ? 'var(--danger)' : n >= 40 ? 'var(--high)' : 'var(--muted)'; }

var selectedId = null;

/* ── Bootstrap ── */
document.addEventListener('DOMContentLoaded', function () {
    if (HAS_RESULTS) {
        document.getElementById('summary-bar').style.display = 'flex';
        document.getElementById('filter-bar').style.display  = 'flex';
        setText('st-total',    METRICS.total);
        setText('st-crithigh', METRICS.critical_high);
        setText('st-maxscore', METRICS.max_score);
        setText('st-users',    METRICS.profiled_users);
        document.getElementById('st-maxscore').style.color = scoreColor(METRICS.max_score);
        document.getElementById('empty-state').style.display    = 'none';
        document.getElementById('table-container').style.display = 'block';
        renderTable();
        applyFilters();
    } else {
        showUpload(true);
    }
});

/* ── Upload toggle ── */
function showUpload(open) {
    document.getElementById('upload-body').style.display = open ? 'block' : 'none';
    document.getElementById('upload-toggle').setAttribute('aria-expanded', open ? 'true' : 'false');
    document.getElementById('toggle-icon').textContent = open ? '\\u25BE' : '\\u25B8';
}
function toggleUpload() {
    showUpload(document.getElementById('upload-toggle').getAttribute('aria-expanded') === 'false');
}

/* Show selected filename next to input */
function showName(input, spanId) {
    document.getElementById(spanId).textContent =
        (input.files && input.files.length) ? input.files[0].name : '';
}

/* Validate and disable button on submit */
function handleSubmit(e) {
    var evInput = document.getElementById('eval_file');
    var errEl   = document.getElementById('upload-error');
    errEl.textContent = '';
    if (!evInput.files || !evInput.files.length) {
        e.preventDefault();
        errEl.textContent = 'Please select an evaluation log CSV before running analysis.';
        return false;
    }
    var btn = document.getElementById('submit-btn');
    btn.disabled    = true;
    btn.textContent = 'Analyzing\\u2026';
    return true;
}

/* ── Table rendering ── */
function renderTable() {
    var tbody = document.getElementById('incident-tbody');
    tbody.innerHTML = '';

    INCIDENTS.forEach(function (inc) {
        var tr = document.createElement('tr');
        tr.setAttribute('data-id',     inc.id);
        tr.setAttribute('data-sev',    inc.severity);
        tr.setAttribute('data-score',  inc.score);
        tr.setAttribute('data-search', (inc.entity + ' ' + inc.title).toLowerCase());
        tr.setAttribute('tabindex', '0');
        tr.setAttribute('role', 'button');

        /* Severity */
        var sWrap = document.createElement('div');  sWrap.className = 'sev-cell';
        var dot   = document.createElement('span'); dot.className   = 'sev-dot';
        dot.style.background = SEV_DOT[inc.severity] || '#7d8590';
        var sTxt  = document.createElement('span'); sTxt.className  = 'sev-text';
        sTxt.style.color   = sevColor(inc.severity);
        sTxt.textContent   = inc.severity.charAt(0) + inc.severity.slice(1).toLowerCase();
        sWrap.appendChild(dot); sWrap.appendChild(sTxt);
        var tdS = document.createElement('td'); tdS.appendChild(sWrap); tr.appendChild(tdS);

        /* ID + title */
        var tdT  = document.createElement('td');
        var idSp = document.createElement('span'); idSp.className = 'inc-id';
        idSp.textContent = inc.id + '\\u00a0';
        var tiSp = document.createElement('span'); tiSp.className = 'inc-title';
        tiSp.textContent = inc.title.replace(/\\s*\\([^)]+\\)\\s*$/, '');
        tdT.appendChild(idSp); tdT.appendChild(tiSp); tr.appendChild(tdT);

        /* Entity */
        var tdE = document.createElement('td');
        var cod = document.createElement('code'); cod.textContent = inc.entity;
        tdE.appendChild(cod); tr.appendChild(tdE);

        /* Score */
        var tdSc = document.createElement('td');
        var pill = document.createElement('span'); pill.className = 'score-pill';
        pill.style.color = scoreColor(inc.score); pill.textContent = inc.score;
        tdSc.appendChild(pill); tr.appendChild(tdSc);

        /* Time */
        var tdTm = document.createElement('td');
        tdTm.className = 'time-cell'; tdTm.textContent = inc.start;
        tr.appendChild(tdTm);

        /* Categories */
        var tdC = document.createElement('td');
        tdC.className = 'cats-cell';
        tdC.textContent = inc.categories.join(', ');
        tdC.title = inc.categories.join(', ');
        tr.appendChild(tdC);

        tr.addEventListener('click', function () { openPanel(inc.id); });
        tr.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPanel(inc.id); }
        });
        tbody.appendChild(tr);
    });
}

/* ── Filtering ── */
function applyFilters() {
    var q   = (document.getElementById('q-entity').value || '').toLowerCase().trim();
    var sev = document.getElementById('q-sev').value;
    var min = parseInt(document.getElementById('q-score').value || '0', 10) || 0;
    var rows    = document.querySelectorAll('#incident-tbody tr[data-id]');
    var visible = 0;

    rows.forEach(function (tr) {
        var show =
            (!q  || tr.getAttribute('data-search').includes(q))
         && (sev === 'ALL' || tr.getAttribute('data-sev') === sev)
         && (parseInt(tr.getAttribute('data-score'), 10) >= min);
        tr.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    var total = INCIDENTS.length;
    document.getElementById('filter-count').textContent =
        visible === total
            ? total + ' incident' + (total === 1 ? '' : 's')
            : visible + ' of ' + total + ' incidents';

    var old = document.getElementById('no-match-row');
    if (old) old.remove();
    if (visible === 0 && total > 0) {
        var nr = document.createElement('tr'); nr.id = 'no-match-row';
        var nd = document.createElement('td'); nd.colSpan = 6;
        nd.style.cssText = 'text-align:center;padding:40px;color:var(--muted);font-size:13px';
        nd.textContent = 'No incidents match the current filters.';
        nr.appendChild(nd);
        document.getElementById('incident-tbody').appendChild(nr);
    }
}

function resetFilters() {
    document.getElementById('q-entity').value = '';
    document.getElementById('q-sev').value    = 'ALL';
    document.getElementById('q-score').value  = '0';
    applyFilters();
}

/* ── Detail panel ── */
function openPanel(id) {
    var inc = INCIDENTS.find(function (i) { return i.id === id; });
    if (!inc) return;
    selectedId = id;

    document.querySelectorAll('#incident-tbody tr[data-id]').forEach(function (tr) {
        tr.classList.toggle('active', tr.getAttribute('data-id') === id);
    });

    setText('p-id', inc.id);
    var sevEl = document.getElementById('p-sev');
    sevEl.textContent = inc.severity.charAt(0) + inc.severity.slice(1).toLowerCase();
    sevEl.style.color = sevColor(inc.severity);

    var scoreEl = document.getElementById('p-score');
    scoreEl.textContent = inc.score;
    scoreEl.style.color = scoreColor(inc.score);

    setText('p-title',  inc.title.replace(/\\s*\\([^)]+\\)\\s*$/, ''));
    setText('p-entity', inc.entity);
    setText('p-time',   inc.start + ' \\u2192 ' + inc.end);

    /* Rule badges */
    var rulesEl = document.getElementById('p-rules'); rulesEl.innerHTML = '';
    inc.rule_ids.forEach(function (r) {
        var sp = document.createElement('span'); sp.className = 'badge-rule'; sp.textContent = r;
        rulesEl.appendChild(sp);
    });

    /* Category badges */
    var catsEl = document.getElementById('p-cats'); catsEl.innerHTML = '';
    inc.categories.forEach(function (c) {
        var sp = document.createElement('span'); sp.className = 'badge-cat'; sp.textContent = c;
        catsEl.appendChild(sp);
    });

    /* Context policy status */
    var ctxBadge = document.getElementById('p-context-badge');
    var ctxSummary = document.getElementById('p-context-summary');
    if (ctxBadge && ctxSummary) {
        ctxBadge.innerHTML = '';
        ctxSummary.textContent = inc.context_summary || 'Standard baseline evaluation (no policy override).';
        var status = inc.context_status || 'NONE';
        var sp = document.createElement('span');
        if (status.indexOf('APPROVED') !== -1) {
            sp.className = 'badge-context-approved';
        } else if (status.indexOf('VPN') !== -1) {
            sp.className = 'badge-context-vpn';
        } else if (status.indexOf('MISMATCH') !== -1) {
            sp.className = 'badge-context-mismatch';
        } else {
            sp.className = 'badge-rule';
        }
        sp.textContent = status;
        ctxBadge.appendChild(sp);
    }

    setText('p-action',      inc.recommended_action);
    setText('p-explanation', inc.risk_explanation);

    /* Evidence rows */
    var evBody = document.getElementById('p-ev-body'); evBody.innerHTML = '';
    inc.evidence.forEach(function (ev) {
        var tr = document.createElement('tr');
        [ev.source, ev.timestamp, ev.username,
         ev.source_ip, ev.dest, ev.event_type, ev.result, ev.logon_type]
        .forEach(function (v, i) {
            var td = document.createElement('td'); td.textContent = v || '';
            if (i === 6) {
                td.className = v === 'SUCCESS' ? 'result-success'
                             : v === 'FAILURE' ? 'result-fail' : '';
            }
            tr.appendChild(td);
        });
        evBody.appendChild(tr);
    });

    document.getElementById('detail-panel').style.display = 'block';
    document.getElementById('table-area').classList.add('panel-open');
}

function closePanel() {
    document.getElementById('detail-panel').style.display = 'none';
    document.getElementById('table-area').classList.remove('panel-open');
    document.querySelectorAll('#incident-tbody tr[data-id]').forEach(function (tr) {
        tr.classList.remove('active');
    });
    selectedId = null;
}

/* Safe text setter — never innerHTML with user data */
function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = (val !== undefined && val !== null) ? String(val) : '';
}
</script>
</body>
</html>
"""


def parse_multipart_form_data(
    headers: Any,
    rfile: Any,
) -> Tuple[Dict[str, Tuple[Optional[str], bytes]], Optional[str]]:
    """
    Parses multipart/form-data using Python 3.13 standard library (email module).
    Replaces deprecated 'cgi' module.
    Returns (fields_dict, error_string).
    fields_dict maps form field name -> (filename_or_none, content_bytes).
    """
    content_type = headers.get("Content-Type", "")
    if not content_type or "multipart/form-data" not in content_type:
        return {}, "Invalid Content-Type: expected multipart/form-data"

    content_length_str = headers.get("Content-Length")
    if not content_length_str:
        return {}, "Missing Content-Length header"

    try:
        content_length = int(content_length_str)
        if content_length < 0:
            return {}, "Invalid negative Content-Length header"
    except ValueError:
        return {}, f"Invalid Content-Length header: '{content_length_str}'"

    # Safety limit: 50MB
    if content_length > 50 * 1024 * 1024:
        return {}, "Payload too large (exceeds 50MB maximum)"

    try:
        body_bytes = rfile.read(content_length)
    except Exception as e:
        return {}, f"Error reading upload payload: {e}"

    if len(body_bytes) < content_length:
        return {}, "Incomplete payload: client closed connection prematurely"

    try:
        # Construct email message with MIME multipart headers
        mime_data = b"Content-Type: " + content_type.encode("latin1", errors="replace") + b"\r\n\r\n" + body_bytes
        msg = email.message_from_bytes(mime_data, policy=email_default)

        if not msg.is_multipart():
            return {}, "Failed to parse multipart body: boundary delimiter not found"

        fields: Dict[str, Tuple[Optional[str], bytes]] = {}
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            cd = part.get("content-disposition", "")
            if not name and cd:
                m = re.search(r'name=["\']?([^"\';\r\n]+)', cd)
                if m:
                    name = m.group(1).strip()

            if not name:
                continue

            filename = part.get_filename()
            if not filename and cd:
                m = re.search(r'filename=["\']?([^"\';\r\n]+)', cd)
                if m:
                    filename = m.group(1).strip()

            data = part.get_payload(decode=True)
            if data is None:
                data = b""

            fields[name] = (filename, data)

        return fields, None
    except Exception as e:
        return {}, f"Failed to parse multipart payload: {e}"


class InvestigatorRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the local investigator interface."""

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/", "/index.html"):
            self._render_dashboard()
        elif path == "/analyze-synthetic":
            self._analyze_synthetic()
        elif path == "/export/incidents.csv":
            self._export_csv("incidents")
        elif path == "/export/evidence.csv":
            self._export_csv("evidence")
        elif path == "/export/users.csv":
            self._export_csv("users")
        elif path == "/export/report.html":
            self._export_html()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == "/analyze":
            self._handle_file_upload()
        else:
            self.send_response(404)
            self.end_headers()

    def _render_dashboard(self) -> None:
        incidents     = GLOBAL_STATE.incidents
        user_profiles = GLOBAL_STATE.user_profiles

        # Build a JSON-serialisable list — all values go through json.dumps so
        # no raw log content ever reaches the HTML as unescaped text.
        incidents_data = []
        for inc in incidents:
            incidents_data.append({
                "id":                 inc.incident_id,
                "title":              inc.title,
                "severity":           inc.severity,
                "score":              inc.risk_score,
                "entity":             inc.primary_entity,
                "start":              inc.start_time_utc.strftime("%Y-%m-%d %H:%M"),
                "end":                inc.end_time_utc.strftime("%H:%M") + " UTC",
                "categories":         inc.categories,
                "rule_ids":           inc.rule_ids,
                "context_status":     getattr(inc, "context_status", "NONE"),
                "context_summary":    getattr(inc, "context_summary", ""),
                "recommended_action": inc.recommended_action,
                "risk_explanation":   inc.risk_explanation,
                "evidence": [
                    {
                        "source":     Path(ev.source_file).name + ":" + str(ev.row_number),
                        "timestamp":  ev.timestamp_utc,
                        "username":   ev.username,
                        "source_ip":  ev.source_ip,
                        "dest":       ev.destination_host,
                        "event_type": ev.event_type,
                        "result":     ev.result,
                        "logon_type": ev.logon_type,
                    }
                    for ev in inc.evidence_records
                ],
            })

        metrics = {
            "total":         len(incidents),
            "critical_high": sum(1 for inc in incidents if inc.severity in ("CRITICAL", "HIGH")),
            "max_score":     max((inc.risk_score for inc in incidents), default=0),
            "profiled_users": len(user_profiles),
        }

        html_out = (
            SERVER_HTML
            .replace("__INCIDENT_JSON__", json.dumps(incidents_data))
            .replace("__METRICS_JSON__",  json.dumps(metrics))
            .replace("__HAS_RESULTS__",   "true" if incidents else "false")
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_out.encode("utf-8"))

    def _analyze_synthetic(self) -> None:
        train_path = Path("data/synthetic/synthetic_training_auth.csv")
        eval_path = Path("data/synthetic/synthetic_evaluation_auth.csv")

        if not train_path.exists() or not eval_path.exists():
            from mission72.synthetic import generate_synthetic_datasets
            generate_synthetic_datasets("data/synthetic")

        with train_path.open("r", encoding="utf-8-sig") as f:
            train_events, _ = parse_csv_stream(f, source_file=str(train_path))

        with eval_path.open("r", encoding="utf-8-sig") as f:
            eval_events, q_rep = parse_csv_stream(f, source_file=str(eval_path))

        repo = build_user_baselines(train_events, min_training_events=5)
        context_reg = get_active_context_registry()
        engine = DetectionEngine(baseline_repo=repo, context_registry=context_reg)
        alerts = engine.run_all(eval_events)
        incidents = group_alerts_into_incidents(alerts, context_registry=context_reg)
        user_profiles = compute_user_risk_profiles(incidents, repo, eval_events, context_registry=context_reg)

        GLOBAL_STATE.incidents = incidents
        GLOBAL_STATE.user_profiles = user_profiles
        GLOBAL_STATE.quality_report = q_rep
        GLOBAL_STATE.training_events_count = len(train_events)
        GLOBAL_STATE.evaluation_events_count = len(eval_events)

        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def _handle_file_upload(self) -> None:
        fields, err = parse_multipart_form_data(self.headers, self.rfile)
        if err:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(err.encode("utf-8"))
            return

        eval_item = fields.get("eval_file")
        if not eval_item or not eval_item[1] or not eval_item[1].strip():
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Evaluation CSV file is required and cannot be empty.")
            return

        train_events = []
        train_item = fields.get("train_file")
        if train_item and train_item[1] and train_item[1].strip():
            train_filename = train_item[0] or "uploaded_train.csv"
            train_content = train_item[1].decode("utf-8-sig", errors="replace")
            train_events, _ = parse_csv_stream(io.StringIO(train_content), source_file=train_filename)

        eval_filename = eval_item[0] or "uploaded_eval.csv"
        eval_content = eval_item[1].decode("utf-8-sig", errors="replace")
        eval_events, q_rep = parse_csv_stream(io.StringIO(eval_content), source_file=eval_filename)

        repo = build_user_baselines(train_events, min_training_events=5)
        context_reg = get_active_context_registry()
        engine = DetectionEngine(baseline_repo=repo, context_registry=context_reg)
        alerts = engine.run_all(eval_events)
        incidents = group_alerts_into_incidents(alerts, context_registry=context_reg)
        user_profiles = compute_user_risk_profiles(incidents, repo, eval_events, context_registry=context_reg)

        GLOBAL_STATE.incidents = incidents
        GLOBAL_STATE.user_profiles = user_profiles
        GLOBAL_STATE.quality_report = q_rep
        GLOBAL_STATE.training_events_count = len(train_events)
        GLOBAL_STATE.evaluation_events_count = len(eval_events)

        self.send_response(302)
        self.send_header("Location", "/")
        self.end_headers()

    def _export_csv(self, kind: str) -> None:
        buf = io.StringIO()
        if kind == "incidents":
            export_incidents_to_csv(GLOBAL_STATE.incidents, Path("scratch_incidents.csv"))
            data = Path("scratch_incidents.csv").read_bytes()
            Path("scratch_incidents.csv").unlink(missing_ok=True)
            filename = "mission72_incidents.csv"
        elif kind == "evidence":
            export_evidence_to_csv(GLOBAL_STATE.incidents, Path("scratch_evidence.csv"))
            data = Path("scratch_evidence.csv").read_bytes()
            Path("scratch_evidence.csv").unlink(missing_ok=True)
            filename = "mission72_evidence.csv"
        else:
            export_user_risk_to_csv(GLOBAL_STATE.user_profiles, Path("scratch_users.csv"))
            data = Path("scratch_users.csv").read_bytes()
            Path("scratch_users.csv").unlink(missing_ok=True)
            filename = "mission72_user_risk_profiles.csv"

        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def _export_html(self) -> None:
        content = generate_html_report(
            GLOBAL_STATE.incidents,
            GLOBAL_STATE.user_profiles,
            GLOBAL_STATE.quality_report,
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="mission72_investigation_report.html"')
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))


def start_server(port: int = 8072) -> None:
    """Starts the local investigator web dashboard."""
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, InvestigatorRequestHandler)
    print(f"Mission 72 Investigator Console started at http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    start_server(8072)
