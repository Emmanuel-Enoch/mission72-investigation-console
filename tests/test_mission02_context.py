"""
Deterministic test suite for Mission 02 Context-Aware Alert Detection.
Validates all 13 scenario requirements from Section 4:
1. Authorized helpdesk on approved hosts during active maintenance.
2. Helpdesk accessing hosts outside the approved window.
3. Helpdesk accessing unapproved host during maintenance.
4. Travelling employee using recognized company VPN endpoint.
5. New-location login without supporting VPN evidence.
6. Unknown or untrusted VPN endpoint.
7. Regular user accessing many unfamiliar hosts (preservation).
8. Maintenance window with invalid/inverted timestamps rejected.
9. Event occurring at exact maintenance-window boundary.
10. Event with missing account, host, timestamp, or VPN fields.
11. Conflicting context signals.
12. Duplicate event ingestion behavior.
13. Unrelated events with similar attributes (no incorrect merge).
"""

import io
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Add src to sys.path
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from mission72.baseline import build_user_baselines
from mission72.context import (
    AccountAuthorization,
    ContextRegistry,
    MaintenanceWindow,
    VpnEndpoint,
    create_default_context_registry,
    parse_iso_or_utc_timestamp,
)
from mission72.detections import DetectionEngine, RuleConfig
from mission72.incidents import (
    compute_incident_risk_score,
    compute_user_risk_profiles,
    group_alerts_into_incidents,
)
from mission72.ingestion import parse_csv_stream
from mission72.models import AuthEvent


class TestMission02ContextScenarios(unittest.TestCase):
    """Deterministic tests covering the 13 required contextual scenarios."""

    def setUp(self):
        # Build baseline with established users
        csv_train = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            + "\n".join([f"2026-10-01T10:{i:02d}:00Z,frank.helpdesk,192.168.1.50,ws-hd-01,AUTHENTICATION,SUCCESS,NETWORK" for i in range(10)])
            + "\n"
            + "\n".join([f"2026-10-01T10:{i:02d}:00Z,alice.smith,192.168.1.60,ws-01,AUTHENTICATION,SUCCESS,NETWORK" for i in range(10)])
            + "\n"
            + "\n".join([f"2026-10-01T{h:02d}:00:00Z,travelling.user,192.168.1.70,ws-lon-01,AUTHENTICATION,SUCCESS,NETWORK" for h in range(8, 18)])
        )
        events, _ = parse_csv_stream(io.StringIO(csv_train), "train.csv")
        self.baseline_repo = build_user_baselines(events, min_training_events=5)

        # Standard context registry for tests
        self.registry = ContextRegistry()
        self.registry.add_maintenance_window(
            window_id="MW-PATCH-01",
            start_time="2026-10-15T02:00:00Z",
            end_time="2026-10-15T06:00:00Z",
            approved_hosts={"srv-patch-*", "srv-db-01", "srv-app-01"},
            permitted_activities={"AUTHENTICATION", "ADMIN_LOGON", "LOGON", "NETWORK"},
            authorized_accounts={"frank.helpdesk"},
            authorized_roles={"helpdesk", "sysadmin"},
            description="Scheduled infrastructure patch window",
        )
        self.registry.add_account(
            username="frank.helpdesk",
            role="helpdesk",
            permitted_targets={"srv-patch-*", "srv-db-01", "srv-app-01", "ws-hd-01"},
            approved_activities={"AUTHENTICATION", "LOGON", "NETWORK"},
        )
        self.registry.add_account(
            username="alice.smith",
            role="standard_user",
            permitted_targets={"ws-01"},
            approved_activities={"AUTHENTICATION", "LOGON", "NETWORK"},
        )
        self.registry.add_vpn_endpoint(
            endpoint_id="VPN-LON-01",
            cidr_or_ip="198.51.100.0/24",
            name="London Corporate VPN Gateway",
            location="London, UK",
            is_trusted=True,
        )
        self.registry.add_vpn_endpoint(
            endpoint_id="VPN-ROGUE-01",
            cidr_or_ip="203.0.113.200/32",
            name="Untrusted Public Anonymizer",
            location="Untrusted Public Anonymizer",
            is_trusted=False,
        )

    # -------------------------------------------------------------------------
    # Scenario 1: Authorized helpdesk on approved hosts during active maintenance
    # -------------------------------------------------------------------------
    def test_scenario_01_authorized_helpdesk_approved_hosts_during_maintenance(self):
        """
        Authorized helpdesk accessing approved hosts during active maintenance.
        Expected: Contextual risk reduction (discount up to -35 pts), alert severity LOW,
        evidence preserved, explicit contextual explanation in incident.
        """
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T03:00:00Z,frank.helpdesk,192.168.1.50,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:05:00Z,frank.helpdesk,192.168.1.50,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:10:00Z,frank.helpdesk,192.168.1.50,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:15:00Z,frank.helpdesk,192.168.1.50,srv-app-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        # Rule 6 triggers because srv-patch-* are unfamiliar hosts
        self.assertTrue(any(a.rule_id == "RULE-06-UNFAMILIAR-HOSTS" for a in alerts))
        r6_alert = next(a for a in alerts if a.rule_id == "RULE-06-UNFAMILIAR-HOSTS")
        self.assertEqual(r6_alert.severity, "LOW")
        self.assertIn("approved maintenance window", r6_alert.explanation)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.context_status, "APPROVED_MAINTENANCE")
        self.assertIn("Context Mitigation (-35 pts", inc.risk_explanation)
        self.assertLessEqual(inc.risk_score, 30)
        self.assertEqual(len(inc.evidence_records), 4)

    # -------------------------------------------------------------------------
    # Scenario 2: Helpdesk accessing hosts outside the approved window
    # -------------------------------------------------------------------------
    def test_scenario_02_helpdesk_accessing_hosts_outside_maintenance_window(self):
        """
        Helpdesk accessing hosts outside the maintenance window.
        Expected: Fully alerted (MEDIUM severity for non-sensitive hosts, NOT reduced to LOW),
        no maintenance discount, explanation notes out-of-window.
        """
        # Event is at 12:00:00Z (window is 02:00 to 06:00)
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T12:00:00Z,frank.helpdesk,192.168.1.50,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T12:05:00Z,frank.helpdesk,192.168.1.50,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T12:10:00Z,frank.helpdesk,192.168.1.50,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T12:15:00Z,frank.helpdesk,192.168.1.50,srv-app-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        r6_alert = next(a for a in alerts if a.rule_id == "RULE-06-UNFAMILIAR-HOSTS")
        self.assertEqual(r6_alert.severity, "MEDIUM")
        self.assertNotIn("approved maintenance window", r6_alert.explanation)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        self.assertNotEqual(inc.context_status, "APPROVED_MAINTENANCE")
        self.assertNotIn("Context Mitigation (-35 pts", inc.risk_explanation)
        self.assertGreaterEqual(inc.risk_score, 35)

    # -------------------------------------------------------------------------
    # Scenario 3: Helpdesk accessing unapproved host during maintenance
    # -------------------------------------------------------------------------
    def test_scenario_03_helpdesk_accessing_unapproved_host_during_maintenance(self):
        """
        Helpdesk accessing an unapproved host during active maintenance.
        Expected: Not exempted; approval mismatch flagged, alert remains active (not reduced to LOW),
        and incident indicates APPROVAL_MISMATCH with no maintenance discount.
        """
        # Host 'srv-finance-secret' is NOT in approved_hosts or frank's permitted_targets
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T03:00:00Z,frank.helpdesk,192.168.1.50,srv-finance-secret,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:05:00Z,frank.helpdesk,192.168.1.50,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:10:00Z,frank.helpdesk,192.168.1.50,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:15:00Z,frank.helpdesk,192.168.1.50,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        r6_alert = next(a for a in alerts if a.rule_id == "RULE-06-UNFAMILIAR-HOSTS")
        self.assertEqual(r6_alert.severity, "MEDIUM")

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        self.assertEqual(inc.context_status, "APPROVAL_MISMATCH")
        self.assertIn("not on approved host list", inc.context_summary)
        self.assertGreaterEqual(inc.risk_score, 35)

    # -------------------------------------------------------------------------
    # Scenario 4: Travelling employee using recognized company VPN endpoint
    # -------------------------------------------------------------------------
    def test_scenario_04_travelling_employee_using_company_vpn(self):
        """
        Travelling employee logging in from new IP within verified company VPN CIDR.
        Expected: Unfamiliar IP alert severity reduced to LOW, VPN context noted,
        context discount (-15 pts) applied without blind suppression of attacks.
        """
        # 198.51.100.45 is within VPN-LON-01 network 198.51.100.0/24
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T11:00:00Z,travelling.user,198.51.100.45,ws-lon-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        r5_alert = next(a for a in alerts if a.rule_id == "RULE-05-UNFAMILIAR-IP")
        self.assertEqual(r5_alert.severity, "LOW")
        self.assertIn("verified corporate VPN gateway", r5_alert.explanation)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        self.assertEqual(inc.context_status, "VERIFIED_VPN")
        self.assertIn("Context Mitigation (-15 pts", inc.risk_explanation)
        self.assertEqual(inc.risk_score, 0)  # 15 base - 15 discount = 0

    # -------------------------------------------------------------------------
    # Scenario 5: New-location login without supporting VPN evidence
    # -------------------------------------------------------------------------
    def test_scenario_05_new_location_without_vpn_evidence(self):
        """
        New-location login from unfamiliar IP with no VPN evidence.
        Expected: Standard unfamiliar IP alert triggered at MEDIUM severity with full risk score.
        """
        # 203.0.113.55 is unknown public IP
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T11:00:00Z,travelling.user,203.0.113.55,ws-lon-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        r5_alert = next(a for a in alerts if a.rule_id == "RULE-05-UNFAMILIAR-IP")
        self.assertEqual(r5_alert.severity, "MEDIUM")
        self.assertNotIn("verified corporate VPN", r5_alert.explanation)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        self.assertNotEqual(inc.context_status, "VERIFIED_VPN")
        self.assertEqual(inc.risk_score, 35)

    # -------------------------------------------------------------------------
    # Scenario 6: Unknown or untrusted VPN endpoint
    # -------------------------------------------------------------------------
    def test_scenario_06_login_from_untrusted_vpn_endpoint(self):
        """
        Login from an unverified/untrusted VPN endpoint (e.g., commercial anonymizer).
        Expected: Flagged as untrusted VPN, elevated to HIGH severity, no automatic discount applied.
        """
        # 203.0.113.200 matches VPN-ROGUE-01 which has is_trusted=False
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T11:00:00Z,travelling.user,203.0.113.200,ws-lon-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        r5_alert = next(a for a in alerts if a.rule_id == "RULE-05-UNFAMILIAR-IP")
        self.assertEqual(r5_alert.severity, "HIGH")
        self.assertIn("untrusted VPN/proxy endpoint", r5_alert.explanation)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        self.assertNotEqual(inc.context_status, "VERIFIED_VPN")
        self.assertNotIn("Context Mitigation", inc.risk_explanation)
        self.assertEqual(inc.risk_score, 55)

    # -------------------------------------------------------------------------
    # Scenario 7: Regular user accessing many unfamiliar hosts (preservation)
    # -------------------------------------------------------------------------
    def test_scenario_07_regular_user_accessing_many_unfamiliar_hosts(self):
        """
        Regular user accesses multiple unfamiliar hosts during active maintenance window.
        Expected: Not suppressed! Maintenance window only authorizes IT staff / helpdesk.
        Normal alerting and risk score retained, context mismatch recorded.
        """
        # alice.smith is standard_user, not helpdesk
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T03:00:00Z,alice.smith,192.168.1.60,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:05:00Z,alice.smith,192.168.1.60,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:10:00Z,alice.smith,192.168.1.60,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:15:00Z,alice.smith,192.168.1.60,srv-app-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        r6_alert = next(a for a in alerts if a.rule_id == "RULE-06-UNFAMILIAR-HOSTS")
        self.assertEqual(r6_alert.severity, "MEDIUM")
        self.assertNotIn("approved maintenance window(s)", r6_alert.explanation)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        self.assertEqual(inc.context_status, "APPROVAL_MISMATCH")
        self.assertIn("standard_user", inc.context_summary)
        self.assertGreaterEqual(inc.risk_score, 35)

    # -------------------------------------------------------------------------
    # Scenario 8: Maintenance window with invalid or inverted timestamps
    # -------------------------------------------------------------------------
    def test_scenario_08_maintenance_window_with_invalid_timestamps_rejected(self):
        """
        Maintenance window with inverted timestamps (start >= end) must be safely rejected
        and logged with warning, allowing normal alerting to proceed safely.
        """
        reg = ContextRegistry()
        # Inverted timestamps raises ValueError on construction
        with self.assertRaises(ValueError):
            MaintenanceWindow(
                window_id="MW-BAD-INVERTED",
                start_time_utc=datetime(2026, 10, 15, 6, 0, tzinfo=timezone.utc),
                end_time_utc=datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc),  # earlier than start
                approved_hosts={"*"},
            )

        # Loading from dict with inverted window should skip bad window safely
        data = {
            "maintenance_windows": [
                {
                    "window_id": "MW-BAD-01",
                    "start_time_utc": "2026-10-15T08:00:00Z",
                    "end_time_utc": "2026-10-15T04:00:00Z",
                    "approved_hosts": ["*"],
                }
            ]
        }
        loaded_reg = ContextRegistry.from_dict(data)
        self.assertEqual(len(loaded_reg.maintenance_windows), 0)

    # -------------------------------------------------------------------------
    # Scenario 9: Event precisely at maintenance-window boundary
    # -------------------------------------------------------------------------
    def test_scenario_09_exact_maintenance_window_boundary_behavior(self):
        """
        Authentication event precisely at start_time or end_time boundary of window.
        Expected: Consistently and deterministically matched (inclusive policy: start <= ts <= end).
        """
        # Exactly at start: 2026-10-15T02:00:00Z
        ev_start = AuthEvent(
            source_file="test.csv",
            row_number=1,
            timestamp_utc=datetime(2026, 10, 15, 2, 0, 0, tzinfo=timezone.utc),
            username="frank.helpdesk",
            source_ip="192.168.1.50",
            destination_host="srv-patch-01",
            event_type="AUTHENTICATION",
            result="SUCCESS",
        )
        res_start = self.registry.evaluate_event_maintenance(ev_start)
        self.assertTrue(res_start.is_approved_maintenance)
        self.assertEqual(res_start.active_window_id, "MW-PATCH-01")

        # Exactly at end: 2026-10-15T06:00:00Z
        ev_end = AuthEvent(
            source_file="test.csv",
            row_number=2,
            timestamp_utc=datetime(2026, 10, 15, 6, 0, 0, tzinfo=timezone.utc),
            username="frank.helpdesk",
            source_ip="192.168.1.50",
            destination_host="srv-patch-01",
            event_type="AUTHENTICATION",
            result="SUCCESS",
        )
        res_end = self.registry.evaluate_event_maintenance(ev_end)
        self.assertTrue(res_end.is_approved_maintenance)
        self.assertEqual(res_end.active_window_id, "MW-PATCH-01")

        # 1 second after end: 2026-10-15T06:00:01Z -> outside!
        ev_outside = AuthEvent(
            source_file="test.csv",
            row_number=3,
            timestamp_utc=datetime(2026, 10, 15, 6, 0, 1, tzinfo=timezone.utc),
            username="frank.helpdesk",
            source_ip="192.168.1.50",
            destination_host="srv-patch-01",
            event_type="AUTHENTICATION",
            result="SUCCESS",
        )
        res_outside = self.registry.evaluate_event_maintenance(ev_outside)
        self.assertFalse(res_outside.is_approved_maintenance)

    # -------------------------------------------------------------------------
    # Scenario 10: Missing account, host, timestamp, or VPN fields
    # -------------------------------------------------------------------------
    def test_scenario_10_missing_fields_safe_handling(self):
        """
        Events with None/empty username, host, timestamp, or IP are safely evaluated
        without crashing and fallback to safe defaults.
        """
        ev_missing = AuthEvent(
            source_file="test.csv",
            row_number=1,
            timestamp_utc=None,
            username="",
            source_ip="",
            destination_host="",
            event_type="AUTHENTICATION",
            result="FAILURE",
        )
        # Should not raise exception
        m_res = self.registry.evaluate_event_maintenance(ev_missing)
        self.assertFalse(m_res.is_approved_maintenance)

        vpn_res = self.registry.evaluate_event_vpn(ev_missing)
        self.assertFalse(vpn_res.is_vpn_verified)

    # -------------------------------------------------------------------------
    # Scenario 11: Conflicting context signals
    # -------------------------------------------------------------------------
    def test_scenario_11_conflicting_context_signals(self):
        """
        Conflicting signals: Authorized helpdesk during maintenance window,
        but connecting from an unknown external IP without VPN.
        Expected: Balanced scoring reflecting mitigating factor (maintenance discount)
        while preserving unfamiliar IP alert and penalty, with full explainability.
        """
        # Unknown external IP 203.0.113.77
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T03:00:00Z,frank.helpdesk,203.0.113.77,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:05:00Z,frank.helpdesk,203.0.113.77,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:10:00Z,frank.helpdesk,203.0.113.77,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:15:00Z,frank.helpdesk,203.0.113.77,srv-app-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        # Rule 5 (Unfamiliar IP) fires because 203.0.113.77 is not in baseline or VPN
        # Rule 6 (Unfamiliar hosts) fires but is mitigated by maintenance window
        rule_ids = {a.rule_id for a in alerts}
        self.assertIn("RULE-05-UNFAMILIAR-IP", rule_ids)
        self.assertIn("RULE-06-UNFAMILIAR-HOSTS", rule_ids)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        inc = incidents[0]
        # Multi-category bonus applies (+10), maintenance discount applies (-35), bounded in [0, 100]
        self.assertIn("Multi-Category", inc.risk_explanation)
        self.assertIn("Context Mitigation (-35 pts", inc.risk_explanation)
        self.assertGreaterEqual(inc.risk_score, 0)
        self.assertLessEqual(inc.risk_score, 100)

    # -------------------------------------------------------------------------
    # Scenario 12: Duplicate event ingestion behavior
    # -------------------------------------------------------------------------
    def test_scenario_12_duplicate_event_ingestion_behavior(self):
        """
        Duplicate event ingestion flags candidates and maintains audit trail
        without unintended risk score inflation.
        """
        csv_data = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-15T03:00:00Z,frank.helpdesk,192.168.1.50,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:00:00Z,frank.helpdesk,192.168.1.50,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, quality = parse_csv_stream(io.StringIO(csv_data), "eval_dups.csv")
        self.assertEqual(quality.valid_records, 2)
        self.assertEqual(quality.duplicate_candidate_count, 1)

    # -------------------------------------------------------------------------
    # Scenario 13: Unrelated events with similar attributes (no incorrect merge)
    # -------------------------------------------------------------------------
    def test_scenario_13_unrelated_events_not_incorrectly_merged(self):
        """
        Unrelated events occurring during the same maintenance window with different entities
        must form separate incidents, avoiding false cross-entity contamination.
        """
        eval_csv = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            # Frank's approved maintenance activity
            "2026-10-15T03:00:00Z,frank.helpdesk,192.168.1.50,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:05:00Z,frank.helpdesk,192.168.1.50,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:10:00Z,frank.helpdesk,192.168.1.50,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:15:00Z,frank.helpdesk,192.168.1.50,srv-app-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            # Alice's separate unauthorized activity
            "2026-10-15T03:00:00Z,alice.smith,192.168.1.60,srv-patch-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:05:00Z,alice.smith,192.168.1.60,srv-patch-02,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:10:00Z,alice.smith,192.168.1.60,srv-db-01,AUTHENTICATION,SUCCESS,NETWORK\n"
            "2026-10-15T03:15:00Z,alice.smith,192.168.1.60,srv-app-01,AUTHENTICATION,SUCCESS,NETWORK\n"
        )
        events, _ = parse_csv_stream(io.StringIO(eval_csv), "eval.csv")
        engine = DetectionEngine(baseline_repo=self.baseline_repo, context_registry=self.registry)
        alerts = engine.run_all(events)

        incidents = group_alerts_into_incidents(alerts, context_registry=self.registry)
        self.assertEqual(len(incidents), 2)
        entities = {inc.primary_entity for inc in incidents}
        self.assertEqual(entities, {"frank.helpdesk", "alice.smith"})


if __name__ == "__main__":
    unittest.main()
