"""
Automated test suite for Mission 72 Stage 1:
- Canonical CSV ingestion & provenance preservation
- Timestamp UTC normalization & explicit policy enforcement
- Timestamp ambiguity detection and configured format support
- Missing schema columns vs missing cell values
- Header-only CSV with invalid schema detection
- UTF-8 BOM encoding support
- Malformed CSV syntax and NUL byte handling
- Baseline safety: successful logins establish normal profiles, failed attempts are not learned
- Baseline strict temporal cutoff inclusion (<=) and exclusion (>)
- Baseline coverage tracking (UNAVAILABLE vs INSUFFICIENT_DATA vs ESTABLISHED)
- Deterministic synthetic data generation with active seed and chronological sorting
- Explicit verification of all six required Mission 72 detection categories
"""

import io
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add src to sys.path for local discovery
src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from mission72.baseline import build_user_baselines
from mission72.ingestion import (
    parse_csv_file,
    parse_csv_stream,
    parse_timestamp_to_utc,
    parse_timestamp_with_diagnosis,
)
from mission72.models import BaselineStatus
from mission72.synthetic import generate_synthetic_datasets, generate_synthetic_records


class TestStage1Ingestion(unittest.TestCase):

    def test_valid_csv_parsing(self):
        csv_data = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-01T09:00:00Z,alice,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\n"
            "2026-10-01T09:05:00Z,bob,192.168.1.101,ws-02,Logon,SUCCESS,Network\n"
        )
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="test_sample.csv")

        self.assertEqual(len(events), 2)
        self.assertEqual(report.total_records, 2)
        self.assertEqual(report.valid_records, 2)
        self.assertEqual(report.malformed_records, 0)
        self.assertEqual(len(report.missing_columns), 0)

        # Check first event
        ev1 = events[0]
        self.assertEqual(ev1.source_file, "test_sample.csv")
        self.assertEqual(ev1.row_number, 2)
        self.assertEqual(ev1.username, "alice")
        self.assertEqual(ev1.source_ip, "192.168.1.100")
        self.assertEqual(ev1.destination_host, "ws-01")
        self.assertEqual(ev1.result, "SUCCESS")
        self.assertTrue(ev1.is_valid)
        self.assertEqual(ev1.timestamp_utc, datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc))

        # Check second event
        ev2 = events[1]
        self.assertEqual(ev2.row_number, 3)
        self.assertEqual(ev2.username, "bob")

    def test_timestamp_timezone_policy(self):
        # 1. Aware ISO 8601 with positive offset (+02:00) -> 12:00 +02:00 is 10:00 UTC
        ts1 = parse_timestamp_to_utc("2026-10-01T12:00:00+02:00")
        self.assertIsNotNone(ts1)
        self.assertEqual(ts1.hour, 10)
        self.assertEqual(ts1.tzinfo, timezone.utc)

        # 2. Aware ISO 8601 with Z suffix
        ts2 = parse_timestamp_to_utc("2026-10-01T15:30:00Z")
        self.assertIsNotNone(ts2)
        self.assertEqual(ts2.hour, 15)
        self.assertEqual(ts2.minute, 30)
        self.assertEqual(ts2.tzinfo, timezone.utc)

        # 3. Naive timestamp policy: assumed UTC by default
        ts3 = parse_timestamp_to_utc("2026-10-01 08:45:00")
        self.assertIsNotNone(ts3)
        self.assertEqual(ts3.hour, 8)
        self.assertEqual(ts3.minute, 45)
        self.assertEqual(ts3.tzinfo, timezone.utc)

    def test_ambiguous_slash_separated_timestamps(self):
        # Ambiguous: 04/05/2026 could be April 5th or May 4th
        ts_ambig, err = parse_timestamp_with_diagnosis("04/05/2026 12:00:00")
        self.assertIsNone(ts_ambig)
        self.assertIn("Ambiguous date format", err)

        # Configured format resolves ambiguity
        ts_cfg, err_cfg = parse_timestamp_with_diagnosis(
            "04/05/2026 12:00:00",
            configured_format="%m/%d/%Y %H:%M:%S",
        )
        self.assertIsNotNone(ts_cfg)
        self.assertIsNone(err_cfg)
        self.assertEqual(ts_cfg.month, 4)
        self.assertEqual(ts_cfg.day, 5)

        # Unambiguous: 25/10/2026 (day > 12 must be DD/MM/YYYY)
        ts_dd, err_dd = parse_timestamp_with_diagnosis("25/10/2026 12:00:00")
        self.assertIsNotNone(ts_dd)
        self.assertEqual(ts_dd.day, 25)
        self.assertEqual(ts_dd.month, 10)

        # Unambiguous: 10/25/2026 (second part > 12 must be MM/DD/YYYY)
        ts_mm, err_mm = parse_timestamp_with_diagnosis("10/25/2026 12:00:00")
        self.assertIsNotNone(ts_mm)
        self.assertEqual(ts_mm.month, 10)
        self.assertEqual(ts_mm.day, 25)

    def test_missing_fields_never_silently_discarded(self):
        # Row 2 missing username; Row 3 missing destination_host
        csv_data = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-01T09:00:00Z,,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\n"
            "2026-10-01T09:05:00Z,bob,192.168.1.101,,Logon,SUCCESS,Network\n"
        )
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="missing_fields.csv")

        # Must not be discarded
        self.assertEqual(len(events), 2)
        self.assertEqual(report.total_records, 2)
        self.assertEqual(report.valid_records, 0)
        self.assertEqual(report.malformed_records, 2)
        self.assertEqual(report.missing_field_count, 2)
        self.assertEqual(len(report.missing_columns), 0)

        self.assertFalse(events[0].is_valid)
        self.assertIn("Missing required field value: 'username'", events[0].validation_errors)

        self.assertFalse(events[1].is_valid)
        self.assertIn("Missing required field value: 'destination_host'", events[1].validation_errors)

    def test_missing_headers_versus_missing_cell_values(self):
        # Missing destination_host in header
        csv_data = (
            "timestamp,username,source_ip,event_type,result,logon_type\n"
            "2026-10-01T09:00:00Z,alice,192.168.1.100,Logon,SUCCESS,Interactive\n"
            "2026-10-01T09:05:00Z,bob,192.168.1.101,Logon,SUCCESS,Network\n"
        )
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="missing_col.csv")

        # Missing column is recorded at schema level, not double-counted in missing_field_count
        self.assertIn("destination_host", report.missing_columns)
        self.assertEqual(report.missing_field_count, 0)
        self.assertEqual(report.malformed_records, 2)
        self.assertTrue(report.summary()["has_schema_error"])

    def test_header_only_csv_with_invalid_schema(self):
        # Header only with 0 data rows and invalid schema
        csv_data = "col_a,col_b,col_c\n"
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="header_only.csv")

        self.assertEqual(len(events), 0)
        self.assertEqual(report.total_records, 0)
        self.assertEqual(len(report.missing_columns), 7)
        self.assertTrue(report.summary()["has_schema_error"])

    def test_utf8_bom_input(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            bom_content = (
                b"\xef\xbb\xbf"
                b"timestamp,username,source_ip,destination_host,event_type,result,logon_type\r\n"
                b"2026-10-01T09:00:00Z,alice,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\r\n"
            )
            f.write(bom_content)
            temp_path = f.name

        try:
            events, report = parse_csv_file(temp_path)
            self.assertEqual(len(events), 1)
            self.assertEqual(report.valid_records, 1)
            self.assertEqual(len(report.missing_columns), 0)
            self.assertEqual(events[0].username, "alice")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_malformed_csv_syntax_and_nul_bytes(self):
        # CSV with an illegal NUL byte in one of the values
        csv_data = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-01T09:00:00Z,ali\x00ce,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\n"
        )
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="nul_byte.csv")

        self.assertEqual(len(events), 1)
        self.assertEqual(report.malformed_records, 1)
        self.assertFalse(events[0].is_valid)
        self.assertTrue(any("NUL byte" in e for e in events[0].validation_errors))

    def test_invalid_timestamps(self):
        csv_data = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-99-99 99:99:99,alice,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\n"
        )
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="invalid_time.csv")

        self.assertEqual(len(events), 1)
        self.assertFalse(events[0].is_valid)
        self.assertIsNone(events[0].timestamp_utc)
        self.assertEqual(events[0].timestamp_raw, "2026-99-99 99:99:99")
        self.assertEqual(report.invalid_timestamp_count, 1)
        self.assertIn("Invalid timestamp format: '2026-99-99 99:99:99'", events[0].validation_errors)

    def test_duplicate_candidate_detection(self):
        # Two identical rows in sequence
        csv_data = (
            "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
            "2026-10-01T09:00:00Z,alice,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\n"
            "2026-10-01T09:00:00Z,alice,192.168.1.100,ws-01,Logon,SUCCESS,Interactive\n"
        )
        stream = io.StringIO(csv_data)
        events, report = parse_csv_stream(stream, source_file="dups.csv")

        # Both records must be retained
        self.assertEqual(len(events), 2)
        self.assertEqual(report.total_records, 2)
        self.assertEqual(report.duplicate_candidate_count, 1)

        # First row is original
        self.assertFalse(events[0].is_duplicate_candidate)
        # Second row is marked as duplicate candidate
        self.assertTrue(events[1].is_duplicate_candidate)
        self.assertEqual(events[0].duplicate_fingerprint, events[1].duplicate_fingerprint)
        self.assertIn(events[0].duplicate_fingerprint, report.duplicate_groups)


class TestStage1Baseline(unittest.TestCase):

    def test_baseline_strict_temporal_cutoff_and_exact_boundaries(self):
        cutoff = datetime(2026, 10, 10, 23, 59, 59, tzinfo=timezone.utc)

        # Baseline events (before cutoff) - 5 events for alice
        training_events = []
        for i in range(5):
            training_events.append(
                parse_csv_stream(
                    io.StringIO(
                        "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                        f"2026-10-0{i+1}T10:00:00Z,alice,192.168.1.50,ws-01,Logon,SUCCESS,Interactive\n"
                    )
                )[0][0]
            )

        # Exact boundary event: timestamp == cutoff (must be included)
        exact_boundary_event = parse_csv_stream(
            io.StringIO(
                "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                "2026-10-10T23:59:59Z,alice,192.168.1.51,ws-01,Logon,SUCCESS,Interactive\n"
            )
        )[0][0]

        # Just beyond boundary event: timestamp == cutoff + 1 second (must be excluded)
        beyond_boundary_event = parse_csv_stream(
            io.StringIO(
                "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                "2026-10-11T00:00:00Z,alice,203.0.113.99,secret-server,Logon,SUCCESS,Interactive\n"
            )
        )[0][0]

        all_events = training_events + [exact_boundary_event, beyond_boundary_event]
        repo = build_user_baselines(all_events, training_cutoff_utc=cutoff, min_training_events=5)
        alice_base = repo.get_user_baseline("alice")

        # 5 normal + 1 exact boundary = 6 total events
        self.assertEqual(alice_base.total_events, 6)
        self.assertEqual(alice_base.status, BaselineStatus.ESTABLISHED)
        self.assertIn("192.168.1.50", alice_base.known_source_ips)
        self.assertIn("192.168.1.51", alice_base.known_source_ips)

        # Post-cutoff event strictly excluded
        self.assertNotIn("203.0.113.99", alice_base.known_source_ips)
        self.assertNotIn("secret-server", alice_base.known_destination_hosts)

    def test_baseline_all_failures_does_not_establish_normal_behavior(self):
        # 10 training events, but all are FAILURE
        events = []
        for i in range(10):
            events.append(
                parse_csv_stream(
                    io.StringIO(
                        "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                        f"2026-10-01T10:{i:02d}:00Z,target_user,198.51.100.99,auth-srv,Logon,FAILURE,Network\n"
                    )
                )[0][0]
            )

        repo = build_user_baselines(events, min_training_events=5)
        base = repo.get_user_baseline("target_user")

        # Must NOT be ESTABLISHED because successes == 0
        self.assertEqual(base.status, BaselineStatus.INSUFFICIENT_DATA)
        self.assertFalse(base.has_established_baseline)
        self.assertEqual(base.successful_events, 0)
        self.assertEqual(base.failed_events, 10)

        # Behavioral sets must remain empty
        self.assertEqual(base.typical_hours_utc, set())
        self.assertEqual(base.typical_days_of_week, set())
        self.assertEqual(base.known_source_ips, set())
        self.assertEqual(base.known_destination_hosts, set())

        # Failed IP and host must be tracked separately
        self.assertIn("198.51.100.99", base.failed_source_ips)
        self.assertIn("auth-srv", base.failed_destination_hosts)

    def test_baseline_failed_logins_not_learned_as_normal_infrastructure(self):
        # 6 successes from normal IP, plus 3 failures from attacker IP
        events = []
        for i in range(6):
            events.append(
                parse_csv_stream(
                    io.StringIO(
                        "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                        f"2026-10-0{i+1}T09:00:00Z,alice,192.168.1.50,corp-ws,Logon,SUCCESS,Interactive\n"
                    )
                )[0][0]
            )
        for i in range(3):
            events.append(
                parse_csv_stream(
                    io.StringIO(
                        "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                        f"2026-10-0{i+1}T23:00:00Z,alice,203.0.113.88,domain-controller,Logon,FAILURE,Network\n"
                    )
                )[0][0]
            )

        repo = build_user_baselines(events, min_training_events=5)
        base = repo.get_user_baseline("alice")

        self.assertEqual(base.status, BaselineStatus.ESTABLISHED)
        self.assertIn("192.168.1.50", base.known_source_ips)
        self.assertIn("corp-ws", base.known_destination_hosts)

        # Attacker failed IP and target host must NOT be in normal known sets
        self.assertNotIn("203.0.113.88", base.known_source_ips)
        self.assertNotIn("domain-controller", base.known_destination_hosts)

        # Attacker IP and target host must be in failed sets
        self.assertIn("203.0.113.88", base.failed_source_ips)
        self.assertIn("domain-controller", base.failed_destination_hosts)

    def test_baseline_coverage_and_unprofiled_users(self):
        cutoff = datetime(2026, 10, 10, 23, 59, 59, tzinfo=timezone.utc)
        events = []

        # User 1: alice (6 SUCCESS events -> ESTABLISHED)
        for i in range(6):
            events.append(
                parse_csv_stream(
                    io.StringIO(
                        "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                        f"2026-10-0{i+1}T10:00:00Z,alice,192.168.1.50,ws-01,Logon,SUCCESS,Interactive\n"
                    )
                )[0][0]
            )

        # User 2: edward (2 SUCCESS events -> INSUFFICIENT_DATA because min_training_events=5)
        for i in range(2):
            events.append(
                parse_csv_stream(
                    io.StringIO(
                        "timestamp,username,source_ip,destination_host,event_type,result,logon_type\n"
                        f"2026-10-0{i+1}T12:00:00Z,edward,192.168.1.75,ws-03,Logon,SUCCESS,Interactive\n"
                    )
                )[0][0]
            )

        repo = build_user_baselines(events, training_cutoff_utc=cutoff, min_training_events=5)

        # 1. Profiled with ESTABLISHED status
        alice_base = repo.get_user_baseline("alice")
        self.assertEqual(alice_base.status, BaselineStatus.ESTABLISHED)
        self.assertTrue(alice_base.has_established_baseline)

        # 2. Profiled with INSUFFICIENT_DATA status
        edward_base = repo.get_user_baseline("edward")
        self.assertEqual(edward_base.status, BaselineStatus.INSUFFICIENT_DATA)
        self.assertFalse(edward_base.has_established_baseline)
        self.assertEqual(edward_base.total_events, 2)

        # 3. Completely unobserved user -> UNAVAILABLE status
        frank_base = repo.get_user_baseline("frank.guest")
        self.assertEqual(frank_base.status, BaselineStatus.UNAVAILABLE)
        self.assertFalse(frank_base.has_established_baseline)
        self.assertEqual(frank_base.total_events, 0)

        # Coverage summary verification
        cov = repo.coverage_summary()
        self.assertEqual(cov["total_users_profiled"], 2)
        self.assertEqual(cov["established_baselines"], 1)
        self.assertEqual(cov["insufficient_data_baselines"], 1)
        self.assertEqual(cov["coverage_percentage"], 50.0)


class TestStage1SyntheticData(unittest.TestCase):

    def test_synthetic_data_generation_deterministic_and_active_seed(self):
        # Deterministic: identical seeds produce identical outputs
        train1a, eval1a = generate_synthetic_records(seed=42)
        train1b, eval1b = generate_synthetic_records(seed=42)
        self.assertEqual(train1a, train1b)
        self.assertEqual(eval1a, eval1b)

        # Active seed: different seeds produce different pseudo-random jitters
        train2, eval2 = generate_synthetic_records(seed=999)
        self.assertNotEqual(train1a, train2)

    def test_chronological_evaluation_record_ordering(self):
        _, eval_records = generate_synthetic_records(seed=42)

        # All parseable timestamps must be non-decreasing
        parseable_dts = []
        for r in eval_records:
            try:
                dt = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                parseable_dts.append(dt)
            except Exception:
                pass

        self.assertGreater(len(parseable_dts), 20)
        for i in range(len(parseable_dts) - 1):
            self.assertLessEqual(
                parseable_dts[i],
                parseable_dts[i + 1],
                f"Evaluation records must be strictly chronological: {parseable_dts[i]} > {parseable_dts[i+1]}",
            )

    def test_synthetic_data_parses_cleanly_and_models_all_six_scenarios(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            train_path, eval_path = generate_synthetic_datasets(output_dir=tmpdir, seed=42)

            # Test training parsing
            train_events, train_report = parse_csv_file(train_path)
            self.assertGreater(train_report.valid_records, 0)
            self.assertEqual(train_report.malformed_records, 0)

            # Build baseline from training data
            repo = build_user_baselines(train_events, min_training_events=5)
            alice_base = repo.get_user_baseline("alice.smith")
            self.assertEqual(alice_base.status, BaselineStatus.ESTABLISHED)

            # Test evaluation parsing (contains valid records, scenarios, plus explicit anomalies)
            eval_events, eval_report = parse_csv_file(eval_path)
            self.assertGreater(eval_report.total_records, 0)
            self.assertGreater(eval_report.malformed_records, 0)  # Has expected data-quality test rows
            self.assertGreater(eval_report.duplicate_candidate_count, 0)  # Has expected duplicate candidates

            # Verify that ALL 6 required test scenarios are present in evaluation records:
            usernames = [e.username for e in eval_events]
            source_ips = [e.source_ip for e in eval_events]
            dest_hosts = [e.destination_host for e in eval_events]

            # Scenario 1 (Repeated failures): charlie.davis
            self.assertIn("charlie.davis", usernames)
            charlie_failures = sum(1 for e in eval_events if e.username == "charlie.davis" and e.result == "FAILURE")
            self.assertGreaterEqual(charlie_failures, 5)

            # Scenario 2 (Burst then success): dana.scully
            self.assertIn("dana.scully", usernames)
            dana_success = any(e.username == "dana.scully" and e.result == "SUCCESS" for e in eval_events)
            dana_failure = any(e.username == "dana.scully" and e.result == "FAILURE" for e in eval_events)
            self.assertTrue(dana_success and dana_failure)

            # Scenario 3 (Password spraying across accounts): 203.0.113.88
            self.assertIn("203.0.113.88", source_ips)
            spray_targets = {e.username for e in eval_events if e.source_ip == "203.0.113.88"}
            self.assertGreaterEqual(len(spray_targets), 5)

            # Scenario 4 (Unusual login hours): alice.smith at 03:15 UTC
            alice_off_hours = any(
                e.username == "alice.smith" and e.timestamp_utc and e.timestamp_utc.hour == 3
                for e in eval_events
            )
            self.assertTrue(alice_off_hours)

            # Scenario 5 (Unfamiliar source IP): bob.jones from 185.220.101.5
            bob_unfamiliar_ip = any(
                e.username == "bob.jones" and e.source_ip == "185.220.101.5"
                for e in eval_events
            )
            self.assertTrue(bob_unfamiliar_ip)

            # Scenario 6 (Sudden unfamiliar host): alice.smith to domain-controller-01
            alice_unfamiliar_host = any(
                e.username == "alice.smith" and e.destination_host == "domain-controller-01"
                for e in eval_events
            )
            self.assertTrue(alice_unfamiliar_host)


if __name__ == "__main__":
    unittest.main()
