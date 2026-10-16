"""
Canonical CSV ingestion, timestamp normalization, explicit field validation,
and duplicate candidate tracking for Mission 72.

Timezone Normalization Policy:
- All valid timestamps are normalized to UTC with timezone awareness (timezone.utc).
- Aware timestamps with explicit offsets (e.g., ISO 8601 with +00:00, Z, or -05:00) are converted
  to UTC via .astimezone(timezone.utc).
- Naive timestamps (lacking timezone offset/indicator) are interpreted as UTC by default per
  the documented offline analysis policy, avoiding reliance on local machine clock.
- The raw, unmodified timestamp string is always preserved in AuthEvent.timestamp_raw.
- Ambiguous timestamps (such as slash-separated dates '04/05/2026' where both day and month <= 12)
  are reported as ambiguous validation errors unless an explicit format is configured.
- Unparseable, ambiguous, or corrupt timestamp strings are marked with explicit validation errors,
  leaving timestamp_utc=None and is_valid=False. Records are never silently dropped.
"""

import csv
import hashlib
import io
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from mission72.models import (
    AuthEvent,
    DataQualityReport,
    DuplicateCandidateRecord,
    DuplicateGroup,
)

# Standard supported unambiguous timestamp formats for offline parsing
UNAMBIGUOUS_TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S%z",
    "%Y/%m/%d",
    "%Y-%m-%d",
]

# Aliases for required logical fields
FIELD_ALIASES: Dict[str, List[str]] = {
    "timestamp": ["timestamp", "time", "datetime", "event_time", "date_time", "@timestamp"],
    "username": ["username", "user", "user_id", "account", "user_name", "principal"],
    "source_ip": ["source ip", "source_ip", "src_ip", "sourceip", "client_ip", "ip", "src"],
    "destination_host": ["destination/host", "destination_host", "destination host", "dest_host", "host", "target_host", "computer_name"],
    "event_type": ["event type", "event_type", "action", "activity", "event"],
    "result": ["result", "status", "outcome", "action_result"],
    "logon_type": ["logon type", "logon_type", "logon", "login_type"],
}

REQUIRED_CANONICAL_FIELDS = [
    "timestamp",
    "username",
    "source_ip",
    "destination_host",
    "event_type",
    "result",
    "logon_type",
]


def _normalize_header(header: str) -> str:
    """Normalizes header string for comparison."""
    return header.strip().lower()


def parse_timestamp_with_diagnosis(
    raw_ts: str,
    configured_format: Optional[str] = None,
) -> Tuple[Optional[datetime], Optional[str]]:
    """
    Normalizes a timestamp string to UTC datetime.
    Returns (parsed_datetime, error_message).

    Follows explicit policy:
    - If configured_format is provided, it is used first.
    - Aware strings are converted to UTC.
    - Naive strings are assumed UTC.
    - Slash-separated dates with ambiguous day/month (both <= 12 and unequal) are reported as ambiguous.
    """
    if not raw_ts or not raw_ts.strip():
        return None, "Timestamp value is empty"

    cleaned = raw_ts.strip()

    # 1. If explicit format was configured, try it first
    if configured_format:
        try:
            dt = datetime.strptime(cleaned, configured_format)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc), None
            return dt.astimezone(timezone.utc), None
        except ValueError:
            return None, f"Timestamp does not match configured format '{configured_format}': '{raw_ts}'"

    # 2. Try ISO 8601 (robust for standard ISO formats)
    try:
        iso_str = cleaned
        if iso_str.endswith("Z") or iso_str.endswith("z"):
            iso_str = iso_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc), None
        return dt.astimezone(timezone.utc), None
    except (ValueError, TypeError):
        pass

    # 3. Check for slash-separated formats (e.g. MM/DD/YYYY vs DD/MM/YYYY)
    slash_match = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})(.*)$", cleaned)
    if slash_match:
        part1 = int(slash_match.group(1))
        part2 = int(slash_match.group(2))
        rest = slash_match.group(4).strip()
        time_part = rest if rest else ""

        # Ambiguity check: both parts <= 12 and different
        if part1 <= 12 and part2 <= 12 and part1 != part2:
            return None, f"Ambiguous date format in timestamp: '{raw_ts}' (cannot distinguish MM/DD vs DD/MM without configured format)"

        # Unambiguous: part1 > 12 must be day (DD/MM/YYYY)
        if part1 > 12 and part2 <= 12:
            fmt = "%d/%m/%Y " + ("%H:%M:%S" if ":" in time_part else "%H:%M") if time_part else "%d/%m/%Y"
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=timezone.utc), None
            except ValueError:
                pass

        # Unambiguous: part2 > 12 must be day (MM/DD/YYYY)
        if part2 > 12 and part1 <= 12:
            fmt = "%m/%d/%Y " + ("%H:%M:%S" if ":" in time_part else "%H:%M") if time_part else "%m/%d/%Y"
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=timezone.utc), None
            except ValueError:
                pass

        # Both parts equal (e.g. 05/05/2026)
        if part1 == part2 and part1 <= 12:
            fmt = "%m/%d/%Y " + ("%H:%M:%S" if ":" in time_part else "%H:%M") if time_part else "%m/%d/%Y"
            try:
                dt = datetime.strptime(cleaned, fmt)
                return dt.replace(tzinfo=timezone.utc), None
            except ValueError:
                pass

    # 4. Try standard unambiguous format strings (year-first)
    for fmt in UNAMBIGUOUS_TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc), None
            return dt.astimezone(timezone.utc), None
        except ValueError:
            continue

    return None, f"Invalid timestamp format: '{raw_ts}'"


def parse_timestamp_to_utc(
    raw_ts: str,
    configured_format: Optional[str] = None,
) -> Optional[datetime]:
    """
    Convenience wrapper returning parsed UTC datetime or None.
    Preserves backward compatibility for callers expecting Optional[datetime].
    """
    dt, _ = parse_timestamp_with_diagnosis(raw_ts, configured_format=configured_format)
    return dt


def compute_duplicate_fingerprint(
    timestamp_key: str,
    username: str,
    source_ip: str,
    destination_host: str,
    event_type: str,
    result: str,
    logon_type: str,
) -> str:
    """
    Computes deterministic SHA-256 fingerprint of normalized fields.
    Used exclusively to detect candidate duplicate records without declaring physical identity.
    """
    data = (
        f"{timestamp_key}|{username.strip().lower()}|{source_ip.strip().lower()}|"
        f"{destination_host.strip().lower()}|{event_type.strip().lower()}|"
        f"{result.strip().upper()}|{logon_type.strip().lower()}"
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def parse_csv_stream(
    stream: Iterable[str],
    source_file: str = "<stream>",
    configured_date_format: Optional[str] = None,
) -> Tuple[List[AuthEvent], DataQualityReport]:
    """
    Parses CSV content from a stream or lines iterable.
    Preserves all rows (even malformed ones) and produces a comprehensive DataQualityReport.

    Data Quality Guarantees:
    - Missing CSV header columns are recorded at the schema level and not double-counted per row.
    - Header-only CSVs with missing columns are explicitly reported as having schema errors.
    - Malformed syntax (NUL bytes, unescaped quotes) is captured without crashing.
    - Ambiguous timestamps are flagged rather than silently guessed.
    """
    events: List[AuthEvent] = []
    report = DataQualityReport()
    seen_fingerprints: Dict[str, Tuple[str, int]] = {}

    reader = csv.reader(stream)
    try:
        header_row = next(reader)
    except StopIteration:
        # Empty stream
        return events, report
    except csv.Error as e:
        report.schema_errors.append(f"Failed to read CSV header: {e}")
        return events, report

    # Resolve header index to canonical name
    header_index_to_canonical: Dict[int, str] = {}
    found_canonicals: set[str] = set()

    for idx, col_name in enumerate(header_row):
        norm = _normalize_header(col_name)
        for canon, aliases in FIELD_ALIASES.items():
            if canon not in found_canonicals and norm in [_normalize_header(a) for a in aliases]:
                header_index_to_canonical[idx] = canon
                found_canonicals.add(canon)
                break

    # Schema validation: check required canonical columns
    missing_columns = [f for f in REQUIRED_CANONICAL_FIELDS if f not in found_canonicals]
    if missing_columns:
        report.missing_columns = list(missing_columns)
        report.schema_errors.append(f"Missing required columns in CSV header: {', '.join(missing_columns)}")

    row_number = 1

    while True:
        try:
            raw_fields = next(reader)
        except StopIteration:
            break
        except csv.Error as e:
            row_number += 1
            report.total_records += 1
            report.malformed_records += 1
            err_msg = f"Malformed CSV syntax: {e}"
            report.validation_errors_by_row.append({
                "source_file": source_file,
                "row_number": row_number,
                "errors": [err_msg],
                "raw_data": {},
            })
            events.append(
                AuthEvent(
                    source_file=source_file,
                    row_number=row_number,
                    raw_data={},
                    is_valid=False,
                    validation_errors=[err_msg],
                )
            )
            continue

        row_number += 1
        report.total_records += 1

        raw_data: Dict[str, str] = {}
        canonical_values: Dict[str, str] = {f: "" for f in REQUIRED_CANONICAL_FIELDS}

        has_nul = False
        for idx, val in enumerate(raw_fields):
            col_name = header_row[idx] if idx < len(header_row) else f"col_{idx}"
            raw_data[col_name] = val
            if "\x00" in val:
                has_nul = True
            if idx in header_index_to_canonical:
                canonical_values[header_index_to_canonical[idx]] = val.strip()

        row_errors: List[str] = []

        if has_nul:
            row_errors.append("Row contains illegal NUL byte (\\x00)")

        # If header columns were missing, mark row as invalid due to schema failure
        # (do NOT increment missing_field_count here; missing header is tracked in report.missing_columns)
        if missing_columns:
            row_errors.append(f"Row invalid due to missing schema column(s): {', '.join(missing_columns)}")

        # Check required fields for columns that DO exist in the header
        for req_field in found_canonicals:
            if not canonical_values[req_field]:
                err = f"Missing required field value: '{req_field}'"
                row_errors.append(err)
                report.missing_field_count += 1

        # Timestamp normalization and validation
        raw_ts = canonical_values["timestamp"]
        parsed_ts: Optional[datetime] = None
        if raw_ts:
            parsed_ts, ts_err = parse_timestamp_with_diagnosis(
                raw_ts,
                configured_format=configured_date_format,
            )
            if ts_err:
                row_errors.append(ts_err)
                report.invalid_timestamp_count += 1

        norm_result = canonical_values["result"].upper() if canonical_values["result"] else ""

        is_valid = len(row_errors) == 0
        if is_valid:
            report.valid_records += 1
        else:
            report.malformed_records += 1
            report.validation_errors_by_row.append({
                "source_file": source_file,
                "row_number": row_number,
                "errors": row_errors,
                "raw_data": raw_data,
            })

        # Duplicate candidate fingerprint
        ts_key = parsed_ts.isoformat() if parsed_ts else raw_ts
        fp = compute_duplicate_fingerprint(
            timestamp_key=ts_key,
            username=canonical_values["username"],
            source_ip=canonical_values["source_ip"],
            destination_host=canonical_values["destination_host"],
            event_type=canonical_values["event_type"],
            result=norm_result,
            logon_type=canonical_values["logon_type"],
        )

        is_duplicate = False
        if fp in seen_fingerprints:
            is_duplicate = True
            report.duplicate_candidate_count += 1
            first_file, first_row = seen_fingerprints[fp]
            if fp not in report.duplicate_groups:
                report.duplicate_groups[fp] = DuplicateGroup(
                    fingerprint=fp,
                    first_seen_file=first_file,
                    first_seen_row=first_row,
                    occurrences=[
                        DuplicateCandidateRecord(
                            source_file=first_file,
                            row_number=first_row,
                            timestamp_raw=ts_key,
                            username=canonical_values["username"],
                            source_ip=canonical_values["source_ip"],
                            destination_host=canonical_values["destination_host"],
                            result=norm_result,
                        )
                    ],
                )
            report.duplicate_groups[fp].occurrences.append(
                DuplicateCandidateRecord(
                    source_file=source_file,
                    row_number=row_number,
                    timestamp_raw=ts_key,
                    username=canonical_values["username"],
                    source_ip=canonical_values["source_ip"],
                    destination_host=canonical_values["destination_host"],
                    result=norm_result,
                )
            )
        else:
            seen_fingerprints[fp] = (source_file, row_number)

        event = AuthEvent(
            source_file=source_file,
            row_number=row_number,
            raw_data=raw_data,
            timestamp_raw=raw_ts,
            timestamp_utc=parsed_ts,
            username=canonical_values["username"],
            source_ip=canonical_values["source_ip"],
            destination_host=canonical_values["destination_host"],
            event_type=canonical_values["event_type"],
            result=norm_result,
            logon_type=canonical_values["logon_type"],
            is_valid=is_valid,
            validation_errors=row_errors,
            is_duplicate_candidate=is_duplicate,
            duplicate_fingerprint=fp,
        )
        events.append(event)

    return events, report


def parse_csv_file(
    file_path: Union[str, Path],
    configured_date_format: Optional[str] = None,
) -> Tuple[List[AuthEvent], DataQualityReport]:
    """
    Parses a CSV file from disk using parse_csv_stream.
    Preserves provenance with exact path and line indices.
    Supports UTF-8 BOM encoding transparently (utf-8-sig).
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Source file not found: {path}")

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        return parse_csv_stream(f, source_file=str(path), configured_date_format=configured_date_format)
