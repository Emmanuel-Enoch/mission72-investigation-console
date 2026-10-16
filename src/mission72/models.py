"""
Canonical event data models, data quality reporting structures, and baseline representations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class BaselineStatus(str, Enum):
    """
    Status of a user's behavioral baseline.
    - UNAVAILABLE: The user was never observed in training data.
    - INSUFFICIENT_DATA: Observed in training, but record count is below minimum threshold.
    - ESTABLISHED: Sufficient training records exist to reliably model normal behavior.
    """
    UNAVAILABLE = "UNAVAILABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    ESTABLISHED = "ESTABLISHED"


@dataclass
class AuthEvent:
    """
    Canonical model for an authentication or activity log record.
    Preserves original file origin and line number to ensure complete provenance.
    Never silently discards malformed data.
    """
    source_file: str
    row_number: int
    raw_data: Dict[str, str] = field(default_factory=dict)

    timestamp_raw: str = ""
    timestamp_utc: Optional[datetime] = None
    username: str = ""
    source_ip: str = ""
    destination_host: str = ""
    event_type: str = ""
    result: str = ""
    logon_type: str = ""

    # Data quality tracking
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)

    # Duplicate candidate tracking
    # Note: A duplicate fingerprint indicates identical canonical attribute values;
    # it does not prove physical identity or replace raw logging.
    is_duplicate_candidate: bool = False
    duplicate_fingerprint: str = ""


@dataclass
class DuplicateCandidateRecord:
    """Represents a row flagged as sharing a duplicate candidate fingerprint."""
    source_file: str
    row_number: int
    timestamp_raw: str
    username: str
    source_ip: str
    destination_host: str
    result: str


@dataclass
class DuplicateGroup:
    """Groups all occurrences matching a duplicate candidate fingerprint."""
    fingerprint: str
    first_seen_file: str
    first_seen_row: int
    occurrences: List[DuplicateCandidateRecord] = field(default_factory=list)


@dataclass
class DataQualityReport:
    """
    Comprehensive record of ingestion quality, schema validity, malformed rows,
    invalid timestamps, missing attributes, and duplicate candidates.
    """
    total_records: int = 0
    valid_records: int = 0
    malformed_records: int = 0
    missing_columns: List[str] = field(default_factory=list)
    schema_errors: List[str] = field(default_factory=list)
    missing_field_count: int = 0
    invalid_timestamp_count: int = 0
    duplicate_candidate_count: int = 0

    validation_errors_by_row: List[Dict[str, Any]] = field(default_factory=list)
    duplicate_groups: Dict[str, DuplicateGroup] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_records": self.total_records,
            "valid_records": self.valid_records,
            "malformed_records": self.malformed_records,
            "missing_columns": list(self.missing_columns),
            "schema_errors": list(self.schema_errors),
            "missing_field_count": self.missing_field_count,
            "invalid_timestamp_count": self.invalid_timestamp_count,
            "duplicate_candidate_count": self.duplicate_candidate_count,
            "unique_duplicate_fingerprints": len(self.duplicate_groups),
            "has_schema_error": bool(self.missing_columns or self.schema_errors),
        }


@dataclass
class UserBaseline:
    """
    User behavioral baseline computed strictly during the training period.
    Explicitly tracks baseline coverage and status to distinguish unprofiled users
    from users with established normal behavior.

    Security Guarantee:
    Only successful authentication events establish normal behavioral profiles
    (known IPs, known hosts, typical hours, typical days, logon types).
    Failed attempts are tracked separately and never learned as normal behavior.
    """
    username: str
    status: BaselineStatus = BaselineStatus.UNAVAILABLE
    total_events: int = 0
    successful_events: int = 0
    failed_events: int = 0

    # Normal behavioral profile (learned ONLY from successful authentications)
    known_source_ips: Set[str] = field(default_factory=set)
    known_destination_hosts: Set[str] = field(default_factory=set)
    typical_hours_utc: Set[int] = field(default_factory=set)  # 0 to 23
    typical_days_of_week: Set[int] = field(default_factory=set)  # 0=Monday, 6=Sunday
    known_logon_types: Set[str] = field(default_factory=set)

    # Failed attempt tracking (strictly audited, never treated as normal infrastructure)
    failed_source_ips: Set[str] = field(default_factory=set)
    failed_destination_hosts: Set[str] = field(default_factory=set)

    first_seen_utc: Optional[datetime] = None
    last_seen_utc: Optional[datetime] = None

    @property
    def has_established_baseline(self) -> bool:
        return self.status == BaselineStatus.ESTABLISHED

