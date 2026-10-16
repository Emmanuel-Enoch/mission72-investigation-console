"""
Training-period user baseline engine for Mission 72.

Guarantees:
1. Strict temporal and dataset isolation: Baselines are built exclusively from events
   within an explicitly supplied training period (timestamp_utc <= training_cutoff_utc)
   or designated training dataset. Evaluation events must never influence baseline values.
2. Explicit baseline coverage tracking: Distinguishes between:
   - UNAVAILABLE: User never observed during training.
   - INSUFFICIENT_DATA: User observed, but event count is below minimum threshold (e.g., < 5 events).
   - ESTABLISHED: Sufficient historical data to model normal behavioral patterns.
"""

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

from mission72.models import AuthEvent, BaselineStatus, UserBaseline


class BaselineRepository:
    """
    In-memory registry of per-user baseline models computed strictly during training.
    Provides safe querying for downstream detectors.
    """

    def __init__(
        self,
        baselines: Dict[str, UserBaseline],
        training_cutoff_utc: Optional[datetime] = None,
        min_training_events: int = 5,
    ) -> None:
        self._baselines = baselines
        self.training_cutoff_utc = training_cutoff_utc
        self.min_training_events = min_training_events

    def get_user_baseline(self, username: str) -> UserBaseline:
        """
        Retrieves the baseline profile for a user.
        If the user has no training record, returns an UNAVAILABLE baseline object.
        Never fabricates a baseline or misrepresents absence of data as normal behavior.
        """
        norm_user = username.strip().lower()
        if norm_user in self._baselines:
            return self._baselines[norm_user]

        # Explicitly return UNAVAILABLE baseline
        return UserBaseline(
            username=username,
            status=BaselineStatus.UNAVAILABLE,
            total_events=0,
            successful_events=0,
            failed_events=0,
            known_source_ips=set(),
            known_destination_hosts=set(),
            typical_hours_utc=set(),
            typical_days_of_week=set(),
            known_logon_types=set(),
            failed_source_ips=set(),
            failed_destination_hosts=set(),
            first_seen_utc=None,
            last_seen_utc=None,
        )

    def all_baselines(self) -> List[UserBaseline]:
        """Returns all computed user baselines."""
        return list(self._baselines.values())

    def coverage_summary(self) -> Dict[str, Any]:
        """
        Reports baseline coverage metrics across all observed users in training.
        """
        total = len(self._baselines)
        established = sum(1 for b in self._baselines.values() if b.status == BaselineStatus.ESTABLISHED)
        insufficient = sum(1 for b in self._baselines.values() if b.status == BaselineStatus.INSUFFICIENT_DATA)
        pct = (established / total * 100.0) if total > 0 else 0.0

        return {
            "total_users_profiled": total,
            "established_baselines": established,
            "insufficient_data_baselines": insufficient,
            "coverage_percentage": round(pct, 2),
            "min_event_threshold": self.min_training_events,
            "training_cutoff_utc": self.training_cutoff_utc.isoformat() if self.training_cutoff_utc else None,
        }


def build_user_baselines(
    events: Iterable[AuthEvent],
    training_cutoff_utc: Optional[datetime] = None,
    min_training_events: int = 5,
) -> BaselineRepository:
    """
    Constructs user baselines strictly from training events.

    Baseline Safety Guarantees:
    - Only SUCCESSFUL authentication events establish normal behavioral baselines
      (known source IPs, known destination hosts, typical hours, days, logon types).
    - Failed attempts in training are tracked separately (failed_source_ips/hosts)
      and are NEVER silently incorporated into normal infrastructure.
    - A baseline is marked ESTABLISHED only when the user has at least min_training_events
      SUCCESSFUL logins. If a user only has failed logins or fewer than min_training_events
      successful logins, status remains INSUFFICIENT_DATA.
    - Events strictly after training_cutoff_utc (even by 1 microsecond) are excluded.
    """
    user_records: Dict[str, List[AuthEvent]] = defaultdict(list)

    for event in events:
        # Enforce quality: malformed or invalid records must not corrupt baseline metrics
        if not event.is_valid or event.timestamp_utc is None:
            continue

        # Enforce strict cutoff: zero data leakage from post-cutoff evaluation records
        # Boundary rule: events with timestamp <= training_cutoff_utc are eligible;
        # events with timestamp > training_cutoff_utc are strictly ignored.
        if training_cutoff_utc is not None and event.timestamp_utc > training_cutoff_utc:
            continue

        norm_user = event.username.strip().lower()
        if not norm_user:
            continue

        user_records[norm_user].append(event)

    baselines: Dict[str, UserBaseline] = {}

    for norm_user, u_events in user_records.items():
        # Representative display username (original casing from first record)
        display_username = u_events[0].username

        known_ips: Set[str] = set()
        known_hosts: Set[str] = set()
        failed_ips: Set[str] = set()
        failed_hosts: Set[str] = set()
        typical_hours: Set[int] = set()
        typical_days: Set[int] = set()
        known_logon_types: Set[str] = set()

        successes = 0
        failures = 0
        first_seen = u_events[0].timestamp_utc
        last_seen = u_events[0].timestamp_utc

        for ev in u_events:
            ts = ev.timestamp_utc
            assert ts is not None  # Guaranteed by earlier filter

            if first_seen is None or ts < first_seen:
                first_seen = ts
            if last_seen is None or ts > last_seen:
                last_seen = ts

            res_upper = ev.result.strip().upper()
            is_success = res_upper in ("SUCCESS", "AUDIT SUCCESS", "PASS", "0", "OK")

            if is_success:
                successes += 1
                if ev.source_ip:
                    known_ips.add(ev.source_ip.strip())
                if ev.destination_host:
                    known_hosts.add(ev.destination_host.strip().lower())
                if ev.logon_type:
                    known_logon_types.add(ev.logon_type.strip())
                typical_hours.add(ts.hour)
                typical_days.add(ts.weekday())
            else:
                failures += 1
                if ev.source_ip:
                    failed_ips.add(ev.source_ip.strip())
                if ev.destination_host:
                    failed_hosts.add(ev.destination_host.strip().lower())

        total_ev = len(u_events)
        # Baseline safety rule:
        # Only users with sufficient SUCCESSFUL authentication events reach ESTABLISHED status.
        status = (
            BaselineStatus.ESTABLISHED
            if successes >= min_training_events
            else BaselineStatus.INSUFFICIENT_DATA
        )

        baselines[norm_user] = UserBaseline(
            username=display_username,
            status=status,
            total_events=total_ev,
            successful_events=successes,
            failed_events=failures,
            known_source_ips=known_ips,
            known_destination_hosts=known_hosts,
            typical_hours_utc=typical_hours,
            typical_days_of_week=typical_days,
            known_logon_types=known_logon_types,
            failed_source_ips=failed_ips,
            failed_destination_hosts=failed_hosts,
            first_seen_utc=first_seen,
            last_seen_utc=last_seen,
        )

    return BaselineRepository(
        baselines=baselines,
        training_cutoff_utc=training_cutoff_utc,
        min_training_events=min_training_events,
    )

