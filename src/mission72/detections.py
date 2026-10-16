"""
Detection engine implementing the six mandatory Mission 72 detection categories:
1. Repeated authentication failures.
2. Failure burst followed by a successful login.
3. Password spraying across accounts.
4. Login at unusual times relative to the user's training baseline.
5. Unfamiliar source IP/location using supplied lookup data where available.
6. Sudden access to many unfamiliar destination hosts.

Baseline Safety Guarantees:
- Rules 4, 5, and 6 ONLY evaluate users with an ESTABLISHED baseline.
- Unprofiled users (UNAVAILABLE or INSUFFICIENT_DATA) do not trigger baseline deviation alerts.
- Suspicious activity is framed as risk indicators for triage, not conclusive guilt.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from mission72.baseline import BaselineRepository
from mission72.models import AuthEvent, BaselineStatus


@dataclass
class Alert:
    """Represents a discrete rule detection with full evidence provenance."""
    alert_id: str
    rule_id: str
    rule_name: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    username: str
    timestamp_utc: datetime
    source_ip: str
    destination_host: str
    explanation: str
    recommended_action: str
    evidence_events: List[AuthEvent] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleConfig:
    """Configurable thresholds for all six detection categories."""
    # Category 1: Repeated failures
    repeated_failures_threshold: int = 5
    repeated_failures_window_seconds: int = 300  # 5 minutes

    # Category 2: Burst followed by success
    burst_failure_threshold: int = 4
    burst_window_seconds: int = 300  # 5 minutes
    burst_success_window_seconds: int = 180  # 3 minutes after burst

    # Category 3: Password spraying
    spray_user_threshold: int = 4  # distinct accounts
    spray_window_seconds: int = 600  # 10 minutes

    # Category 4: Unusual login times
    unusual_time_severity: str = "MEDIUM"

    # Category 5: Unfamiliar IP/Location
    unfamiliar_ip_severity: str = "MEDIUM"

    # Category 6: Sudden access to unfamiliar hosts
    unfamiliar_host_threshold: int = 2  # distinct unfamiliar hosts
    unfamiliar_host_window_seconds: int = 3600  # 1 hour


class DetectionEngine:
    """
    Executes the six required detection rules on valid, chronologically ordered
    evaluation events, utilizing user baselines where appropriate.
    """

    def __init__(
        self,
        baseline_repo: BaselineRepository,
        config: Optional[RuleConfig] = None,
        ip_location_map: Optional[Dict[str, Dict[str, str]]] = None,
        context_registry: Optional[Any] = None,
    ) -> None:
        self.baseline_repo = baseline_repo
        self.config = config or RuleConfig()
        self.ip_location_map = ip_location_map or {}
        self.context_registry = context_registry

    def _resolve_location(self, ip: str) -> Optional[str]:
        """Looks up location information if supplied in lookup data."""
        if ip in self.ip_location_map:
            loc = self.ip_location_map[ip]
            city = loc.get("city", "")
            country = loc.get("country", "")
            if city and country:
                return f"{city}, {country}"
            return country or city or None
        return None

    def detect_repeated_failures(self, events: List[AuthEvent]) -> List[Alert]:
        """
        Category 1: Repeated authentication failures.
        Detects multiple failed login attempts against a single user within a sliding time window.
        """
        alerts: List[Alert] = []
        user_failures: Dict[str, List[AuthEvent]] = defaultdict(list)

        for ev in events:
            if not ev.is_valid or ev.timestamp_utc is None:
                continue
            res = ev.result.strip().upper()
            if res in ("FAILURE", "FAILED", "AUDIT FAILURE", "ERROR", "1"):
                norm_user = ev.username.strip().lower()
                user_failures[norm_user].append(ev)

        alert_idx = 1
        for norm_user, fails in user_failures.items():
            fails.sort(key=lambda e: e.timestamp_utc)
            i = 0
            while i < len(fails):
                start_ev = fails[i]
                start_time = start_ev.timestamp_utc
                window_events = [
                    e for e in fails[i:]
                    if (e.timestamp_utc - start_time).total_seconds() <= self.config.repeated_failures_window_seconds
                ]

                if len(window_events) >= self.config.repeated_failures_threshold:
                    ips = sorted({e.source_ip for e in window_events if e.source_ip})
                    hosts = sorted({e.destination_host for e in window_events if e.destination_host})
                    end_time = window_events[-1].timestamp_utc
                    alerts.append(
                        Alert(
                            alert_id=f"ALT-R01-{alert_idx:04d}",
                            rule_id="RULE-01-REPEATED-FAILURES",
                            rule_name="Repeated Authentication Failures",
                            category="Authentication Anomaly",
                            severity="HIGH" if len(window_events) >= 10 else "MEDIUM",
                            username=window_events[0].username,
                            timestamp_utc=end_time,
                            source_ip=", ".join(ips),
                            destination_host=", ".join(hosts),
                            explanation=(
                                f"Observed {len(window_events)} consecutive login failures for user '{window_events[0].username}' "
                                f"within {int((end_time - start_time).total_seconds())}s (threshold: {self.config.repeated_failures_threshold})."
                            ),
                            recommended_action="Inspect source IPs for brute-force origins; verify if account lockout was triggered.",
                            evidence_events=list(window_events),
                            metadata={"failure_count": len(window_events), "source_ips": ips},
                        )
                    )
                    alert_idx += 1
                    i += len(window_events)
                else:
                    i += 1

        return alerts

    def detect_burst_then_success(self, events: List[AuthEvent]) -> List[Alert]:
        """
        Category 2: Failure burst followed by a successful login.
        Detects elevated failure attempts ending in a successful login, indicating potential credential compromise.
        """
        alerts: List[Alert] = []
        user_events: Dict[str, List[AuthEvent]] = defaultdict(list)

        for ev in events:
            if not ev.is_valid or ev.timestamp_utc is None:
                continue
            norm_user = ev.username.strip().lower()
            user_events[norm_user].append(ev)

        alert_idx = 1
        for norm_user, u_evs in user_events.items():
            u_evs.sort(key=lambda e: e.timestamp_utc)
            for i, ev in enumerate(u_evs):
                res = ev.result.strip().upper()
                if res in ("SUCCESS", "AUDIT SUCCESS", "PASS", "0", "OK"):
                    succ_time = ev.timestamp_utc
                    # Look backwards for failure burst preceding this success
                    preceding_fails = [
                        prev for prev in u_evs[:i]
                        if prev.result.strip().upper() in ("FAILURE", "FAILED", "AUDIT FAILURE", "ERROR", "1")
                        and 0 <= (succ_time - prev.timestamp_utc).total_seconds() <= (self.config.burst_window_seconds + self.config.burst_success_window_seconds)
                    ]

                    if len(preceding_fails) >= self.config.burst_failure_threshold:
                        evidence = preceding_fails + [ev]
                        alerts.append(
                            Alert(
                                alert_id=f"ALT-R02-{alert_idx:04d}",
                                rule_id="RULE-02-BURST-THEN-SUCCESS",
                                rule_name="Failure Burst Followed by Successful Login",
                                category="Credential Compromise",
                                severity="CRITICAL",
                                username=ev.username,
                                timestamp_utc=succ_time,
                                source_ip=ev.source_ip,
                                destination_host=ev.destination_host,
                                explanation=(
                                    f"User '{ev.username}' experienced a burst of {len(preceding_fails)} login failures "
                                    f"culminating in a SUCCESSFUL login at {succ_time.isoformat()} from IP {ev.source_ip}."
                                ),
                                recommended_action="High priority: Contact user immediately to verify legitimacy; consider revoking active session tokens.",
                                evidence_events=evidence,
                                metadata={"failure_burst_count": len(preceding_fails), "success_ip": ev.source_ip},
                            )
                        )
                        alert_idx += 1

        return alerts

    def detect_password_spraying(self, events: List[AuthEvent]) -> List[Alert]:
        """
        Category 3: Password spraying across accounts.
        Detects a single source IP attempting logins across multiple distinct usernames.
        """
        alerts: List[Alert] = []
        ip_failures: Dict[str, List[AuthEvent]] = defaultdict(list)

        for ev in events:
            if not ev.is_valid or ev.timestamp_utc is None or not ev.source_ip:
                continue
            res = ev.result.strip().upper()
            if res in ("FAILURE", "FAILED", "AUDIT FAILURE", "ERROR", "1"):
                ip_failures[ev.source_ip.strip()].append(ev)

        alert_idx = 1
        for ip, fails in ip_failures.items():
            fails.sort(key=lambda e: e.timestamp_utc)
            i = 0
            while i < len(fails):
                start_time = fails[i].timestamp_utc
                window_events = [
                    e for e in fails[i:]
                    if (e.timestamp_utc - start_time).total_seconds() <= self.config.spray_window_seconds
                ]
                targeted_users = sorted({e.username.strip().lower() for e in window_events if e.username})

                if len(targeted_users) >= self.config.spray_user_threshold:
                    end_time = window_events[-1].timestamp_utc
                    loc_desc = self._resolve_location(ip)
                    loc_suffix = f" (Location: {loc_desc})" if loc_desc else ""
                    alerts.append(
                        Alert(
                            alert_id=f"ALT-R03-{alert_idx:04d}",
                            rule_id="RULE-03-PASSWORD-SPRAY",
                            rule_name="Password Spraying Across Accounts",
                            category="Credential Access",
                            severity="HIGH",
                            username=f"Multiple Accounts ({len(targeted_users)} users)",
                            timestamp_utc=end_time,
                            source_ip=ip,
                            destination_host=", ".join(sorted({e.destination_host for e in window_events if e.destination_host})),
                            explanation=(
                                f"Source IP {ip}{loc_suffix} attempted login failures across {len(targeted_users)} "
                                f"distinct user accounts within {int((end_time - start_time).total_seconds())}s "
                                f"(targeted: {', '.join(targeted_users[:5])}{'...' if len(targeted_users) > 5 else ''})."
                            ),
                            recommended_action="Block offending source IP at edge firewall; check for successful logins from this IP.",
                            evidence_events=list(window_events),
                            metadata={"targeted_accounts": targeted_users, "attempt_count": len(window_events)},
                        )
                    )
                    alert_idx += 1
                    i += len(window_events)
                else:
                    i += 1

        return alerts

    def detect_unusual_login_times(self, events: List[AuthEvent]) -> List[Alert]:
        """
        Category 4: Login at unusual times relative to user's training baseline.
        Safety Guarantee: Only evaluated if user has an ESTABLISHED baseline with non-empty typical hours.
        """
        alerts: List[Alert] = []
        alert_idx = 1

        for ev in events:
            if not ev.is_valid or ev.timestamp_utc is None:
                continue

            base = self.baseline_repo.get_user_baseline(ev.username)
            # Baseline Safety: Skip if baseline is unprofiled or has insufficient data
            if not base.has_established_baseline or not base.typical_hours_utc:
                continue

            ev_hour = ev.timestamp_utc.hour
            ev_weekday = ev.timestamp_utc.weekday()

            if ev_hour not in base.typical_hours_utc:
                typical_hrs_sorted = sorted(base.typical_hours_utc)
                min_h, max_h = min(typical_hrs_sorted), max(typical_hrs_sorted)
                alerts.append(
                    Alert(
                        alert_id=f"ALT-R04-{alert_idx:04d}",
                        rule_id="RULE-04-UNUSUAL-TIME",
                        rule_name="Login Attempt at Unusual Hour",
                        category="Behavioral Anomaly",
                        severity=self.config.unusual_time_severity,
                        username=ev.username,
                        timestamp_utc=ev.timestamp_utc,
                        source_ip=ev.source_ip,
                        destination_host=ev.destination_host,
                        explanation=(
                            f"User '{ev.username}' logged in at {ev.timestamp_utc.strftime('%H:%M')} UTC (hour {ev_hour}), "
                            f"outside established normal training hours (typical: {min_h:02d}:00–{max_h:02d}:00 UTC)."
                        ),
                        recommended_action="Verify with user if off-hours activity was expected or scheduled.",
                        evidence_events=[ev],
                        metadata={"event_hour": ev_hour, "typical_hours": typical_hrs_sorted},
                    )
                )
                alert_idx += 1

        return alerts

    def detect_unfamiliar_source_ip(self, events: List[AuthEvent]) -> List[Alert]:
        """
        Category 5: Unfamiliar source IP/location using supplied lookup data where available.
        Safety Guarantee: Only evaluated if user has an ESTABLISHED baseline.
        """
        alerts: List[Alert] = []
        alert_idx = 1
        seen_unfamiliar: Set[Tuple[str, str]] = set()  # (username, ip) to avoid duplicate alerts

        for ev in events:
            if not ev.is_valid or ev.timestamp_utc is None or not ev.source_ip:
                continue

            base = self.baseline_repo.get_user_baseline(ev.username)
            if not base.has_established_baseline or not base.known_source_ips:
                continue

            norm_ip = ev.source_ip.strip()
            norm_user = ev.username.strip().lower()

            if norm_ip not in base.known_source_ips:
                pair = (norm_user, norm_ip)
                if pair in seen_unfamiliar:
                    continue
                seen_unfamiliar.add(pair)

                vpn_match = self.context_registry.match_vpn(norm_ip) if self.context_registry else None
                loc_desc = self._resolve_location(norm_ip)
                if not loc_desc and vpn_match:
                    loc_desc = vpn_match.location
                loc_text = f" (Geo-Location: {loc_desc})" if loc_desc else ""

                is_verified_vpn = bool(vpn_match and vpn_match.is_trusted)
                is_untrusted_vpn = bool(vpn_match and not vpn_match.is_trusted)

                if is_verified_vpn:
                    explanation = (
                        f"User '{ev.username}' accessed system from unfamiliar IP {norm_ip}{loc_text} "
                        f"via verified corporate VPN gateway '{vpn_match.name}'. "
                        f"Location anomaly risk is mitigated by enterprise VPN evidence."
                    )
                    recommended_action = "Confirm employee remote travel status. VPN evidence verifies corporate gateway."
                    severity = "LOW"
                elif is_untrusted_vpn:
                    explanation = (
                        f"User '{ev.username}' accessed system from unfamiliar IP {norm_ip}{loc_text} "
                        f"via unverified or untrusted VPN/proxy endpoint '{vpn_match.name}'. "
                        f"Potential evasion or compromised proxy."
                    )
                    recommended_action = "Investigate untrusted VPN/proxy endpoint; verify user identity out-of-band."
                    severity = "HIGH"
                else:
                    explanation = (
                        f"User '{ev.username}' accessed system from IP {norm_ip}{loc_text}, "
                        f"which was never observed in training history (known IPs: {', '.join(sorted(base.known_source_ips))})."
                    )
                    recommended_action = "Check IP reputation and geolocation; verify whether user connected via new VPN or ISP."
                    severity = "HIGH" if loc_desc else self.config.unfamiliar_ip_severity

                alerts.append(
                    Alert(
                        alert_id=f"ALT-R05-{alert_idx:04d}",
                        rule_id="RULE-05-UNFAMILIAR-IP",
                        rule_name="Authentication from Unfamiliar Source IP",
                        category="Network Anomaly",
                        severity=severity,
                        username=ev.username,
                        timestamp_utc=ev.timestamp_utc,
                        source_ip=norm_ip,
                        destination_host=ev.destination_host,
                        explanation=explanation,
                        recommended_action=recommended_action,
                        evidence_events=[ev],
                        metadata={
                            "source_ip": norm_ip,
                            "geo_location": loc_desc,
                            "known_ips": sorted(base.known_source_ips),
                            "vpn_verified": is_verified_vpn,
                            "vpn_name": vpn_match.name if vpn_match else None,
                        },
                    )
                )
                alert_idx += 1

        return alerts

    def detect_unfamiliar_destination_hosts(self, events: List[AuthEvent]) -> List[Alert]:
        """
        Category 6: Sudden access to unfamiliar destination hosts.
        Safety Guarantee: Only evaluated if user has an ESTABLISHED baseline.
        """
        alerts: List[Alert] = []
        user_host_events: Dict[str, List[AuthEvent]] = defaultdict(list)

        for ev in events:
            if not ev.is_valid or ev.timestamp_utc is None or not ev.destination_host:
                continue
            base = self.baseline_repo.get_user_baseline(ev.username)
            if not base.has_established_baseline or not base.known_destination_hosts:
                continue

            norm_host = ev.destination_host.strip().lower()
            if norm_host not in base.known_destination_hosts:
                user_host_events[ev.username.strip().lower()].append(ev)

        alert_idx = 1
        for norm_user, u_evs in user_host_events.items():
            u_evs.sort(key=lambda e: e.timestamp_utc)
            base = self.baseline_repo.get_user_baseline(norm_user)

            # Group within sliding window or evaluate unfamiliar access
            i = 0
            while i < len(u_evs):
                start_time = u_evs[i].timestamp_utc
                window_evs = [
                    e for e in u_evs[i:]
                    if (e.timestamp_utc - start_time).total_seconds() <= self.config.unfamiliar_host_window_seconds
                ]
                unfam_hosts = sorted({e.destination_host.strip().lower() for e in window_evs})

                # Check if threshold reached or if high-value host is targeted
                is_sensitive = any("domain-controller" in h or "dc" in h or "admin" in h for h in unfam_hosts)
                if len(unfam_hosts) >= self.config.unfamiliar_host_threshold or is_sensitive:
                    end_time = window_evs[-1].timestamp_utc

                    # Context evaluation for maintenance windows and roles
                    all_approved = False
                    partial_approved = False
                    active_window_ids = []
                    mismatch_reasons = []

                    if self.context_registry:
                        approved_count = 0
                        for e in window_evs:
                            m_res = self.context_registry.evaluate_event_maintenance(e)
                            if m_res.is_approved_maintenance:
                                approved_count += 1
                                if m_res.active_window_id and m_res.active_window_id not in active_window_ids:
                                    active_window_ids.append(m_res.active_window_id)
                            elif m_res.has_mismatch:
                                mismatch_reasons.extend(m_res.mismatch_reasons)

                        if approved_count == len(window_evs):
                            all_approved = True
                        elif approved_count > 0:
                            partial_approved = True

                    if all_approved:
                        explanation = (
                            f"User '{window_evs[0].username}' accessed unfamiliar destination host(s) "
                            f"({', '.join(unfam_hosts)}) during approved maintenance window(s): {', '.join(active_window_ids)}."
                        )
                        recommended_action = "Routine maintenance activity. Verify scheduled change window closure."
                        severity = "LOW"
                    elif partial_approved:
                        explanation = (
                            f"User '{window_evs[0].username}' accessed unfamiliar destination host(s): {', '.join(unfam_hosts)}. "
                            f"Partial maintenance match ({', '.join(active_window_ids)}), but unapproved access observed: {'; '.join(dict.fromkeys(mismatch_reasons))}."
                        )
                        recommended_action = "Investigate unapproved destination hosts accessed outside maintenance scope."
                        severity = "HIGH" if is_sensitive else "MEDIUM"
                    elif mismatch_reasons:
                        explanation = (
                            f"User '{window_evs[0].username}' accessed unfamiliar destination host(s): {', '.join(unfam_hosts)}. "
                            f"Context Mismatch: {'; '.join(dict.fromkeys(mismatch_reasons))}."
                        )
                        recommended_action = "Investigate unauthorized lateral movement outside maintenance approval."
                        severity = "HIGH" if is_sensitive else "MEDIUM"
                    else:
                        explanation = (
                            f"User '{window_evs[0].username}' accessed unfamiliar destination host(s): "
                            f"{', '.join(unfam_hosts)} (baseline hosts: {', '.join(sorted(base.known_destination_hosts))})."
                        )
                        recommended_action = "Investigate lateral movement risk; verify host access authorization."
                        severity = "HIGH" if is_sensitive else "MEDIUM"

                    alerts.append(
                        Alert(
                            alert_id=f"ALT-R06-{alert_idx:04d}",
                            rule_id="RULE-06-UNFAMILIAR-HOSTS",
                            rule_name="Access to Unfamiliar Destination Host",
                            category="Lateral Movement Anomaly",
                            severity=severity,
                            username=window_evs[0].username,
                            timestamp_utc=end_time,
                            source_ip=", ".join(sorted({e.source_ip for e in window_evs if e.source_ip})),
                            destination_host=", ".join(unfam_hosts),
                            explanation=explanation,
                            recommended_action=recommended_action,
                            evidence_events=list(window_evs),
                            metadata={
                                "unfamiliar_hosts": unfam_hosts,
                                "is_sensitive_target": is_sensitive,
                                "all_approved_maintenance": all_approved,
                                "active_window_ids": active_window_ids,
                                "mismatch_reasons": mismatch_reasons,
                            },
                        )
                    )
                    alert_idx += 1
                    i += len(window_evs)
                else:
                    i += 1

        return alerts

    def run_all(self, events: List[AuthEvent]) -> List[Alert]:
        """Runs all six detection categories and returns consolidated chronological alerts."""
        alerts: List[Alert] = []
        alerts.extend(self.detect_repeated_failures(events))
        alerts.extend(self.detect_burst_then_success(events))
        alerts.extend(self.detect_password_spraying(events))
        alerts.extend(self.detect_unusual_login_times(events))
        alerts.extend(self.detect_unfamiliar_source_ip(events))
        alerts.extend(self.detect_unfamiliar_destination_hosts(events))

        alerts.sort(key=lambda a: a.timestamp_utc)
        return alerts
