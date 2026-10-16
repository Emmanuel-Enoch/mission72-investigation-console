"""
Context-Aware Alert Detection module for Mission 02.
Provides configurable registries and evaluation engines for:
1. Declared Maintenance Windows (with boundary precision, inverted timestamp rejection, and scope matching)
2. Authorised Helpdesk Accounts and Role-Based Authorisations
3. Recognized Corporate VPN Endpoints and Travelling Employee Context
4. Contextual Risk Reductions and Approval Mismatch Explanations
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from mission72.models import AuthEvent


def parse_iso_or_utc_timestamp(ts: Union[str, datetime]) -> datetime:
    """
    Parses an ISO 8601 string or datetime into a strict UTC datetime.
    Rejects malformed or ambiguous strings.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)

    if not isinstance(ts, str) or not ts.strip():
        raise ValueError("Timestamp cannot be empty or non-string.")

    clean_ts = ts.strip()
    if clean_ts.endswith("Z"):
        clean_ts = clean_ts[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception as e:
        raise ValueError(f"Invalid timestamp format '{ts}': {e}") from e


@dataclass
class MaintenanceWindow:
    """
    Represents an officially declared IT maintenance window.
    Strictly validates start and end timestamps. Inverted windows (start >= end) are rejected.
    """
    window_id: str
    start_time_utc: datetime
    end_time_utc: datetime
    approved_hosts: Set[str] = field(default_factory=set)
    permitted_activities: Set[str] = field(default_factory=set)  # e.g., {'LOGON', 'INTERACTIVE', 'NETWORK'}
    authorized_accounts: Set[str] = field(default_factory=set)
    authorized_roles: Set[str] = field(default_factory=set)  # e.g., {'helpdesk', 'sysadmin'}
    description: str = ""
    change_reference: str = ""

    def __post_init__(self) -> None:
        if not self.window_id or not self.window_id.strip():
            raise ValueError("Maintenance window_id cannot be empty.")
        if self.start_time_utc >= self.end_time_utc:
            raise ValueError(
                f"Maintenance window '{self.window_id}' is inverted or zero duration: "
                f"start ({self.start_time_utc}) must be strictly earlier than end ({self.end_time_utc})."
            )

    def is_active_at(self, ts: datetime) -> bool:
        """
        Boundary check: includes exact start and exact end boundaries [start, end].
        """
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return self.start_time_utc <= ts <= self.end_time_utc

    def matches_host(self, host: str) -> bool:
        """Checks if target host matches approved list or wildcards."""
        if not host:
            return False
        h_low = host.strip().lower()
        for pattern in self.approved_hosts:
            p_low = pattern.strip().lower()
            if p_low == "*" or p_low == h_low:
                return True
            if p_low.endswith("*") and h_low.startswith(p_low[:-1]):
                return True
            if p_low.startswith("*") and h_low.endswith(p_low[1:]):
                return True
        return False

    def matches_activity(self, activity: str) -> bool:
        """Checks if activity type matches permitted types."""
        if not self.permitted_activities:
            return True  # Open if not restricted
        if not activity:
            return False
        act_up = activity.strip().upper()
        return any(act_up == p.strip().upper() or p.strip() == "*" for p in self.permitted_activities)

    def matches_account(self, username: str, user_role: Optional[str] = None) -> bool:
        """Checks if username or user role is authorized for this window."""
        u_low = (username or "").strip().lower()
        r_low = (user_role or "").strip().lower()

        if any(u_low == a.strip().lower() for a in self.authorized_accounts):
            return True
        if r_low and any(r_low == r.strip().lower() for r in self.authorized_roles):
            return True
        return False


@dataclass
class AccountAuthorization:
    """
    Registry entry for an account identity, explicit role, permitted target footprint, and validity.
    """
    username: str
    role: str = "standard_user"  # e.g., 'helpdesk', 'sysadmin', 'contractor', 'standard_user'
    permitted_targets: Set[str] = field(default_factory=set)
    approved_activities: Set[str] = field(default_factory=lambda: {"LOGON", "INTERACTIVE", "NETWORK"})
    is_active: bool = True
    valid_until_utc: Optional[datetime] = None

    def is_valid_at(self, ts: datetime) -> bool:
        if not self.is_active:
            return False
        if self.valid_until_utc is not None:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            else:
                ts = ts.astimezone(timezone.utc)
            return ts <= self.valid_until_utc
        return True

    def is_permitted_target(self, host: str) -> bool:
        if not host:
            return False
        h_low = host.strip().lower()
        if not self.permitted_targets:
            return False
        for pattern in self.permitted_targets:
            p_low = pattern.strip().lower()
            if p_low == "*" or p_low == h_low:
                return True
            if p_low.endswith("*") and h_low.startswith(p_low[:-1]):
                return True
        return False


@dataclass
class VpnEndpoint:
    """
    Recognized corporate VPN gateway or trusted subnet.
    """
    endpoint_id: str
    cidr_or_ip: str
    name: str
    location: str
    is_trusted: bool = True

    def matches_ip(self, ip_str: str) -> bool:
        """Matches IP directly or via CIDR subnet check."""
        if not ip_str:
            return False
        clean_ip = ip_str.strip()
        if clean_ip == self.cidr_or_ip.strip():
            return True
        try:
            net = ipaddress.ip_network(self.cidr_or_ip.strip(), strict=False)
            addr = ipaddress.ip_address(clean_ip)
            return addr in net
        except ValueError:
            return False


@dataclass
class ContextMatchResult:
    """Outcome of evaluating an event or incident against contextual policies."""
    is_approved_maintenance: bool = False
    active_window_id: Optional[str] = None
    change_reference: Optional[str] = None
    matched_role: Optional[str] = None
    is_vpn_verified: bool = False
    vpn_endpoint_name: Optional[str] = None
    vpn_location: Optional[str] = None

    # Mismatch / deficiency details
    has_mismatch: bool = False
    mismatch_reasons: List[str] = field(default_factory=list)
    explanations: List[str] = field(default_factory=list)
    risk_discount_pts: int = 0


class ContextRegistry:
    """
    Central repository for Mission 02 contextual policies:
    - Maintenance windows
    - Account roles and permissions
    - Corporate VPN endpoints and travelling context
    """

    def __init__(self) -> None:
        self.maintenance_windows: Dict[str, MaintenanceWindow] = {}
        self.accounts: Dict[str, AccountAuthorization] = {}
        self.vpn_endpoints: Dict[str, VpnEndpoint] = {}
        self.config_errors: List[str] = []

    def add_maintenance_window(
        self,
        window_id: str,
        start_time: Union[str, datetime],
        end_time: Union[str, datetime],
        approved_hosts: Optional[Set[str]] = None,
        permitted_activities: Optional[Set[str]] = None,
        authorized_accounts: Optional[Set[str]] = None,
        authorized_roles: Optional[Set[str]] = None,
        description: str = "",
        change_reference: str = "",
    ) -> bool:
        """Adds and validates a maintenance window. Returns True on success, False if rejected."""
        try:
            start_dt = parse_iso_or_utc_timestamp(start_time)
            end_dt = parse_iso_or_utc_timestamp(end_time)
            mw = MaintenanceWindow(
                window_id=window_id.strip(),
                start_time_utc=start_dt,
                end_time_utc=end_dt,
                approved_hosts=set(approved_hosts or []),
                permitted_activities=set(permitted_activities or {"LOGON", "INTERACTIVE", "NETWORK"}),
                authorized_accounts={a.strip().lower() for a in (authorized_accounts or [])},
                authorized_roles={r.strip().lower() for r in (authorized_roles or [])},
                description=description,
                change_reference=change_reference,
            )
            self.maintenance_windows[mw.window_id] = mw
            return True
        except Exception as e:
            err = f"Failed to register maintenance window '{window_id}': {e}"
            self.config_errors.append(err)
            return False

    def add_account(
        self,
        username: str,
        role: str = "standard_user",
        permitted_targets: Optional[Set[str]] = None,
        approved_activities: Optional[Set[str]] = None,
        is_active: bool = True,
        valid_until: Optional[Union[str, datetime]] = None,
    ) -> bool:
        """Registers an account and role authorization."""
        if not username or not username.strip():
            self.config_errors.append("Account registration rejected: username is empty.")
            return False

        valid_until_dt = None
        if valid_until is not None:
            try:
                valid_until_dt = parse_iso_or_utc_timestamp(valid_until)
            except Exception as e:
                self.config_errors.append(f"Account '{username}' expiration date invalid: {e}")
                return False

        norm_user = username.strip().lower()
        self.accounts[norm_user] = AccountAuthorization(
            username=norm_user,
            role=role.strip().lower(),
            permitted_targets=set(permitted_targets or []),
            approved_activities=set(approved_activities or {"LOGON", "INTERACTIVE", "NETWORK"}),
            is_active=is_active,
            valid_until_utc=valid_until_dt,
        )
        return True

    def add_vpn_endpoint(
        self,
        endpoint_id: str,
        cidr_or_ip: str,
        name: str,
        location: str,
        is_trusted: bool = True,
    ) -> bool:
        """Registers a recognized corporate VPN endpoint."""
        try:
            ep = VpnEndpoint(
                endpoint_id=endpoint_id.strip(),
                cidr_or_ip=cidr_or_ip.strip(),
                name=name.strip(),
                location=location.strip(),
                is_trusted=is_trusted,
            )
            self.vpn_endpoints[ep.endpoint_id] = ep
            return True
        except Exception as e:
            self.config_errors.append(f"Failed to register VPN endpoint '{endpoint_id}': {e}")
            return False

    def get_account(self, username: str) -> Optional[AccountAuthorization]:
        if not username:
            return None
        return self.accounts.get(username.strip().lower())

    def match_vpn(self, ip_str: str) -> Optional[VpnEndpoint]:
        """Matches a source IP against corporate VPN registry."""
        if not ip_str:
            return None
        clean_ip = ip_str.strip()
        for ep in self.vpn_endpoints.values():
            if ep.matches_ip(clean_ip):
                return ep
        return None

    def evaluate_event_maintenance(self, event: AuthEvent) -> ContextMatchResult:
        """
        Evaluates a single authentication event against maintenance windows and account authorizations.
        Strict verification of:
        1. Account identity and active role authorization
        2. Maintenance window timing (including exact boundary)
        3. Approved target host
        4. Permitted activity
        """
        res = ContextMatchResult()
        if not event.is_valid or event.timestamp_utc is None:
            res.has_mismatch = True
            res.mismatch_reasons.append("Event is malformed or has invalid timestamp; cannot evaluate context.")
            return res

        u_norm = (event.username or "").strip().lower()
        acct = self.accounts.get(u_norm)
        user_role = acct.role if acct else "standard_user"
        res.matched_role = user_role

        # Check account authorization validity
        if acct and not acct.is_valid_at(event.timestamp_utc):
            res.has_mismatch = True
            res.mismatch_reasons.append(f"Account authorization for '{event.username}' has expired or is inactive.")

        # Find any active maintenance windows at event timestamp
        active_windows = [
            mw for mw in self.maintenance_windows.values()
            if mw.is_active_at(event.timestamp_utc)
        ]

        if not active_windows:
            # Not in any maintenance window
            if user_role == "helpdesk":
                res.has_mismatch = True
                res.mismatch_reasons.append(
                    f"Helpdesk user '{event.username}' accessed '{event.destination_host}' outside any declared maintenance window."
                )
            return res

        # We have at least one active window; verify if any window fully matches all 4 constraints
        best_partial_mismatches: List[str] = []

        for mw in active_windows:
            window_mismatches: List[str] = []

            # 1. Account / Role check
            if not mw.matches_account(u_norm, user_role):
                window_mismatches.append(
                    f"User '{event.username}' (role: {user_role}) is not authorized for window '{mw.window_id}'."
                )

            # 2. Target host check
            if not mw.matches_host(event.destination_host):
                window_mismatches.append(
                    f"Destination host '{event.destination_host}' is not on approved host list for window '{mw.window_id}'."
                )

            # 3. Activity check
            if not mw.matches_activity(event.event_type):
                window_mismatches.append(
                    f"Activity '{event.event_type}' is not permitted in window '{mw.window_id}'."
                )

            if not window_mismatches:
                # FULL MATCH
                res.is_approved_maintenance = True
                res.active_window_id = mw.window_id
                res.change_reference = mw.change_reference
                res.explanations.append(
                    f"Activity approved under Maintenance Window '{mw.window_id}' "
                    f"({mw.change_reference or mw.description or 'Scheduled Change'}) for target '{event.destination_host}'."
                )
                return res
            else:
                best_partial_mismatches.extend(window_mismatches)

        # Active window exists, but requirements mismatched
        res.has_mismatch = True
        res.mismatch_reasons = best_partial_mismatches
        return res

    def evaluate_event_vpn(self, event: AuthEvent) -> ContextMatchResult:
        """
        Evaluates source IP against company VPN registry.
        Distinguishes:
        - Verified company VPN endpoint
        - Untrusted / unverified endpoint
        - Missing VPN data
        """
        res = ContextMatchResult()
        if not event.source_ip:
            res.has_mismatch = True
            res.mismatch_reasons.append("Missing source IP; cannot establish network/VPN context.")
            return res

        vpn = self.match_vpn(event.source_ip)
        if vpn is not None:
            if vpn.is_trusted:
                res.is_vpn_verified = True
                res.vpn_endpoint_name = vpn.name
                res.vpn_location = vpn.location
                res.explanations.append(
                    f"Source IP {event.source_ip} matches verified corporate VPN gateway '{vpn.name}' ({vpn.location})."
                )
            else:
                res.has_mismatch = True
                res.mismatch_reasons.append(
                    f"Source IP {event.source_ip} matches registered but UNTRUSTED endpoint '{vpn.name}'."
                )
        return res

    def evaluate_incident_context(
        self,
        alerts: List[Any],
        evidence_events: List[AuthEvent],
    ) -> ContextMatchResult:
        """
        Evaluates an entire incident cluster against contextual policies:
        - Analyzes maintenance window coverage across all evidence rows
        - Analyzes corporate VPN presence and consistency
        - Calculates appropriate explainable risk discount
        """
        overall = ContextMatchResult()
        if not evidence_events:
            return overall

        maintenance_matches = 0
        maintenance_mismatches: List[str] = []
        matched_windows: Set[str] = set()

        vpn_matches = 0
        vpn_names: Set[str] = set()
        vpn_mismatches: List[str] = []

        for ev in evidence_events:
            m_res = self.evaluate_event_maintenance(ev)
            if m_res.is_approved_maintenance:
                maintenance_matches += 1
                if m_res.active_window_id:
                    matched_windows.add(m_res.active_window_id)
            elif m_res.has_mismatch and m_res.mismatch_reasons:
                maintenance_mismatches.extend(m_res.mismatch_reasons)

            v_res = self.evaluate_event_vpn(ev)
            if v_res.is_vpn_verified:
                vpn_matches += 1
                if v_res.vpn_endpoint_name:
                    vpn_names.add(v_res.vpn_endpoint_name)
            elif v_res.has_mismatch and v_res.mismatch_reasons:
                vpn_mismatches.extend(v_res.mismatch_reasons)

        total_ev = len(evidence_events)

        # 1. Maintenance evaluation
        if maintenance_matches > 0:
            if maintenance_matches == total_ev and not maintenance_mismatches:
                # 100% of events occurred under approved maintenance
                overall.is_approved_maintenance = True
                overall.active_window_id = ", ".join(sorted(matched_windows))
                # Substantial risk discount (up to 35 pts) to prevent false alerts on authorized helpdesk/maintenance
                overall.risk_discount_pts += 35
                overall.explanations.append(
                    f"All {total_ev} activity events match approved Maintenance Window(s): {overall.active_window_id} (-35 pts)."
                )
            else:
                # Scope violation: unapproved hosts, roles, or actions detected!
                overall.has_mismatch = True
                partial_pct = int((maintenance_matches / total_ev) * 100)
                overall.explanations.append(
                    f"Partial maintenance coverage ({maintenance_matches}/{total_ev} events, {partial_pct}%), but unapproved activity detected. No maintenance discount granted."
                )
                if maintenance_mismatches:
                    overall.mismatch_reasons.extend(dict.fromkeys(maintenance_mismatches))
        elif maintenance_mismatches:
            overall.has_mismatch = True
            overall.mismatch_reasons.extend(dict.fromkeys(maintenance_mismatches))

        # 2. VPN evaluation
        has_unfamiliar_ip_alert = any(getattr(a, "rule_id", "") == "RULE-05-UNFAMILIAR-IP" for a in alerts)
        if vpn_matches > 0:
            if vpn_matches == total_ev or (has_unfamiliar_ip_alert and vpn_matches >= 1):
                overall.is_vpn_verified = True
                overall.vpn_endpoint_name = ", ".join(sorted(vpn_names))
                # Mitigate unfamiliar IP penalty without blindly trusting everything
                vpn_discount = 15 if has_unfamiliar_ip_alert else 5
                overall.risk_discount_pts += vpn_discount
                overall.explanations.append(
                    f"Verified Corporate VPN gateway connection ({overall.vpn_endpoint_name}) observed; "
                    f"mitigates unfamiliar location risk (-{vpn_discount} pts)."
                )
        elif vpn_mismatches:
            overall.has_mismatch = True
            overall.mismatch_reasons.extend(dict.fromkeys(vpn_mismatches))

        return overall

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContextRegistry":
        """Builds a ContextRegistry from a configuration dictionary with complete error tracking."""
        reg = cls()

        # 1. Maintenance Windows
        for item in data.get("maintenance_windows", []):
            reg.add_maintenance_window(
                window_id=item.get("window_id", ""),
                start_time=item.get("start_time", ""),
                end_time=item.get("end_time", ""),
                approved_hosts=set(item.get("approved_hosts", [])),
                permitted_activities=set(item.get("permitted_activities", [])),
                authorized_accounts=set(item.get("authorized_accounts", [])),
                authorized_roles=set(item.get("authorized_roles", [])),
                description=item.get("description", ""),
                change_reference=item.get("change_reference", ""),
            )

        # 2. Account Authorizations
        for item in data.get("accounts", []):
            reg.add_account(
                username=item.get("username", ""),
                role=item.get("role", "standard_user"),
                permitted_targets=set(item.get("permitted_targets", [])),
                approved_activities=set(item.get("approved_activities", [])),
                is_active=item.get("is_active", True),
                valid_until=item.get("valid_until"),
            )

        # 3. VPN Endpoints
        for item in data.get("vpn_endpoints", []):
            reg.add_vpn_endpoint(
                endpoint_id=item.get("endpoint_id", ""),
                cidr_or_ip=item.get("cidr_or_ip", ""),
                name=item.get("name", ""),
                location=item.get("location", ""),
                is_trusted=item.get("is_trusted", True),
            )

        return reg

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "ContextRegistry":
        """Loads and parses context configuration from a JSON file."""
        p = Path(path)
        if not p.exists():
            reg = cls()
            reg.config_errors.append(f"Context config file does not exist: {path}")
            return reg
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


def create_default_context_registry() -> ContextRegistry:
    """
    Creates a rich, realistic default context configuration with synthetic enterprise policies:
    - Scheduled server maintenance windows (e.g. database cluster patching)
    - Authorized helpdesk and sysadmin roles
    - Corporate VPN gateways (London, New York, Tokyo)
    """
    reg = ContextRegistry()

    # Maintenance Window 1: Weekend Infrastructure Patching
    reg.add_maintenance_window(
        window_id="MW-2026-10-PATCH",
        start_time="2026-10-12T00:00:00Z",
        end_time="2026-10-12T06:00:00Z",
        approved_hosts={"srv-app01", "srv-db01", "srv-db02", "ws-*"},
        permitted_activities={"LOGON", "INTERACTIVE", "NETWORK"},
        authorized_roles={"helpdesk", "sysadmin"},
        authorized_accounts={"frank.helpdesk", "sarah.admin"},
        description="Q4 Monthly Database & Workstation Patching",
        change_reference="CHG-49201",
    )

    # Maintenance Window 2: Emergency Network Maintenance
    reg.add_maintenance_window(
        window_id="MW-2026-10-EMERGENCY",
        start_time="2026-10-15T02:00:00Z",
        end_time="2026-10-15T05:00:00Z",
        approved_hosts={"corp-net01", "corp-net02", "edge-router01"},
        permitted_activities={"LOGON", "NETWORK"},
        authorized_roles={"netadmin", "sysadmin"},
        authorized_accounts={"alex.network"},
        description="Emergency Core Switch Firmware Upgrade",
        change_reference="CHG-49880",
    )

    # Accounts and Roles
    reg.add_account("frank.helpdesk", role="helpdesk", permitted_targets={"srv-*", "ws-*"})
    reg.add_account("sarah.admin", role="sysadmin", permitted_targets={"*"})
    reg.add_account("alex.network", role="netadmin", permitted_targets={"corp-net*", "edge-*"})
    reg.add_account("bob.jones", role="standard_user", permitted_targets={"ws-01"})
    reg.add_account("alice.smith", role="standard_user", permitted_targets={"ws-02"})
    reg.add_account("dana.scully", role="special_agent", permitted_targets={"ws-04"})

    # Corporate VPN Endpoints
    reg.add_vpn_endpoint(
        endpoint_id="VPN-LON-01",
        cidr_or_ip="198.51.100.200",
        name="London EMEA Gateway",
        location="London, United Kingdom",
        is_trusted=True,
    )
    reg.add_vpn_endpoint(
        endpoint_id="VPN-NYC-01",
        cidr_or_ip="198.51.100.201",
        name="New York Americas Gateway",
        location="New York, United States",
        is_trusted=True,
    )
    reg.add_vpn_endpoint(
        endpoint_id="VPN-TYO-01",
        cidr_or_ip="198.51.100.202",
        name="Tokyo APAC Gateway",
        location="Tokyo, Japan",
        is_trusted=True,
    )
    # Untrusted Commercial VPN / Proxy Gateway (for testing negative scenarios)
    reg.add_vpn_endpoint(
        endpoint_id="VPN-UNTRUSTED-01",
        cidr_or_ip="203.0.113.250",
        name="Commercial Proxy Service",
        location="Frankfurt, Germany",
        is_trusted=False,
    )

    return reg
