"""
Incident grouping engine and explainable 0–100 risk scoring for Mission 72.

Guarantees:
- Stable rule IDs, evidence references, severity, explanations, and triage recommendations are preserved.
- Risk scores are explainable, bounded strictly to [0, 100], and supported by a clear breakdown.
- Evidence rows preserve complete source file and row number provenance.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from mission72.baseline import BaselineRepository
from mission72.detections import Alert
from mission72.models import AuthEvent, BaselineStatus

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEVERITY_BASE_SCORES = {"CRITICAL": 75, "HIGH": 55, "MEDIUM": 35, "LOW": 15}


@dataclass
class EvidenceRow:
    """Represents a discrete raw log row associated with an incident."""
    source_file: str
    row_number: int
    timestamp_utc: str
    username: str
    source_ip: str
    destination_host: str
    event_type: str
    result: str
    logon_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_file": self.source_file,
            "row_number": self.row_number,
            "timestamp_utc": self.timestamp_utc,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_host": self.destination_host,
            "event_type": self.event_type,
            "result": self.result,
            "logon_type": self.logon_type,
        }


@dataclass
class Incident:
    """Consolidated security incident grouping correlated alerts and evidence."""
    incident_id: str
    title: str
    primary_entity: str
    severity: str
    risk_score: int
    risk_explanation: str
    rule_ids: List[str]
    categories: List[str]
    alerts: List[Alert]
    evidence_records: List[EvidenceRow]
    source_ips: List[str]
    destination_hosts: List[str]
    start_time_utc: datetime
    end_time_utc: datetime
    triage_summary: str
    recommended_action: str
    context_status: str = "NORMAL_EVALUATION"
    context_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "primary_entity": self.primary_entity,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "risk_explanation": self.risk_explanation,
            "rule_ids": self.rule_ids,
            "categories": self.categories,
            "alert_count": len(self.alerts),
            "evidence_count": len(self.evidence_records),
            "source_ips": self.source_ips,
            "destination_hosts": self.destination_hosts,
            "start_time_utc": self.start_time_utc.isoformat(),
            "end_time_utc": self.end_time_utc.isoformat(),
            "triage_summary": self.triage_summary,
            "recommended_action": self.recommended_action,
            "context_status": self.context_status,
            "context_summary": self.context_summary,
        }


@dataclass
class UserRiskProfile:
    """Summary risk profile for an individual user account."""
    username: str
    risk_score: int
    baseline_status: str
    incident_count: int
    highest_severity: str
    rules_triggered: List[str]
    score_rationale: str


def compute_incident_risk_score(
    alerts: List[Alert],
    evidence_events: List[AuthEvent],
    context_registry: Optional[Any] = None,
) -> Tuple[int, str]:
    """
    Computes an explainable, deterministic risk score from 0 to 100 based on:
    - Base severity of highest alert (CRITICAL=75, HIGH=55, MEDIUM=35, LOW=15)
    - Multi-category bonus (+10 for 2 categories, +20 for 3+ categories)
    - Evidence volume bonus (+5 for >5 events, +10 for >10 events)
    - Sensitive target bonus (+10 if high-value host is targeted)
    - Contextual mitigation discount (up to -35 pts for verified maintenance or VPN)
    """
    if not alerts:
        return 0, "No alerts (Risk: 0)"

    # 1. Base score from max severity
    highest_sev = "LOW"
    max_rank = 0
    for a in alerts:
        rank = SEVERITY_ORDER.get(a.severity.upper(), 1)
        if rank > max_rank:
            max_rank = rank
            highest_sev = a.severity.upper()

    base_score = SEVERITY_BASE_SCORES.get(highest_sev, 20)

    # 2. Multi-category bonus
    categories = {a.category for a in alerts}
    cat_bonus = 0
    if len(categories) >= 3:
        cat_bonus = 20
    elif len(categories) == 2:
        cat_bonus = 10

    # 3. Evidence volume bonus
    ev_count = len(evidence_events)
    vol_bonus = 0
    if ev_count >= 10:
        vol_bonus = 10
    elif ev_count >= 5:
        vol_bonus = 5

    # 4. Sensitive target bonus
    # Only genuinely high-privilege assets qualify: domain controllers, admin hosts,
    # security-ops systems, and secrets/vault stores.
    # "mail-gateway" is intentionally excluded — a mail relay is not a privileged admin
    # asset, and including it caused password-spray incidents (all evidence pointing at
    # a mail gateway) to incorrectly earn this bonus.
    # "auth" is intentionally excluded — it is too broad a substring and would match
    # unrelated hostnames (e.g. "pathserver", "marathon-auth-proxy").
    sensitive_keywords = ["domain-controller", "-dc", "dc01", "dc02", "admin", "sec-ops", "vault"]
    has_sensitive = False
    for ev in evidence_events:
        host_low = (ev.destination_host or "").lower()
        if any(kw in host_low for kw in sensitive_keywords):
            has_sensitive = True
            break
    sens_bonus = 10 if has_sensitive else 0

    # 5. Contextual mitigation discount
    context_discount = 0
    context_note = ""
    if context_registry:
        c_res = context_registry.evaluate_incident_context(alerts, evidence_events)
        context_discount = c_res.risk_discount_pts
        if context_discount > 0:
            context_note = f" | Context Mitigation (-{context_discount} pts: {'; '.join(c_res.explanations)})"
        elif c_res.has_mismatch and c_res.mismatch_reasons:
            context_note = f" | Context Audit (0 pts discount: {'; '.join(c_res.mismatch_reasons[:2])})"

    raw_total = base_score + cat_bonus + vol_bonus + sens_bonus - context_discount
    clamped_score = max(0, min(100, raw_total))

    explanation = (
        f"Base Severity ({highest_sev}): {base_score} pts | "
        f"Multi-Category ({len(categories)} categories): +{cat_bonus} pts | "
        f"Evidence Volume ({ev_count} rows): +{vol_bonus} pts | "
        f"Sensitive Asset Targeting: +{sens_bonus} pts{context_note} "
        f"-> Total Score: {clamped_score}/100"
    )

    return clamped_score, explanation


def group_alerts_into_incidents(
    alerts: List[Alert],
    clustering_window_seconds: int = 7200,  # 2 hours
    context_registry: Optional[Any] = None,
) -> List[Incident]:
    """
    Groups alerts into coherent security incidents based on primary entity
    (username or source IP for password spraying) within a temporal clustering window.
    """
    if not alerts:
        return []

    # Sort alerts chronologically
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp_utc)

    # Group keys: username (or IP for password spray)
    entity_groups: Dict[str, List[Alert]] = defaultdict(list)
    for a in sorted_alerts:
        if a.rule_id == "RULE-03-PASSWORD-SPRAY":
            entity_key = f"SOURCE-IP:{a.source_ip}"
        else:
            entity_key = f"USER:{a.username.strip().lower()}"
        entity_groups[entity_key].append(a)

    incidents: List[Incident] = []
    inc_idx = 1

    for entity_key, g_alerts in entity_groups.items():
        g_alerts.sort(key=lambda a: a.timestamp_utc)

        # Cluster temporally within entity
        clusters: List[List[Alert]] = []
        current_cluster: List[Alert] = [g_alerts[0]]

        for a in g_alerts[1:]:
            last_ts = current_cluster[-1].timestamp_utc
            if (a.timestamp_utc - last_ts).total_seconds() <= clustering_window_seconds:
                current_cluster.append(a)
            else:
                clusters.append(current_cluster)
                current_cluster = [a]
        if current_cluster:
            clusters.append(current_cluster)

        # Build Incident for each cluster
        for cluster in clusters:
            # Deduplicate and sort evidence events
            seen_ev_keys: Set[Tuple[str, int]] = set()
            all_evidence: List[AuthEvent] = []
            for a in cluster:
                for ev in a.evidence_events:
                    k = (ev.source_file, ev.row_number)
                    if k not in seen_ev_keys:
                        seen_ev_keys.add(k)
                        all_evidence.append(ev)

            # Sort evidence chronologically
            all_evidence.sort(key=lambda e: (e.timestamp_utc or datetime.min.replace(tzinfo=timezone.utc), e.row_number))

            evidence_rows = [
                EvidenceRow(
                    source_file=ev.source_file,
                    row_number=ev.row_number,
                    timestamp_utc=ev.timestamp_utc.isoformat() if ev.timestamp_utc else ev.timestamp_raw,
                    username=ev.username,
                    source_ip=ev.source_ip,
                    destination_host=ev.destination_host,
                    event_type=ev.event_type,
                    result=ev.result,
                    logon_type=ev.logon_type,
                )
                for ev in all_evidence
            ]

            # Highest severity in cluster
            highest_sev = "LOW"
            max_rank = 0
            for a in cluster:
                rank = SEVERITY_ORDER.get(a.severity.upper(), 1)
                if rank > max_rank:
                    max_rank = rank
                    highest_sev = a.severity.upper()

            # Rule IDs and Categories
            rule_ids = sorted({a.rule_id for a in cluster})
            categories = sorted({a.category for a in cluster})
            source_ips = sorted({ev.source_ip for ev in all_evidence if ev.source_ip})
            dest_hosts = sorted({ev.destination_host for ev in all_evidence if ev.destination_host})

            start_time = cluster[0].timestamp_utc
            end_time = cluster[-1].timestamp_utc
            if all_evidence and all_evidence[0].timestamp_utc:
                start_time = min(start_time, all_evidence[0].timestamp_utc)
            if all_evidence and all_evidence[-1].timestamp_utc:
                end_time = max(end_time, all_evidence[-1].timestamp_utc)

            # Calculate explainable risk score
            score, explanation = compute_incident_risk_score(cluster, all_evidence, context_registry=context_registry)

            # Context status and summary
            context_status = "NORMAL_EVALUATION"
            context_summary = "Standard evaluation (no contextual mitigation active)."
            if context_registry:
                c_res = context_registry.evaluate_incident_context(cluster, all_evidence)
                if c_res.is_approved_maintenance:
                    context_status = "APPROVED_MAINTENANCE"
                    context_summary = "; ".join(c_res.explanations)
                elif c_res.is_vpn_verified:
                    context_status = "VERIFIED_VPN"
                    context_summary = "; ".join(c_res.explanations)
                elif c_res.has_mismatch:
                    context_status = "APPROVAL_MISMATCH"
                    context_summary = "; ".join(c_res.mismatch_reasons)
                elif c_res.explanations:
                    context_summary = "; ".join(c_res.explanations)

            # Construct readable title & entity
            if entity_key.startswith("SOURCE-IP:"):
                ip_val = entity_key.split(":", 1)[1]
                entity_name = f"External IP {ip_val}"
                title = f"Password Spray Campaign from {ip_val}"
            else:
                user_val = cluster[0].username
                entity_name = user_val
                title = f"Suspicious Activity on Account '{user_val}' ({', '.join(rule_ids)})"

            # Triage & Actions
            triage_recs = [a.recommended_action for a in cluster if a.recommended_action]
            unique_actions = list(dict.fromkeys(triage_recs))
            recommended_action = " | ".join(unique_actions) if unique_actions else "Review authentication logs and contact account owner."

            triage_summary = (
                f"Incident involves {len(cluster)} correlated alerts across {len(categories)} categories "
                f"with {len(evidence_rows)} evidence rows spanning {int((end_time - start_time).total_seconds())}s."
            )

            incidents.append(
                Incident(
                    incident_id=f"INC-{inc_idx:04d}",
                    title=title,
                    primary_entity=entity_name,
                    severity=highest_sev,
                    risk_score=score,
                    risk_explanation=explanation,
                    rule_ids=rule_ids,
                    categories=categories,
                    alerts=cluster,
                    evidence_records=evidence_rows,
                    source_ips=source_ips,
                    destination_hosts=dest_hosts,
                    start_time_utc=start_time,
                    end_time_utc=end_time,
                    triage_summary=triage_summary,
                    recommended_action=recommended_action,
                    context_status=context_status,
                    context_summary=context_summary,
                )
            )
            inc_idx += 1

    # Sort incidents by risk score descending
    incidents.sort(key=lambda inc: (inc.risk_score, inc.start_time_utc), reverse=True)
    return incidents


def compute_user_risk_profiles(
    incidents: List[Incident],
    baseline_repo: BaselineRepository,
    all_events: Optional[List[AuthEvent]] = None,
    context_registry: Optional[Any] = None,
) -> List[UserRiskProfile]:
    """
    Computes consolidated per-user risk scores (0–100) across all incidents.
    """
    user_incidents: Dict[str, List[Incident]] = defaultdict(list)
    for inc in incidents:
        # Check primary entity or evidence usernames
        for ev in inc.evidence_records:
            if ev.username:
                user_incidents[ev.username.strip().lower()].append(inc)

    # Also include baseline users with 0 incidents for complete visibility
    all_users = set(user_incidents.keys())
    for base in baseline_repo.all_baselines():
        all_users.add(base.username.strip().lower())

    profiles: List[UserRiskProfile] = []

    for norm_user in all_users:
        incs = user_incidents.get(norm_user, [])
        base = baseline_repo.get_user_baseline(norm_user)
        display_name = base.username if base.username else norm_user

        if not incs:
            profiles.append(
                UserRiskProfile(
                    username=display_name,
                    risk_score=0,
                    baseline_status=base.status.value,
                    incident_count=0,
                    highest_severity="NONE",
                    rules_triggered=[],
                    score_rationale="No suspicious alerts or anomalies detected (Risk: 0/100).",
                )
            )
            continue

        # Max incident score + small multi-incident factor capped at 100
        max_inc_score = max(inc.risk_score for inc in incs)
        multi_inc_bonus = min(15, (len(incs) - 1) * 5)
        final_score = min(100, max_inc_score + multi_inc_bonus)

        rules = sorted({r for inc in incs for r in inc.rule_ids})
        highest_sev = "LOW"
        max_rank = 0
        for inc in incs:
            rank = SEVERITY_ORDER.get(inc.severity.upper(), 1)
            if rank > max_rank:
                max_rank = rank
                highest_sev = inc.severity.upper()

        rationale = (
            f"Highest incident score: {max_inc_score} | "
            f"Multi-incident bonus ({len(incs)} incidents): +{multi_inc_bonus} | "
            f"Rules triggered: {', '.join(rules)} -> Final Score: {final_score}/100"
        )

        profiles.append(
            UserRiskProfile(
                username=display_name,
                risk_score=final_score,
                baseline_status=base.status.value,
                incident_count=len(incs),
                highest_severity=highest_sev,
                rules_triggered=rules,
                score_rationale=rationale,
            )
        )

    profiles.sort(key=lambda p: (p.risk_score, p.incident_count), reverse=True)
    return profiles
