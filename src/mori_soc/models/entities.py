from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
HostStatus = Literal["online", "offline", "unknown"]
SourceName = Literal["fleet", "wazuh", "zabbix", "host_log", "trivy"]
AliasSource = SourceName
SyncStatus = Literal["success", "error", "running"]


@dataclass(slots=True)
class Host:
    host_id: str
    hostname: str
    platform: str | None = None
    primary_ip: str | None = None
    status: HostStatus = "unknown"
    risk_score: int = 0
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


@dataclass(slots=True)
class HostAlias:
    alias_id: str
    host_id: str
    source: AliasSource
    alias_type: str
    alias_value: str
    confidence: float = 1.0
    is_primary: bool = False
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


@dataclass(slots=True)
class Alert:
    alert_id: str
    source: Literal["wazuh", "zabbix", "host_log"]
    observed_at: datetime
    message: str
    host_id: str | None = None
    source_event_id: str | None = None
    severity: Severity = "info"
    original_severity: str | None = None
    rule_name: str | None = None
    rule_id: str | None = None
    resolved_at: datetime | None = None
    raw_ref: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Vulnerability:
    vuln_id: str
    host_id: str
    detected_at: datetime
    source: Literal["fleet", "trivy"] = "fleet"
    cve: str | None = None
    severity: Severity = "info"
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    resolved_at: datetime | None = None
    raw_ref: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class QueryResult:
    query_result_id: str
    host_id: str
    observed_at: datetime
    result_json: dict[str, Any]
    source: Literal["fleet"] = "fleet"
    query_name: str | None = None
    query_text: str | None = None
    raw_ref: str | None = None


@dataclass(slots=True)
class HostObservation:
    observation_id: str
    source: Literal["fleet", "zabbix", "host_log"]
    host_id: str
    observation_type: str
    metric_name: str
    observed_at: datetime
    metric_value: str | None = None
    unit: str | None = None
    severity: Severity | None = None
    raw_ref: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SourceSync:
    source: SourceName
    status: SyncStatus
    last_sync_at: datetime
    last_success_at: datetime | None = None
    last_error_at: datetime | None = None
    message: str | None = None
    records_collected: int = 0
    envelopes_normalized: int = 0
    entities_saved: int = 0


# ---------------------------------------------------------------------------
# Phase 2 — Compliance / Audit entities
# ---------------------------------------------------------------------------

ControlCheckStatus = Literal["pass", "fail", "warning", "not_applicable", "not_checked"]
EntityType = Literal["host", "account", "network", "application", "policy"]


@dataclass(slots=True)
class ControlCheckResult:
    """통제 항목 점검 결과 — ISMS-P / ISO 27001 통제 항목에 대한 자동/수동 점검 기록."""

    check_id: str
    control_id: str          # e.g. "A.8.1" (ISO 27001) or "2.5.1" (ISMS-P)
    entity_type: EntityType
    entity_id: str           # host_id, account_id, etc.
    status: ControlCheckStatus
    checked_at: datetime
    evidence_refs: list[str] = field(default_factory=list)   # URIs / file paths
    owner: str | None = None
    note: str | None = None
    remediation_due_at: datetime | None = None
    resolved_at: datetime | None = None


# ---------------------------------------------------------------------------
# Phase 2 — Directory / Identity entities (LDAP/AD)
# ---------------------------------------------------------------------------

AccountStatus = Literal["active", "disabled", "locked", "expired"]


@dataclass(slots=True)
class DirectoryAccount:
    """LDAP/AD 사용자 계정."""

    account_id: str
    username: str
    display_name: str | None = None
    email: str | None = None
    department: str | None = None
    status: AccountStatus = "active"
    is_privileged: bool = False
    last_login_at: datetime | None = None
    password_last_set: datetime | None = None
    created_at: datetime | None = None


@dataclass(slots=True)
class PrivilegeBinding:
    """계정-권한 바인딩 (sudo, admin group 등)."""

    binding_id: str
    account_id: str
    privilege_type: str        # e.g. "sudo", "domain_admin", "db_admin"
    target: str | None = None  # e.g. hostname, database name
    granted_at: datetime | None = None
    expires_at: datetime | None = None
    granted_by: str | None = None


@dataclass(slots=True)
class GroupMembership:
    """계정-그룹 매핑."""

    membership_id: str
    account_id: str
    group_name: str
    source: str = "ldap"       # ldap | ad | local
    synced_at: datetime | None = None


@dataclass(slots=True)
class AccountObservation:
    """계정 관련 이벤트 관측 (로그인 실패, 비밀번호 변경 등)."""

    observation_id: str
    account_id: str
    observation_type: str      # e.g. "login_failure", "password_change", "privilege_escalation"
    source: str = "ldap"
    observed_at: datetime | None = None
    detail: str | None = None
    severity: Severity | None = None