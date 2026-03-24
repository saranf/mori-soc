from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
HostStatus = Literal["online", "offline", "unknown"]
SourceName = Literal["fleet", "wazuh", "zabbix", "host_log"]
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
    raw_ref: str | None = None
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Vulnerability:
    vuln_id: str
    host_id: str
    detected_at: datetime
    source: Literal["fleet"] = "fleet"
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