from __future__ import annotations

from decimal import Decimal
from typing import Any

from mori_soc.models import (
    AccountObservation,
    Alert,
    ControlCheckResult,
    DirectoryAccount,
    GroupMembership,
    Host,
    HostAlias,
    HostObservation,
    PrivilegeBinding,
    QueryResult,
    SourceSync,
    Vulnerability,
)
from mori_soc.services.query_service import InMemoryQueryStore

from .base import BaseRepository, RepositorySnapshot

try:
    import psycopg
    from psycopg.types.json import Jsonb

    PSYCOPG_AVAILABLE = True
except ImportError:  # pragma: no cover - import guard only
    psycopg = None
    Jsonb = None
    PSYCOPG_AVAILABLE = False


def snapshot_to_query_store(snapshot: RepositorySnapshot) -> InMemoryQueryStore:
    return InMemoryQueryStore(
        hosts=list(snapshot.hosts),
        alerts=list(snapshot.alerts),
        vulnerabilities=list(snapshot.vulnerabilities),
        query_results=list(snapshot.query_results),
        observations=list(snapshot.observations),
        host_aliases=list(snapshot.host_aliases),
        source_syncs=list(snapshot.source_syncs),
        control_checks=list(snapshot.control_checks),
        directory_accounts=list(snapshot.directory_accounts),
        privilege_bindings=list(snapshot.privilege_bindings),
        group_memberships=list(snapshot.group_memberships),
        account_observations=list(snapshot.account_observations),
    )


class PostgresRepository(BaseRepository):
    def __init__(self, dsn: str) -> None:
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg is not installed. Install psycopg to use PostgresRepository.")
        self.dsn = dsn

    def save(self, entity: object) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            if isinstance(entity, Host):
                cur.execute(
                    """
                    INSERT INTO hosts (
                        host_id, hostname, platform, primary_ip, status, risk_score, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (host_id) DO UPDATE SET
                        hostname = COALESCE(EXCLUDED.hostname, hosts.hostname),
                        platform = COALESCE(EXCLUDED.platform, hosts.platform),
                        primary_ip = COALESCE(EXCLUDED.primary_ip, hosts.primary_ip),
                        status = CASE WHEN EXCLUDED.status = 'unknown' THEN hosts.status ELSE EXCLUDED.status END,
                        risk_score = GREATEST(hosts.risk_score, EXCLUDED.risk_score),
                        first_seen_at = CASE
                            WHEN hosts.first_seen_at IS NULL THEN EXCLUDED.first_seen_at
                            WHEN EXCLUDED.first_seen_at IS NULL THEN hosts.first_seen_at
                            ELSE LEAST(hosts.first_seen_at, EXCLUDED.first_seen_at)
                        END,
                        last_seen_at = CASE
                            WHEN hosts.last_seen_at IS NULL THEN EXCLUDED.last_seen_at
                            WHEN EXCLUDED.last_seen_at IS NULL THEN hosts.last_seen_at
                            ELSE GREATEST(hosts.last_seen_at, EXCLUDED.last_seen_at)
                        END,
                        updated_at = now()
                    """,
                    (
                        entity.host_id,
                        entity.hostname,
                        entity.platform,
                        entity.primary_ip,
                        entity.status,
                        entity.risk_score,
                        entity.first_seen_at,
                        entity.last_seen_at,
                    ),
                )
                return

            if isinstance(entity, HostAlias):
                cur.execute(
                    """
                    INSERT INTO host_aliases (
                        alias_id, host_id, source, alias_type, alias_value, confidence, is_primary, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source, alias_type, alias_value) DO UPDATE SET
                        host_id = EXCLUDED.host_id,
                        confidence = EXCLUDED.confidence,
                        is_primary = EXCLUDED.is_primary,
                        first_seen_at = CASE
                            WHEN host_aliases.first_seen_at IS NULL THEN EXCLUDED.first_seen_at
                            WHEN EXCLUDED.first_seen_at IS NULL THEN host_aliases.first_seen_at
                            ELSE LEAST(host_aliases.first_seen_at, EXCLUDED.first_seen_at)
                        END,
                        last_seen_at = CASE
                            WHEN host_aliases.last_seen_at IS NULL THEN EXCLUDED.last_seen_at
                            WHEN EXCLUDED.last_seen_at IS NULL THEN host_aliases.last_seen_at
                            ELSE GREATEST(host_aliases.last_seen_at, EXCLUDED.last_seen_at)
                        END
                    """,
                    (
                        entity.alias_id,
                        entity.host_id,
                        entity.source,
                        entity.alias_type,
                        entity.alias_value,
                        entity.confidence,
                        entity.is_primary,
                        entity.first_seen_at,
                        entity.last_seen_at,
                    ),
                )
                return

            if isinstance(entity, Alert):
                cur.execute(
                    """
                    INSERT INTO alerts (
                        alert_id, source, source_event_id, host_id, severity, original_severity, rule_name, rule_id,
                        message, observed_at, raw_ref, raw_payload
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (alert_id) DO UPDATE SET
                        source = EXCLUDED.source,
                        source_event_id = EXCLUDED.source_event_id,
                        host_id = EXCLUDED.host_id,
                        severity = EXCLUDED.severity,
                        original_severity = EXCLUDED.original_severity,
                        rule_name = EXCLUDED.rule_name,
                        rule_id = EXCLUDED.rule_id,
                        message = EXCLUDED.message,
                        observed_at = EXCLUDED.observed_at,
                        raw_ref = EXCLUDED.raw_ref,
                        raw_payload = EXCLUDED.raw_payload
                    """,
                    (
                        entity.alert_id,
                        entity.source,
                        entity.source_event_id,
                        entity.host_id,
                        entity.severity,
                        entity.original_severity,
                        entity.rule_name,
                        entity.rule_id,
                        entity.message,
                        entity.observed_at,
                        entity.raw_ref,
                        _jsonb(entity.raw_payload),
                    ),
                )
                return

            if isinstance(entity, Vulnerability):
                cur.execute(
                    """
                    INSERT INTO vulnerabilities (
                        vuln_id, host_id, source, cve, severity, package_name, installed_version, fixed_version,
                        detected_at, resolved_at, raw_ref, raw_payload
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (vuln_id) DO UPDATE SET
                        host_id = EXCLUDED.host_id,
                        source = EXCLUDED.source,
                        cve = EXCLUDED.cve,
                        severity = EXCLUDED.severity,
                        package_name = EXCLUDED.package_name,
                        installed_version = EXCLUDED.installed_version,
                        fixed_version = EXCLUDED.fixed_version,
                        detected_at = EXCLUDED.detected_at,
                        resolved_at = EXCLUDED.resolved_at,
                        raw_ref = EXCLUDED.raw_ref,
                        raw_payload = EXCLUDED.raw_payload
                    """,
                    (
                        entity.vuln_id,
                        entity.host_id,
                        entity.source,
                        entity.cve,
                        entity.severity,
                        entity.package_name,
                        entity.installed_version,
                        entity.fixed_version,
                        entity.detected_at,
                        entity.resolved_at,
                        entity.raw_ref,
                        _jsonb(entity.raw_payload),
                    ),
                )
                return

            if isinstance(entity, QueryResult):
                cur.execute(
                    """
                    INSERT INTO query_results (
                        query_result_id, source, host_id, query_name, query_text, result_json, observed_at, raw_ref
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (query_result_id) DO UPDATE SET
                        source = EXCLUDED.source,
                        host_id = EXCLUDED.host_id,
                        query_name = EXCLUDED.query_name,
                        query_text = EXCLUDED.query_text,
                        result_json = EXCLUDED.result_json,
                        observed_at = EXCLUDED.observed_at,
                        raw_ref = EXCLUDED.raw_ref
                    """,
                    (
                        entity.query_result_id,
                        entity.source,
                        entity.host_id,
                        entity.query_name,
                        entity.query_text,
                        _jsonb(entity.result_json),
                        entity.observed_at,
                        entity.raw_ref,
                    ),
                )
                return

            if isinstance(entity, HostObservation):
                cur.execute(
                    """
                    INSERT INTO host_observations (
                        observation_id, source, host_id, observation_type, metric_name, metric_value,
                        unit, severity, observed_at, raw_ref, raw_payload
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (observation_id) DO UPDATE SET
                        source = EXCLUDED.source,
                        host_id = EXCLUDED.host_id,
                        observation_type = EXCLUDED.observation_type,
                        metric_name = EXCLUDED.metric_name,
                        metric_value = EXCLUDED.metric_value,
                        unit = EXCLUDED.unit,
                        severity = EXCLUDED.severity,
                        observed_at = EXCLUDED.observed_at,
                        raw_ref = EXCLUDED.raw_ref,
                        raw_payload = EXCLUDED.raw_payload
                    """,
                    (
                        entity.observation_id,
                        entity.source,
                        entity.host_id,
                        entity.observation_type,
                        entity.metric_name,
                        entity.metric_value,
                        entity.unit,
                        entity.severity,
                        entity.observed_at,
                        entity.raw_ref,
                        _jsonb(entity.raw_payload),
                    ),
                )
                return

            if isinstance(entity, SourceSync):
                _ensure_source_syncs_table(cur)
                cur.execute(
                    """
                    INSERT INTO source_syncs (
                        source, status, last_sync_at, last_success_at, last_error_at, message,
                        records_collected, envelopes_normalized, entities_saved
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source) DO UPDATE SET
                        status = EXCLUDED.status,
                        last_sync_at = EXCLUDED.last_sync_at,
                        last_success_at = EXCLUDED.last_success_at,
                        last_error_at = EXCLUDED.last_error_at,
                        message = EXCLUDED.message,
                        records_collected = EXCLUDED.records_collected,
                        envelopes_normalized = EXCLUDED.envelopes_normalized,
                        entities_saved = EXCLUDED.entities_saved,
                        updated_at = now()
                    """,
                    (
                        entity.source,
                        entity.status,
                        entity.last_sync_at,
                        entity.last_success_at,
                        entity.last_error_at,
                        entity.message,
                        entity.records_collected,
                        entity.envelopes_normalized,
                        entity.entities_saved,
                    ),
                )
                return

            raise TypeError(f"Unsupported entity type: {type(entity)!r}")

    def snapshot(self) -> RepositorySnapshot:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT host_id, hostname, platform, primary_ip, status, risk_score, first_seen_at, last_seen_at FROM hosts ORDER BY host_id"
            )
            hosts = [Host(*row) for row in cur.fetchall()]

            cur.execute(
                """
                SELECT alias_id, host_id, source, alias_type, alias_value, confidence, is_primary, first_seen_at, last_seen_at
                FROM host_aliases ORDER BY source, alias_type, alias_value
                """
            )
            host_aliases = [
                HostAlias(
                    alias_id=row[0],
                    host_id=row[1],
                    source=row[2],
                    alias_type=row[3],
                    alias_value=row[4],
                    confidence=_to_float(row[5]),
                    is_primary=row[6],
                    first_seen_at=row[7],
                    last_seen_at=row[8],
                )
                for row in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT alert_id, source, observed_at, message, host_id, source_event_id, severity, original_severity,
                       rule_name, rule_id, raw_ref, raw_payload
                FROM alerts ORDER BY observed_at DESC, alert_id
                """
            )
            alerts = [
                Alert(
                    alert_id=row[0],
                    source=row[1],
                    observed_at=row[2],
                    message=row[3],
                    host_id=row[4],
                    source_event_id=row[5],
                    severity=row[6],
                    original_severity=row[7],
                    rule_name=row[8],
                    rule_id=row[9],
                    raw_ref=row[10],
                    raw_payload=_as_dict(row[11]),
                )
                for row in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT vuln_id, host_id, detected_at, source, cve, severity, package_name, installed_version,
                       fixed_version, resolved_at, raw_ref, raw_payload
                FROM vulnerabilities ORDER BY detected_at DESC, vuln_id
                """
            )
            vulnerabilities = [
                Vulnerability(
                    vuln_id=row[0],
                    host_id=row[1],
                    detected_at=row[2],
                    source=row[3],
                    cve=row[4],
                    severity=row[5],
                    package_name=row[6],
                    installed_version=row[7],
                    fixed_version=row[8],
                    resolved_at=row[9],
                    raw_ref=row[10],
                    raw_payload=_as_dict(row[11]),
                )
                for row in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT query_result_id, host_id, observed_at, result_json, source, query_name, query_text, raw_ref
                FROM query_results ORDER BY observed_at DESC, query_result_id
                """
            )
            query_results = [
                QueryResult(
                    query_result_id=row[0],
                    host_id=row[1],
                    observed_at=row[2],
                    result_json=_as_dict(row[3]),
                    source=row[4],
                    query_name=row[5],
                    query_text=row[6],
                    raw_ref=row[7],
                )
                for row in cur.fetchall()
            ]

            cur.execute(
                """
                SELECT observation_id, source, host_id, observation_type, metric_name, observed_at,
                       metric_value, unit, severity, raw_ref, raw_payload
                FROM host_observations ORDER BY observed_at DESC, observation_id
                """
            )
            observations = [
                HostObservation(
                    observation_id=row[0],
                    source=row[1],
                    host_id=row[2],
                    observation_type=row[3],
                    metric_name=row[4],
                    observed_at=row[5],
                    metric_value=row[6],
                    unit=row[7],
                    severity=row[8],
                    raw_ref=row[9],
                    raw_payload=_as_dict(row[10]),
                )
                for row in cur.fetchall()
            ]

            _ensure_source_syncs_table(cur)
            cur.execute(
                """
                SELECT source, status, last_sync_at, last_success_at, last_error_at, message,
                       records_collected, envelopes_normalized, entities_saved
                FROM source_syncs ORDER BY source
                """
            )
            source_syncs = [
                SourceSync(
                    source=row[0],
                    status=row[1],
                    last_sync_at=row[2],
                    last_success_at=row[3],
                    last_error_at=row[4],
                    message=row[5],
                    records_collected=row[6],
                    envelopes_normalized=row[7],
                    entities_saved=row[8],
                )
                for row in cur.fetchall()
            ]

        return RepositorySnapshot(
            hosts=hosts,
            host_aliases=host_aliases,
            alerts=alerts,
            vulnerabilities=vulnerabilities,
            query_results=query_results,
            observations=observations,
            source_syncs=source_syncs,
        )

    def _connect(self):
        return psycopg.connect(self.dsn)


def _jsonb(payload: dict[str, Any] | None):
    return Jsonb(payload or {}) if Jsonb is not None else payload or {}


def _to_float(value: Decimal | float | int) -> float:
    return float(value)


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return dict(value)


def _ensure_source_syncs_table(cur) -> None:
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS source_syncs (
            source text PRIMARY KEY,
            status text NOT NULL,
            last_sync_at timestamptz NOT NULL,
            last_success_at timestamptz,
            last_error_at timestamptz,
            message text,
            records_collected integer NOT NULL DEFAULT 0,
            envelopes_normalized integer NOT NULL DEFAULT 0,
            entities_saved integer NOT NULL DEFAULT 0,
            updated_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT source_syncs_source_check CHECK (source IN ('fleet', 'wazuh', 'zabbix', 'host_log', 'trivy')),
            CONSTRAINT source_syncs_status_check CHECK (status IN ('success', 'error', 'running'))
        )
        """
    )