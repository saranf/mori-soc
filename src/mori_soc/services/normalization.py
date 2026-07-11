from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime

from mori_soc.collectors.base import NormalizedEnvelope
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
    Vulnerability,
)


ASSET_BUCKET_BY_SOURCE = {
    "fleet": "pc",
    "zabbix": "server",
    "trivy": "server",
    "wazuh": "neutral",
    "host_log": "neutral",
    "code_review": "neutral",
}

BRIDGED_ASSET_BUCKETS = ("pc", "server")


@dataclass(slots=True)
class EnvelopeEntityMapper:
    alias_map: dict[str, str] = field(default_factory=dict)
    bucket_alias_map: dict[str, dict[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for bucket in {"pc", "server", "neutral"}:
            self.bucket_alias_map.setdefault(bucket, {})

    def register_alias(self, alias: str, host_id: str, *, source: str | None = None, bucket: str | None = None) -> None:
        self.alias_map[alias] = host_id
        resolved_bucket = bucket or self._bucket_for_source(source)
        if resolved_bucket:
            self.bucket_alias_map.setdefault(resolved_bucket, {})[alias] = host_id

    def map_envelope(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        if envelope.entity_type == "host_observation":
            return self._map_host_observation(envelope)
        if envelope.entity_type == "query_result":
            return self._map_query_result(envelope)
        if envelope.entity_type == "alert":
            return self._map_alert(envelope)
        if envelope.entity_type == "vulnerability":
            return self._map_vulnerability(envelope)
        # Phase 2 — identity / compliance entities (pass-through mapping)
        if envelope.entity_type == "directory_account":
            return self._map_directory_account(envelope)
        if envelope.entity_type == "group_membership":
            return self._map_group_membership(envelope)
        if envelope.entity_type == "privilege_binding":
            return self._map_privilege_binding(envelope)
        if envelope.entity_type == "account_observation":
            return self._map_account_observation(envelope)
        if envelope.entity_type == "control_check":
            return self._map_control_check(envelope)
        raise ValueError(f"Unsupported envelope entity_type: {envelope.entity_type}")

    def _map_host_observation(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        normalized = envelope.normalized
        alias, aliases = self._extract_aliases(normalized)
        host_id = self._resolve_host_id(envelope.source, aliases, fallback=f"host-{envelope.entity_id}")
        hostname = self._string_value(normalized.get("hostname")) or alias or host_id
        platform = self._string_value(normalized.get("platform"))
        status = self._host_status(normalized.get("status"))
        records: list[object] = [
            Host(
                host_id=host_id,
                hostname=hostname,
                platform=platform,
                primary_ip=self._string_value(normalized.get("primary_ip")),
                status=status,  # type: ignore[arg-type]
                first_seen_at=envelope.observed_at,
                last_seen_at=envelope.observed_at,
            )
        ]
        records.extend(self._build_alias_records(host_id, aliases, envelope.source, envelope.observed_at))
        records.append(
            HostObservation(
                observation_id=envelope.entity_id,
                source=envelope.source,
                host_id=host_id,
                observation_type=self._string_value(normalized.get("observation_type")) or "status",
                metric_name=self._string_value(normalized.get("metric_name")) or "unknown_metric",
                observed_at=envelope.observed_at,
                metric_value=self._string_value(normalized.get("metric_value")),
                unit=self._string_value(normalized.get("unit")),
                severity=self._string_value(normalized.get("severity")),
                raw_ref=envelope.raw_ref,
                raw_payload=envelope.raw_payload,
            )
        )
        return tuple(records)

    def _map_query_result(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        normalized = envelope.normalized
        alias, aliases = self._extract_aliases(normalized)
        host_id = self._resolve_host_id(envelope.source, aliases, fallback=f"host-{envelope.entity_id}")
        result_json = normalized.get("result_json") if isinstance(normalized.get("result_json"), dict) else {}
        hostname = self._string_value(normalized.get("hostname")) or self._string_value(result_json.get("hostname")) or alias
        platform = self._string_value(normalized.get("platform")) or self._string_value(result_json.get("platform"))
        records: list[object] = []
        if hostname:
            records.append(
                Host(
                    host_id=host_id,
                    hostname=hostname,
                    platform=platform,
                    status="unknown",
                    first_seen_at=envelope.observed_at,
                    last_seen_at=envelope.observed_at,
                )
            )
        records.extend(self._build_alias_records(host_id, aliases, envelope.source, envelope.observed_at))
        records.append(
            QueryResult(
                query_result_id=envelope.entity_id,
                host_id=host_id,
                observed_at=envelope.observed_at,
                result_json=result_json,
                source=envelope.source,
                query_name=self._string_value(normalized.get("query_name")),
                query_text=self._string_value(normalized.get("query_text")),
                raw_ref=envelope.raw_ref,
            )
        )
        return tuple(records)

    def _resolve_host_id(self, source: str, aliases: list[str], fallback: str) -> str:
        bucket = self._bucket_for_source(source) or "neutral"
        host_id = self._find_bucket_host_id(bucket, aliases)
        if host_id is not None:
            self._register_bucket_aliases(bucket, aliases, host_id)
            return host_id

        if bucket == "neutral":
            bridged_host_id = self._find_neutral_bridge_host_id(aliases)
            if bridged_host_id is not None:
                self._register_bucket_aliases(bucket, aliases, bridged_host_id)
                return bridged_host_id

        for alias in aliases:
            if alias in self.alias_map:
                host_id = self.alias_map[alias]
                self._register_bucket_aliases(bucket, aliases, host_id)
                return host_id

        identity = aliases[0] if aliases else fallback
        host_id = self._scoped_host_id(bucket, identity)
        self._register_bucket_aliases(bucket, aliases, host_id)
        return host_id

    def _build_alias(self, host_id: str, alias: str, source: str, alias_type: str, observed_at):
        digest = hashlib.sha1(f"{host_id}|{source}|{alias_type}|{alias}".encode("utf-8")).hexdigest()
        return HostAlias(
            alias_id=f"alias-{digest[:16]}",
            host_id=host_id,
            source=source,
            alias_type=alias_type,
            alias_value=alias,
            is_primary=True,
            first_seen_at=observed_at,
            last_seen_at=observed_at,
        )

    def _build_alias_records(
        self,
        host_id: str,
        aliases: list[str],
        source: str,
        observed_at,
    ) -> tuple[HostAlias, ...]:
        return tuple(
            self._build_alias(host_id, alias, source, "source_alias", observed_at)
            for alias in aliases
        )

    def _map_alert(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        normalized = envelope.normalized
        alias, aliases = self._extract_aliases(normalized)
        host_id: str | None = None
        records: list[object] = []

        if aliases:
            host_id = self._resolve_host_id(envelope.source, aliases, fallback=alias or f"host-{envelope.entity_id}")
            hostname = self._string_value(normalized.get("hostname")) or alias or host_id
            primary_ip = self._string_value(normalized.get("primary_ip"))
            records.append(
                Host(
                    host_id=host_id,
                    hostname=hostname,
                    primary_ip=primary_ip,
                    status="unknown",
                    first_seen_at=envelope.observed_at,
                    last_seen_at=envelope.observed_at,
                )
            )
            records.extend(self._build_alias_records(host_id, aliases, envelope.source, envelope.observed_at))

        records.append(
            Alert(
                alert_id=envelope.entity_id,
                source=envelope.source,  # type: ignore[arg-type]
                host_id=host_id,
                source_event_id=self._string_value(normalized.get("source_event_id")),
                severity=self._string_value(normalized.get("severity")) or "info",  # type: ignore[arg-type]
                original_severity=self._string_value(normalized.get("original_severity")),
                rule_name=self._string_value(normalized.get("rule_name")),
                rule_id=self._string_value(normalized.get("rule_id")),
                resolved_at=(normalized.get("resolved_at")
                             if isinstance(normalized.get("resolved_at"), datetime) else None),
                message=self._string_value(normalized.get("message")) or "alert",
                observed_at=envelope.observed_at,
                raw_ref=envelope.raw_ref,
                raw_payload=envelope.raw_payload,
            )
        )
        return tuple(records)

    def _map_vulnerability(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        normalized = envelope.normalized
        alias, aliases = self._extract_aliases(normalized)
        host_id = self._resolve_host_id(envelope.source, aliases, fallback=f"host-{envelope.entity_id}")
        records: list[object] = []

        if alias:
            hostname = self._string_value(normalized.get("hostname")) or alias
            records.append(
                Host(
                    host_id=host_id,
                    hostname=hostname,
                    status="unknown",
                    first_seen_at=envelope.observed_at,
                    last_seen_at=envelope.observed_at,
                )
            )
        records.extend(self._build_alias_records(host_id, aliases, envelope.source, envelope.observed_at))

        records.append(
            Vulnerability(
                vuln_id=envelope.entity_id,
                host_id=host_id,
                source=envelope.source,  # type: ignore[arg-type]
                cve=self._string_value(normalized.get("cve")),
                severity=self._string_value(normalized.get("severity")) or "info",  # type: ignore[arg-type]
                package_name=self._string_value(normalized.get("package_name")),
                installed_version=self._string_value(normalized.get("installed_version")),
                fixed_version=self._string_value(normalized.get("fixed_version")),
                detected_at=envelope.observed_at,
                raw_ref=envelope.raw_ref,
                raw_payload=envelope.raw_payload,
            )
        )
        return tuple(records)

    # ------------------------------------------------------------------
    # Phase 2 — Identity / Compliance entity mappers
    # ------------------------------------------------------------------

    def _map_directory_account(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        n = envelope.normalized
        return (DirectoryAccount(
            account_id=n.get("account_id") or envelope.entity_id,
            username=n.get("username") or "unknown",
            display_name=self._string_value(n.get("display_name")),
            email=self._string_value(n.get("email")),
            department=self._string_value(n.get("department")),
            status=n.get("status") or "active",
            is_privileged=bool(n.get("is_privileged")),
            last_login_at=self._parse_iso(n.get("last_login_at")),
            password_last_set=self._parse_iso(n.get("password_last_set")),
            created_at=self._parse_iso(n.get("created_at")),
        ),)

    def _map_group_membership(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        n = envelope.normalized
        return (GroupMembership(
            membership_id=n.get("membership_id") or envelope.entity_id,
            account_id=n.get("account_id") or "unknown",
            group_name=n.get("group_name") or "unknown",
            source=n.get("source") or "ldap",
            synced_at=envelope.observed_at,
        ),)

    def _map_privilege_binding(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        n = envelope.normalized
        return (PrivilegeBinding(
            binding_id=n.get("binding_id") or envelope.entity_id,
            account_id=n.get("account_id") or "unknown",
            privilege_type=n.get("privilege_type") or "unknown",
            target=self._string_value(n.get("target")),
            granted_at=envelope.observed_at,
            granted_by=self._string_value(n.get("granted_by")),
        ),)

    def _map_account_observation(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        n = envelope.normalized
        return (AccountObservation(
            observation_id=n.get("observation_id") or envelope.entity_id,
            account_id=n.get("account_id") or "unknown",
            observation_type=n.get("observation_type") or "unknown",
            source=n.get("source") or "ldap",
            observed_at=envelope.observed_at,
            detail=self._string_value(n.get("detail")),
            severity=self._string_value(n.get("severity")),
        ),)

    def _map_control_check(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        n = envelope.normalized
        return (ControlCheckResult(
            check_id=n.get("check_id") or envelope.entity_id,
            control_id=n.get("control_id") or "unknown",
            entity_type=n.get("entity_type") or "host",
            entity_id=n.get("entity_id") or "unknown",
            status=n.get("status") or "not_checked",
            checked_at=envelope.observed_at,
            evidence_refs=n.get("evidence_refs") or [],
            owner=self._string_value(n.get("owner")),
            note=self._string_value(n.get("note")),
        ),)

    @staticmethod
    def _parse_iso(value: object) -> datetime | None:
        """Parse ISO timestamp string to datetime, or return None."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str) and value:
            try:
                from datetime import timezone as _tz
                dt = datetime.fromisoformat(value)
                return dt if dt.tzinfo else dt.replace(tzinfo=_tz.utc)
            except (ValueError, TypeError):
                return None
        return None

    def _extract_aliases(self, normalized: dict[str, object]) -> tuple[str | None, list[str]]:
        aliases: list[str] = []
        primary = self._string_value(normalized.get("host_id"))
        if primary:
            aliases.append(primary)
        source_aliases = normalized.get("source_aliases")
        if isinstance(source_aliases, list):
            for value in source_aliases:
                if isinstance(value, str) and value and value not in aliases:
                    aliases.append(value)
        return primary or (aliases[0] if aliases else None), aliases

    def _bucket_for_source(self, source: str | None) -> str | None:
        if source is None:
            return None
        return ASSET_BUCKET_BY_SOURCE.get(source)

    def _find_bucket_host_id(self, bucket: str, aliases: list[str]) -> str | None:
        bucket_map = self.bucket_alias_map.get(bucket, {})
        for alias in aliases:
            host_id = bucket_map.get(alias)
            if host_id is not None:
                return host_id
        return None

    def _find_neutral_bridge_host_id(self, aliases: list[str]) -> str | None:
        matched_host_ids = {
            host_id
            for bucket in BRIDGED_ASSET_BUCKETS
            for alias in aliases
            for host_id in [self.bucket_alias_map.get(bucket, {}).get(alias)]
            if host_id is not None
        }
        if len(matched_host_ids) == 1:
            return next(iter(matched_host_ids))
        return None

    def _register_bucket_aliases(self, bucket: str, aliases: list[str], host_id: str) -> None:
        bucket_map = self.bucket_alias_map.setdefault(bucket, {})
        for alias in aliases:
            bucket_map[alias] = host_id

    def _scoped_host_id(self, bucket: str, identity: str) -> str:
        safe_identity = re.sub(r"[^A-Za-z0-9._-]+", "-", identity).strip("-._")
        if not safe_identity:
            digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()
            safe_identity = digest[:16]
        if safe_identity.startswith(f"{bucket}-"):
            return safe_identity
        return f"{bucket}-{safe_identity}"

    def _string_value(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None

    def _host_status(self, value: object) -> str:
        status = self._string_value(value)
        if status in {"online", "offline", "unknown"}:
            return status
        return "unknown"