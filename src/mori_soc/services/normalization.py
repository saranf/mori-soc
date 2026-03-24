from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from mori_soc.collectors.base import NormalizedEnvelope
from mori_soc.models import Alert, Host, HostAlias, HostObservation, QueryResult, Vulnerability


@dataclass(slots=True)
class EnvelopeEntityMapper:
    alias_map: dict[str, str] = field(default_factory=dict)

    def register_alias(self, alias: str, host_id: str) -> None:
        self.alias_map[alias] = host_id

    def map_envelope(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        if envelope.entity_type == "host_observation":
            return self._map_host_observation(envelope)
        if envelope.entity_type == "query_result":
            return self._map_query_result(envelope)
        if envelope.entity_type == "alert":
            return self._map_alert(envelope)
        if envelope.entity_type == "vulnerability":
            return self._map_vulnerability(envelope)
        raise ValueError(f"Unsupported envelope entity_type: {envelope.entity_type}")

    def _map_host_observation(self, envelope: NormalizedEnvelope) -> tuple[object, ...]:
        normalized = envelope.normalized
        alias, aliases = self._extract_aliases(normalized)
        host_id = self._resolve_host_id(aliases, fallback=f"host-{envelope.entity_id}")
        hostname = self._string_value(normalized.get("hostname")) or alias or host_id
        platform = self._string_value(normalized.get("platform"))
        status = self._string_value(normalized.get("status")) or "online"
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
        host_id = self._resolve_host_id(aliases, fallback=f"host-{envelope.entity_id}")
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
                    status="online",
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

    def _resolve_host_id(self, aliases: list[str], fallback: str) -> str:
        for alias in aliases:
            if alias in self.alias_map:
                host_id = self.alias_map[alias]
                for candidate in aliases:
                    self.alias_map[candidate] = host_id
                return host_id
        if aliases:
            host_id = aliases[0]
            for candidate in aliases:
                self.alias_map[candidate] = host_id
            return host_id
        return fallback

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
            host_id = self._resolve_host_id(aliases, fallback=alias or f"host-{envelope.entity_id}")
            hostname = self._string_value(normalized.get("hostname")) or alias or host_id
            primary_ip = self._string_value(normalized.get("primary_ip"))
            records.append(
                Host(
                    host_id=host_id,
                    hostname=hostname,
                    primary_ip=primary_ip,
                    status="online",
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
        host_id = self._resolve_host_id(aliases, fallback=f"host-{envelope.entity_id}")
        records: list[object] = []

        if alias:
            hostname = self._string_value(normalized.get("hostname")) or alias
            records.append(
                Host(
                    host_id=host_id,
                    hostname=hostname,
                    status="online",
                    first_seen_at=envelope.observed_at,
                    last_seen_at=envelope.observed_at,
                )
            )
        records.extend(self._build_alias_records(host_id, aliases, envelope.source, envelope.observed_at))

        records.append(
            Vulnerability(
                vuln_id=envelope.entity_id,
                host_id=host_id,
                source="fleet",
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

    def _string_value(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None