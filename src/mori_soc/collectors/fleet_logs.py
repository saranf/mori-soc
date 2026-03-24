from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope


class FleetLogCollector(BaseCollector):
    """Collector stub for Fleet/osquery status and result logs."""

    def __init__(self, status_lines: Iterable[str] = (), result_lines: Iterable[str] = ()) -> None:
        self._status_lines = tuple(status_lines)
        self._result_lines = tuple(result_lines)

    @property
    def source_name(self) -> str:
        return "fleet"

    def collect(self) -> Iterable[CollectorRecord]:
        yield from self.collect_lines(self._status_lines, "status", raw_ref_prefix="fleet.status")
        yield from self.collect_lines(self._result_lines, "result", raw_ref_prefix="fleet.results")

    def collect_lines(
        self,
        lines: Iterable[str],
        record_type: str,
        raw_ref_prefix: str = "fleet",
    ) -> list[CollectorRecord]:
        records: list[CollectorRecord] = []
        for index, line in enumerate(lines):
            payload = json.loads(line)
            observed_at = self._extract_timestamp(payload)
            host_aliases = self._extract_host_aliases(payload)
            external_id = payload.get("name") or payload.get("hostIdentifier") or f"{record_type}-{index}"
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type=record_type,
                    observed_at=observed_at,
                    external_id=str(external_id),
                    host_aliases=host_aliases,
                    payload={**payload, "raw_ref": f"{raw_ref_prefix}:{index}"},
                )
            )
        return records

    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type == "status":
            yield self._normalize_status(record)
            return
        if record.record_type == "result":
            yield self._normalize_result(record)
            return
        raise ValueError(f"Unsupported Fleet record_type: {record.record_type}")

    def _normalize_status(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        host_alias = record.host_aliases[0] if record.host_aliases else None
        normalized = {
            "source": self.source_name,
            "host_id": host_alias,
            "source_aliases": record.host_aliases,
            "observation_type": "status",
            "metric_name": "fleet_status",
            "metric_value": payload.get("message") or payload.get("status") or payload.get("state") or "status",
            "hostname": self._extract_hostname(payload),
            "platform": self._extract_platform(payload),
            "status": "online",
            "severity": self._normalize_severity(payload.get("severity")),
        }
        return NormalizedEnvelope(
            entity_type="host_observation",
            entity_id=self._make_id("status", record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=payload.get("raw_ref"),
            normalized=normalized,
            raw_payload=payload,
        )

    def _normalize_result(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        host_alias = record.host_aliases[0] if record.host_aliases else None
        result_json = self._extract_result_json(payload)
        normalized = {
            "source": self.source_name,
            "host_id": host_alias,
            "source_aliases": record.host_aliases,
            "hostname": self._extract_hostname(payload, result_json),
            "platform": self._extract_platform(payload, result_json),
            "query_name": self._string_value(payload.get("name")) or self._string_value(payload.get("query_name")) or record.external_id,
            "query_text": self._string_value(payload.get("query")) or self._string_value(payload.get("query_sql")) or self._string_value(payload.get("sql")),
            "result_json": result_json,
        }
        return NormalizedEnvelope(
            entity_type="query_result",
            entity_id=self._make_id("result", record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=payload.get("raw_ref"),
            normalized=normalized,
            raw_payload=payload,
        )

    def _extract_host_aliases(self, payload: dict[str, object]) -> list[str]:
        aliases: list[str] = []
        for container in (
            payload,
            payload.get("decorations"),
            payload.get("columns"),
            payload.get("result"),
            payload.get("results"),
            payload.get("snapshot"),
        ):
            self._collect_aliases(container, aliases)
        return aliases

    def _extract_result_json(self, payload: dict[str, object]) -> dict[str, Any]:
        for key in ("columns", "result", "results", "snapshot", "data"):
            extracted = self._normalize_result_container(payload.get(key))
            if extracted is not None:
                return extracted
        return dict(payload)

    def _normalize_result_container(self, value: object) -> dict[str, Any] | None:
        if isinstance(value, dict):
            columns = value.get("columns")
            if isinstance(columns, dict):
                return dict(columns)
            return dict(value)
        if isinstance(value, list):
            rows = [row for row in (self._normalize_result_row(item) for item in value) if row is not None]
            if rows:
                return {"rows": rows, "row_count": len(rows)}
            return {"rows": [], "row_count": 0}
        if value is None:
            return None
        return {"value": value}

    def _normalize_result_row(self, value: object) -> dict[str, Any] | None:
        if isinstance(value, dict):
            columns = value.get("columns")
            if isinstance(columns, dict):
                return dict(columns)
            return dict(value)
        if value is None:
            return None
        return {"value": value}

    def _extract_hostname(self, payload: dict[str, object], result_json: dict[str, Any] | None = None) -> str | None:
        for candidate in (
            self._string_value(payload.get("hostname")),
            self._string_value(self._nested(payload, "decorations", "hostname")),
            self._string_value(self._nested(payload, "columns", "hostname")),
            self._string_value(self._nested(payload, "columns", "computer_name")),
            self._string_value(result_json.get("hostname")) if isinstance(result_json, dict) else None,
            self._string_value(result_json.get("computer_name")) if isinstance(result_json, dict) else None,
            self._first_row_value(result_json, "hostname", "computer_name", "local_hostname") if isinstance(result_json, dict) else None,
            self._string_value(payload.get("hostIdentifier")),
        ):
            if candidate:
                return candidate
        return None

    def _extract_platform(self, payload: dict[str, object], result_json: dict[str, Any] | None = None) -> str | None:
        for candidate in (
            self._string_value(payload.get("platform")),
            self._string_value(self._nested(payload, "columns", "platform")),
            self._string_value(result_json.get("platform")) if isinstance(result_json, dict) else None,
            self._first_row_value(result_json, "platform") if isinstance(result_json, dict) else None,
        ):
            if candidate:
                return candidate
        return None

    def _collect_aliases(self, value: object, aliases: list[str]) -> None:
        if isinstance(value, dict):
            for key in (
                "hostIdentifier",
                "host_identifier",
                "host_id",
                "hostId",
                "hostname",
                "local_hostname",
                "computer_name",
                "uuid",
                "host_uuid",
                "hardware_uuid",
                "hardwareUuid",
            ):
                self._append_alias(aliases, value.get(key))
            if "columns" in value:
                self._collect_aliases(value.get("columns"), aliases)
            return
        if isinstance(value, list):
            for item in value:
                self._collect_aliases(item, aliases)

    def _append_alias(self, aliases: list[str], candidate: object) -> None:
        text = self._string_value(candidate)
        if text and text not in aliases:
            aliases.append(text)

    def _first_row_value(self, result_json: dict[str, Any], *keys: str) -> str | None:
        rows = result_json.get("rows")
        if not isinstance(rows, list):
            return None
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in keys:
                text = self._string_value(row.get(key))
                if text:
                    return text
        return None

    def _extract_timestamp(self, payload: dict[str, object]) -> datetime:
        unix_time = payload.get("unixTime") or payload.get("unix_time")
        if isinstance(unix_time, (int, float)):
            return datetime.fromtimestamp(unix_time, tz=timezone.utc)

        for key in ("timestamp", "calendarTime"):
            value = payload.get(key)
            if isinstance(value, str):
                parsed = self._parse_datetime(value)
                if parsed is not None:
                    return parsed
        return datetime.now(tz=timezone.utc)

    def _parse_datetime(self, value: str) -> datetime | None:
        candidates = (
            lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")),
            lambda v: datetime.strptime(v, "%a %b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc),
        )
        for parser in candidates:
            try:
                parsed = parser(value)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    def _normalize_severity(self, value: object) -> str:
        mapping = {
            "0": "info",
            "1": "low",
            "2": "medium",
            "3": "high",
            "4": "critical",
            0: "info",
            1: "low",
            2: "medium",
            3: "high",
            4: "critical",
        }
        return mapping.get(value, "info")

    def _make_id(self, prefix: str, record: CollectorRecord) -> str:
        digest = hashlib.sha1(
            f"{prefix}|{record.external_id}|{record.observed_at.isoformat()}|{record.payload}".encode("utf-8")
        ).hexdigest()
        return f"fleet-{prefix}-{digest[:16]}"

    def _nested(self, payload: dict[str, object], *keys: str) -> object | None:
        current: object = payload
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        return current

    def _string_value(self, value: object) -> str | None:
        if isinstance(value, str) and value:
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
        return None