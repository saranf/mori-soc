from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable

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
            "observation_type": "status",
            "metric_name": "fleet_status",
            "metric_value": payload.get("message") or payload.get("status") or "status",
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
        result_json = payload.get("columns") or payload.get("result") or payload
        normalized = {
            "source": self.source_name,
            "host_id": host_alias,
            "query_name": payload.get("name") or record.external_id,
            "query_text": payload.get("query") or payload.get("query_sql"),
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
        for candidate in (
            payload.get("hostIdentifier"),
            payload.get("hostname"),
            self._nested(payload, "decorations", "hostname"),
            self._nested(payload, "columns", "hostname"),
        ):
            if isinstance(candidate, str) and candidate and candidate not in aliases:
                aliases.append(candidate)
        return aliases

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