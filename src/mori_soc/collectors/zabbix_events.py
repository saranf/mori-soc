from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope


class ZabbixEventCollector(BaseCollector):
    """Collector for Zabbix problem events and item metric data.

    problem_lines: Zabbix 트리거 문제 이벤트 JSON (-> alert)
      {"eventid": "12345", "clock": "1710160500", "hosts": [{"hostid": "10001", "name": "zbx-host"}],
       "name": "CPU > 80%", "severity": "3", "triggerid": "99001"}

    item_lines: Zabbix 아이템 수집값 JSON (-> host_observation)
      {"itemid": "22001", "clock": "1710160500", "value": "85.4",
       "hosts": [{"hostid": "10001", "name": "zbx-host"}], "item_name": "CPU utilization", "units": "%"}
    """

    def __init__(
        self,
        problem_lines: Iterable[str] = (),
        item_lines: Iterable[str] = (),
    ) -> None:
        self._problem_lines = tuple(problem_lines)
        self._item_lines = tuple(item_lines)

    @property
    def source_name(self) -> str:
        return "zabbix"

    def collect(self) -> Iterable[CollectorRecord]:
        yield from self.collect_problem_lines(self._problem_lines)
        yield from self.collect_item_lines(self._item_lines)

    def collect_problem_lines(self, lines: Iterable[str]) -> list[CollectorRecord]:
        records: list[CollectorRecord] = []
        for index, line in enumerate(lines):
            payload = json.loads(line)
            external_id = str(payload.get("eventid") or f"zbx-event-{index}")
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="problem",
                    observed_at=self._extract_timestamp(payload),
                    external_id=external_id,
                    host_aliases=self._extract_host_aliases(payload),
                    payload=payload,
                )
            )
        return records

    def collect_item_lines(self, lines: Iterable[str]) -> list[CollectorRecord]:
        records: list[CollectorRecord] = []
        for index, line in enumerate(lines):
            payload = json.loads(line)
            external_id = str(payload.get("itemid") or f"zbx-item-{index}")
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="item_data",
                    observed_at=self._extract_timestamp(payload),
                    external_id=external_id,
                    host_aliases=self._extract_host_aliases(payload),
                    payload=payload,
                )
            )
        return records

    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type == "problem":
            yield self._normalize_problem(record)
            return
        if record.record_type == "item_data":
            yield self._normalize_item(record)
            return
        raise ValueError(f"Unsupported Zabbix record_type: {record.record_type}")

    def _normalize_problem(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        host_alias = record.host_aliases[0] if record.host_aliases else None
        severity_raw = payload.get("severity")
        severity = self._normalize_severity(severity_raw)
        trigger_id_raw = payload.get("triggerid")
        rule_id = str(trigger_id_raw) if trigger_id_raw is not None else None
        name = self._str(payload.get("name")) or "zabbix problem"

        normalized = {
            "host_id": host_alias,
            "source_aliases": record.host_aliases,
            "hostname": host_alias,
            "source_event_id": record.external_id,
            "severity": severity,
            "original_severity": str(severity_raw) if severity_raw is not None else None,
            "rule_name": name,
            "rule_id": rule_id,
            "message": name,
        }
        return NormalizedEnvelope(
            entity_type="alert",
            entity_id=self._make_id("problem", record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"zabbix:event:{record.external_id}",
            normalized=normalized,
            raw_payload=payload,
        )

    def _normalize_item(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        host_alias = record.host_aliases[0] if record.host_aliases else None
        value = payload.get("value")

        normalized = {
            "host_id": host_alias,
            "source_aliases": record.host_aliases,
            "hostname": host_alias,
            "observation_type": "metric",
            "metric_name": self._str(payload.get("item_name")) or self._str(payload.get("key_")) or "unknown_metric",
            "metric_value": str(value) if value is not None else None,
            "unit": self._str(payload.get("units")) or self._str(payload.get("unit")),
        }
        return NormalizedEnvelope(
            entity_type="host_observation",
            entity_id=self._make_id("item", record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"zabbix:item:{record.external_id}",
            normalized=normalized,
            raw_payload=payload,
        )

    def _extract_host_aliases(self, payload: dict) -> list[str]:
        aliases: list[str] = []
        hosts = payload.get("hosts")
        if isinstance(hosts, list):
            for h in hosts:
                if isinstance(h, dict):
                    for key in ("name", "hostid"):
                        val = self._str(h.get(key))
                        if val and val not in aliases:
                            aliases.append(val)
        return aliases

    def _extract_timestamp(self, payload: dict) -> datetime:
        clock = payload.get("clock")
        try:
            return datetime.fromtimestamp(int(clock), tz=timezone.utc)  # type: ignore[arg-type]
        except (TypeError, ValueError, OSError):
            return datetime.now(tz=timezone.utc)

    def _normalize_severity(self, severity: object) -> str:
        mapping: dict[object, str] = {
            0: "info", "0": "info",
            1: "info", "1": "info",
            2: "low", "2": "low",
            3: "medium", "3": "medium",
            4: "high", "4": "high",
            5: "critical", "5": "critical",
        }
        return mapping.get(severity, "info")

    def _make_id(self, prefix: str, record: CollectorRecord) -> str:
        digest = hashlib.sha1(
            f"zabbix|{prefix}|{record.external_id}|{record.observed_at.isoformat()}".encode("utf-8")
        ).hexdigest()
        return f"zabbix-{prefix}-{digest[:16]}"

    def _str(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None

