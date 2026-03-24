from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope


class WazuhAlertCollector(BaseCollector):
    """Collector for Wazuh 4.x alert JSON lines.

    각 줄은 Wazuh alert JSON 형식:
    {"id": "...", "timestamp": "...", "agent": {"id": "001", "name": "mbp-01", "ip": "..."},
     "rule": {"id": "100001", "level": 10, "description": "..."}, "full_log": "..."}
    """

    def __init__(self, alert_lines: Iterable[str] = ()) -> None:
        self._alert_lines = tuple(alert_lines)

    @property
    def source_name(self) -> str:
        return "wazuh"

    def collect(self) -> Iterable[CollectorRecord]:
        yield from self.collect_lines(self._alert_lines)

    def collect_lines(self, lines: Iterable[str]) -> list[CollectorRecord]:
        records: list[CollectorRecord] = []
        for index, line in enumerate(lines):
            payload = json.loads(line)
            observed_at = self._extract_timestamp(payload)
            host_aliases = self._extract_host_aliases(payload)
            external_id = str(payload.get("id") or f"wazuh-{index}")
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="alert",
                    observed_at=observed_at,
                    external_id=external_id,
                    host_aliases=host_aliases,
                    payload=payload,
                )
            )
        return records

    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type == "alert":
            yield self._normalize_alert(record)
            return
        raise ValueError(f"Unsupported Wazuh record_type: {record.record_type}")

    def _normalize_alert(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}

        level = rule.get("level") if isinstance(rule, dict) else None
        severity = self._normalize_severity(level)

        host_alias = record.host_aliases[0] if record.host_aliases else None
        hostname = self._str(agent.get("name") if isinstance(agent, dict) else None) or host_alias
        primary_ip = self._str(agent.get("ip") if isinstance(agent, dict) else None)

        rule_desc = self._str(rule.get("description") if isinstance(rule, dict) else None)
        full_log = payload.get("full_log", "")
        message = rule_desc or (str(full_log)[:200] if full_log else None) or "wazuh alert"
        rule_id = self._str(str(rule.get("id")) if isinstance(rule, dict) and rule.get("id") is not None else None)

        normalized = {
            "host_id": host_alias,
            "source_aliases": record.host_aliases,
            "hostname": hostname,
            "primary_ip": primary_ip,
            "source_event_id": record.external_id,
            "severity": severity,
            "original_severity": str(level) if level is not None else None,
            "rule_name": rule_desc,
            "rule_id": rule_id,
            "message": message,
        }
        return NormalizedEnvelope(
            entity_type="alert",
            entity_id=self._make_id(record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"wazuh:{record.external_id}",
            normalized=normalized,
            raw_payload=payload,
        )

    def _extract_host_aliases(self, payload: dict) -> list[str]:
        aliases: list[str] = []
        agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
        for candidate in (
            agent.get("name") if isinstance(agent, dict) else None,
            agent.get("id") if isinstance(agent, dict) else None,
        ):
            if isinstance(candidate, str) and candidate and candidate not in aliases:
                aliases.append(candidate)
        return aliases

    def _extract_timestamp(self, payload: dict) -> datetime:
        ts = payload.get("timestamp")
        if isinstance(ts, str):
            for fmt in (
                lambda v: datetime.fromisoformat(v.replace("Z", "+00:00").replace("+0000", "+00:00")),
            ):
                try:
                    parsed = fmt(ts)
                    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    continue
        return datetime.now(tz=timezone.utc)

    def _normalize_severity(self, level: object) -> str:
        try:
            lvl = int(level)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return "info"
        if lvl >= 13:
            return "critical"
        if lvl >= 11:
            return "high"
        if lvl >= 8:
            return "medium"
        if lvl >= 4:
            return "low"
        return "info"

    def _make_id(self, record: CollectorRecord) -> str:
        digest = hashlib.sha1(
            f"wazuh|{record.external_id}|{record.observed_at.isoformat()}".encode("utf-8")
        ).hexdigest()
        return f"wazuh-alert-{digest[:16]}"

    def _str(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None

