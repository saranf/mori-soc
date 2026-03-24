from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Iterable
from urllib import error, request

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
        *,
        api_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        request_timeout: int = 10,
        host_limit: int = 500,
        problem_limit: int = 500,
    ) -> None:
        self._problem_lines = tuple(problem_lines)
        self._item_lines = tuple(item_lines)
        self._api_url = api_url
        self._username = username
        self._password = password
        self._token = token
        self._request_timeout = request_timeout
        self._host_limit = host_limit
        self._problem_limit = problem_limit

    @property
    def source_name(self) -> str:
        return "zabbix"

    def collect(self) -> Iterable[CollectorRecord]:
        if self._api_url:
            yield from self._collect_api()
            return
        yield from self.collect_problem_lines(self._problem_lines)
        yield from self.collect_item_lines(self._item_lines)

    def _collect_api(self) -> list[CollectorRecord]:
        auth = self._token or self._login()
        collected_at = datetime.now(tz=timezone.utc)
        hosts = self._api_call(
            "host.get",
            {
                "output": ["hostid", "host", "name", "status", "active_available"],
                "selectInterfaces": ["ip", "available"],
                "limit": self._host_limit,
                "sortfield": "host",
            },
            auth=auth,
        )
        problems = self._api_call(
            "problem.get",
            {
                "output": ["eventid", "clock", "name", "severity", "objectid"],
                "selectHosts": ["hostid", "host", "name"],
                "recent": True,
                "sortfield": "eventid",
                "sortorder": "DESC",
                "limit": self._problem_limit,
            },
            auth=auth,
        )

        records: list[CollectorRecord] = []
        for payload in hosts:
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="host",
                    observed_at=collected_at,
                    external_id=str(payload.get("hostid") or payload.get("host") or payload.get("name") or "zbx-host"),
                    host_aliases=self._extract_host_aliases(payload),
                    payload=payload,
                )
            )
        for payload in problems:
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="problem",
                    observed_at=self._extract_timestamp(payload),
                    external_id=str(payload.get("eventid") or payload.get("objectid") or "zbx-problem"),
                    host_aliases=self._extract_host_aliases(payload),
                    payload=payload,
                )
            )
        return records

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
        if record.record_type == "host":
            yield self._normalize_host(record)
            return
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

    def _normalize_host(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        primary_ip = self._extract_primary_ip(payload)
        status = self._extract_host_status(payload)
        metric_value = "available" if status == "online" else "unavailable" if status == "offline" else "unknown"
        normalized = {
            "host_id": record.host_aliases[0] if record.host_aliases else None,
            "source_aliases": record.host_aliases,
            "hostname": self._str(payload.get("name")) or self._str(payload.get("host")) or primary_ip,
            "primary_ip": primary_ip,
            "status": status,
            "observation_type": "availability",
            "metric_name": "zabbix_agent_status",
            "metric_value": metric_value,
        }
        return NormalizedEnvelope(
            entity_type="host_observation",
            entity_id=self._make_id("host", record),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"zabbix:host:{record.external_id}",
            normalized=normalized,
            raw_payload=payload,
        )

    def _extract_host_aliases(self, payload: dict) -> list[str]:
        aliases: list[str] = []
        for key in ("name", "host", "hostid"):
            value = self._str(payload.get(key))
            if value and value not in aliases:
                aliases.append(value)
        hosts = payload.get("hosts")
        if isinstance(hosts, list):
            for h in hosts:
                if isinstance(h, dict):
                    for key in ("name", "host", "hostid"):
                        val = self._str(h.get(key))
                        if val and val not in aliases:
                            aliases.append(val)
        interfaces = payload.get("interfaces")
        if isinstance(interfaces, list):
            for interface in interfaces:
                if isinstance(interface, dict):
                    ip = self._str(interface.get("ip"))
                    if ip and ip not in aliases:
                        aliases.append(ip)
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

    def _extract_primary_ip(self, payload: dict) -> str | None:
        interfaces = payload.get("interfaces")
        if isinstance(interfaces, list):
            for interface in interfaces:
                if isinstance(interface, dict):
                    ip = self._str(interface.get("ip"))
                    if ip:
                        return ip
        return None

    def _extract_host_status(self, payload: dict) -> str:
        if str(payload.get("status")) == "1":
            return "offline"
        interfaces = payload.get("interfaces")
        if isinstance(interfaces, list):
            for interface in interfaces:
                if isinstance(interface, dict):
                    available = str(interface.get("available"))
                    if available == "1":
                        return "online"
                    if available == "2":
                        return "offline"
        active_available = str(payload.get("active_available"))
        if active_available == "1":
            return "online"
        if active_available == "2":
            return "offline"
        return "unknown"

    def _login(self) -> str:
        if not self._username or not self._password:
            raise RuntimeError("Zabbix API credentials are missing")
        try:
            return str(self._api_call("user.login", {"username": self._username, "password": self._password}))
        except RuntimeError as exc:
            if "Invalid params" not in str(exc):
                raise
        return str(self._api_call("user.login", {"user": self._username, "password": self._password}))

    def _api_call(self, method: str, params: dict[str, object], *, auth: str | None = None):
        prefer_auth_header = bool(auth and self._token)
        try:
            return self._perform_api_call(method, params, auth=auth, use_auth_header=prefer_auth_header)
        except RuntimeError as exc:
            if auth and not prefer_auth_header and 'unexpected parameter "auth"' in str(exc):
                return self._perform_api_call(method, params, auth=auth, use_auth_header=True)
            raise

    def _perform_api_call(
        self,
        method: str,
        params: dict[str, object],
        *,
        auth: str | None = None,
        use_auth_header: bool = False,
    ):
        if not self._api_url:
            raise RuntimeError("Zabbix API URL is not configured")
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        if auth and not use_auth_header:
            payload["auth"] = auth
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json-rpc"}
        if auth and use_auth_header:
            headers["Authorization"] = f"Bearer {auth}"
        req = request.Request(
            self._api_url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._request_timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            raise RuntimeError(f"Zabbix API request failed: {exc}") from exc
        if "error" in data:
            err = data["error"]
            raise RuntimeError(f"Zabbix API error {err.get('code')}: {err.get('message')} {err.get('data', '')}".strip())
        return data.get("result", [])

    def _make_id(self, prefix: str, record: CollectorRecord) -> str:
        digest = hashlib.sha1(
            f"zabbix|{prefix}|{record.external_id}|{record.observed_at.isoformat()}".encode("utf-8")
        ).hexdigest()
        return f"zabbix-{prefix}-{digest[:16]}"

    def _str(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None

