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
                "output": ["eventid", "clock", "name", "severity", "objectid", "r_eventid", "r_clock"],
                "recent": True,
                "sortfield": "eventid",
                "sortorder": "DESC",
                "limit": self._problem_limit,
            },
            auth=auth,
        )
        trigger_hosts = self._fetch_trigger_hosts(problems, auth=auth)

        # 여러 호스트가 같은 인터페이스 IP 를 쓰면(컨테이너·NAT·에이전트 집합) 그 IP 는
        # 신원 키로 쓸 수 없다 — alias 가 하나라도 겹치면 서로 다른 호스트가 한 host_id 로
        # 병합돼 버린다(예: 50대가 172.19.0.1 공유 → 1대로 붕괴). 공유 IP 는 신원 후보에서
        # 빼고, 값 자체는 primary_ip 로 계속 보존한다.
        shared_ips = self._shared_interface_ips(hosts)

        records: list[CollectorRecord] = []
        for payload in hosts:
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="host",
                    observed_at=collected_at,
                    external_id=str(payload.get("hostid") or payload.get("host") or payload.get("name") or "zbx-host"),
                    host_aliases=self._extract_host_aliases(payload, shared_ips=shared_ips),
                    payload=payload,
                )
            )
        for payload in problems:
            enriched_payload = self._enrich_problem_payload(payload, trigger_hosts)
            records.append(
                CollectorRecord(
                    source=self.source_name,
                    record_type="problem",
                    observed_at=self._extract_timestamp(enriched_payload),
                    external_id=str(enriched_payload.get("eventid") or enriched_payload.get("objectid") or "zbx-problem"),
                    host_aliases=self._extract_problem_host_aliases(enriched_payload),
                    payload=enriched_payload,
                )
            )
        return records

    def _fetch_trigger_hosts(
        self,
        problems: list[dict[str, object]],
        *,
        auth: str | None,
    ) -> dict[str, list[dict[str, object]]]:
        trigger_ids: list[str] = []
        for payload in problems:
            trigger_id = payload.get("objectid") or payload.get("triggerid")
            if trigger_id is None:
                continue
            trigger_id_text = str(trigger_id)
            if trigger_id_text not in trigger_ids:
                trigger_ids.append(trigger_id_text)
        if not trigger_ids:
            return {}
        triggers = self._api_call(
            "trigger.get",
            {
                "output": ["triggerid"],
                "triggerids": trigger_ids,
                "selectHosts": ["hostid", "host", "name"],
            },
            auth=auth,
        )
        trigger_hosts: dict[str, list[dict[str, object]]] = {}
        for trigger in triggers:
            trigger_id = trigger.get("triggerid")
            hosts = trigger.get("hosts")
            if trigger_id is None or not isinstance(hosts, list):
                continue
            trigger_hosts[str(trigger_id)] = [host for host in hosts if isinstance(host, dict)]
        return trigger_hosts

    def _enrich_problem_payload(
        self,
        payload: dict[str, object],
        trigger_hosts: dict[str, list[dict[str, object]]],
    ) -> dict[str, object]:
        enriched = dict(payload)
        trigger_id = enriched.get("objectid") or enriched.get("triggerid")
        if trigger_id is None:
            return enriched
        trigger_id_text = str(trigger_id)
        enriched.setdefault("triggerid", trigger_id_text)
        hosts = trigger_hosts.get(trigger_id_text)
        if hosts:
            enriched["hosts"] = hosts
        return enriched

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
                    host_aliases=self._extract_problem_host_aliases(payload),
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

        # 해소(resolve) 감지: recent=True 는 최근 해소된 problem 도 반환하며,
        # 해소된 경우 r_eventid(복구 이벤트) != "0" + r_clock(복구 시각)이 채워진다.
        resolved_at = None
        r_eventid = str(payload.get("r_eventid") or "0")
        if r_eventid not in ("", "0"):
            r_clock = payload.get("r_clock")
            try:
                resolved_at = datetime.fromtimestamp(int(r_clock), tz=timezone.utc)  # type: ignore[arg-type]
            except (TypeError, ValueError, OSError):
                resolved_at = datetime.now(tz=timezone.utc)

        normalized = {
            "host_id": host_alias,
            "source_aliases": record.host_aliases,
            "hostname": host_alias,
            "source_event_id": record.external_id,
            "severity": severity,
            "original_severity": str(severity_raw) if severity_raw is not None else None,
            "rule_name": name,
            "rule_id": rule_id,
            "resolved_at": resolved_at,
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
            entity_id=self._make_id("item", record, stable=True),
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
            entity_id=self._make_id("host", record, stable=True),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"zabbix:host:{record.external_id}",
            normalized=normalized,
            raw_payload=payload,
        )

    def _shared_interface_ips(self, hosts: object) -> frozenset[str]:
        """2대 이상의 호스트가 공유하는 인터페이스 IP 집합.

        이 IP 들은 host_id 신원(별칭) 후보에서 제외한다 — 공유 IP 를 별칭으로 쓰면
        서로 다른 호스트가 같은 host_id 로 병합된다(컨테이너/NAT 환경에서 흔함).
        """
        if not isinstance(hosts, list):
            return frozenset()
        counts: dict[str, int] = {}
        for payload in hosts:
            if not isinstance(payload, dict):
                continue
            seen: set[str] = set()
            interfaces = payload.get("interfaces")
            if isinstance(interfaces, list):
                for interface in interfaces:
                    if isinstance(interface, dict):
                        ip = self._str(interface.get("ip"))
                        if ip:
                            seen.add(ip)
            for ip in seen:
                counts[ip] = counts.get(ip, 0) + 1
        return frozenset(ip for ip, count in counts.items() if count > 1)

    def _extract_host_aliases(self, payload: dict, *, shared_ips: frozenset[str] = frozenset()) -> list[str]:
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
                    # 공유 IP 는 신원 키로 쓰면 서로 다른 호스트를 병합시킨다 → 제외
                    # (primary_ip 로는 그대로 저장되므로 화면·증적에서는 계속 보인다)
                    if ip and ip not in shared_ips and ip not in aliases:
                        aliases.append(ip)
        return aliases

    def _extract_problem_host_aliases(self, payload: dict) -> list[str]:
        aliases: list[str] = []
        hosts = payload.get("hosts")
        if isinstance(hosts, list):
            for host in hosts:
                if not isinstance(host, dict):
                    continue
                for key in ("name", "host", "hostid"):
                    value = self._str(host.get(key))
                    if value and value not in aliases:
                        aliases.append(value)
        for key in ("host", "hostid"):
            value = self._str(payload.get(key))
            if value and value not in aliases:
                aliases.append(value)
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

    def _make_id(self, prefix: str, record: CollectorRecord, *, stable: bool = False) -> str:
        """Generate a deterministic ID for a collector record.

        Parameters
        ----------
        prefix:
            Record category (``host``, ``item``, ``problem``).
        record:
            The source record.
        stable:
            When *True*, the ID is derived from source+prefix+external_id only,
            without the collection timestamp.  Use this for "current-state"
            observations (host availability, metric snapshots) so that repeated
            polling cycles overwrite the previous record instead of accumulating
            duplicates in the store.
        """
        if stable:
            key = f"zabbix|{prefix}|{record.external_id}"
        else:
            key = f"zabbix|{prefix}|{record.external_id}|{record.observed_at.isoformat()}"
        digest = hashlib.sha1(key.encode("utf-8")).hexdigest()
        return f"zabbix-{prefix}-{digest[:16]}"

    def _str(self, value: object) -> str | None:
        return value if isinstance(value, str) and value else None

