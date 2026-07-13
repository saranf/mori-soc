"""Fleet REST API 수집기 — 호스트(자산) + 소프트웨어 취약점.

스키마 근거는 **실제 Fleet 응답 캡처**(``tests/fixtures/fleet/``, F0)이며 추측이 아니다.

수집 경로
---------
``GET /api/v1/fleet/hosts``           → 호스트 목록      → ``host_observation``
``GET /api/v1/fleet/hosts/{id}``      → ``software[]``   → ``vulnerability`` (``software[].vulnerabilities``)

호스트 ID 접두사(``pc-``)는 **여기서 붙이지 않는다** — ``normalization.ASSET_BUCKET_BY_SOURCE``
가 ``fleet → pc`` 로 스코프를 부여한다. 수집기는 원본 hostname 을 alias 로만 넘긴다.

osquery 로그(status/result)는 이미 fluent-bit → Loki 로 흐르므로 여기서 다시 수집하지 않는다
(MORI 는 증적 층 — 로그 조회는 Grafana/Loki 위임). 그 경로는 :mod:`collectors.fleet_logs` 참고.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib import error, parse, request

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope

# Fleet 호스트 상태 → MORI HostStatus
_HOST_STATUS = {"online": "online", "offline": "offline", "mia": "offline", "missing": "offline"}


class FleetApiCollector(BaseCollector):
    """Fleet REST API 수집기 (Bearer 토큰 인증).

    ``hosts`` 는 항상 수집한다. ``include_software`` 가 참이면 호스트별 상세를 추가로 조회해
    ``software[].vulnerabilities`` 에서 취약점을 뽑는다(호스트 수만큼 요청이 늘어난다).
    """

    def __init__(
        self,
        *,
        api_url: str,
        token: str,
        request_timeout: int = 10,
        host_limit: int = 500,
        include_software: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._token = token
        self._request_timeout = request_timeout
        self._host_limit = host_limit
        self._include_software = include_software
        self._verify_tls = verify_tls

    @property
    def source_name(self) -> str:
        return "fleet"

    # ── 수집 ────────────────────────────────────────────────────────
    def collect(self) -> Iterable[CollectorRecord]:
        collected_at = datetime.now(tz=timezone.utc)
        payload = self._get("/api/v1/fleet/hosts", {"per_page": self._host_limit})
        hosts = payload.get("hosts") if isinstance(payload, dict) else None
        if not isinstance(hosts, list):
            return []

        records: list[CollectorRecord] = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            records.append(self._host_record(host, collected_at))
            if self._include_software:
                records.extend(self._software_records(host, collected_at))
        return records

    def _host_record(self, host: dict[str, Any], collected_at: datetime) -> CollectorRecord:
        return CollectorRecord(
            source=self.source_name,
            record_type="host",
            observed_at=self._parse_time(host.get("seen_time")) or collected_at,
            external_id=self._str(host.get("id")),
            host_aliases=self._host_aliases(host),
            payload=host,
        )

    def _software_records(self, host: dict[str, Any], collected_at: datetime) -> list[CollectorRecord]:
        host_id = self._str(host.get("id"))
        if not host_id:
            return []
        detail = self._get(f"/api/v1/fleet/hosts/{host_id}")
        detail_host = detail.get("host") if isinstance(detail, dict) else None
        if not isinstance(detail_host, dict):
            return []
        software = detail_host.get("software")
        if not isinstance(software, list):
            return []

        aliases = self._host_aliases(host)
        observed_at = self._parse_time(detail_host.get("software_updated_at")) or collected_at
        records: list[CollectorRecord] = []
        for item in software:
            if not isinstance(item, dict):
                continue
            vulns = item.get("vulnerabilities")
            if not isinstance(vulns, list) or not vulns:
                continue  # 취약점 없는 소프트웨어는 자산 목록이지 취약점이 아니다 → 적재하지 않음
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                records.append(
                    CollectorRecord(
                        source=self.source_name,
                        record_type="software_vuln",
                        observed_at=observed_at,
                        external_id=self._str(vuln.get("cve")) or self._str(item.get("id")),
                        host_aliases=aliases,
                        payload={
                            "host_id": host_id,
                            "hostname": self._str(host.get("hostname")),
                            "software": item,
                            "vulnerability": vuln,
                        },
                    )
                )
        return records

    # ── 정규화 ──────────────────────────────────────────────────────
    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        if record.record_type == "host":
            yield self._normalize_host(record)
            return
        if record.record_type == "software_vuln":
            yield self._normalize_vuln(record)
            return
        raise ValueError(f"Unsupported Fleet record_type: {record.record_type}")

    def _normalize_host(self, record: CollectorRecord) -> NormalizedEnvelope:
        host = record.payload
        alias = record.host_aliases[0] if record.host_aliases else None
        status = _HOST_STATUS.get(str(host.get("status") or "").lower(), "unknown")
        normalized = {
            "host_id": alias,
            "source_aliases": list(record.host_aliases),
            "hostname": self._str(host.get("hostname")) or alias,
            "platform": self._str(host.get("platform")),
            "primary_ip": self._str(host.get("primary_ip")),
            "status": status,
            "observation_type": "availability",
            "metric_name": "fleet_agent_status",
            "metric_value": "available" if status == "online" else "unavailable" if status == "offline" else "unknown",
            "os_version": self._str(host.get("os_version")),
            "osquery_version": self._str(host.get("osquery_version")),
        }
        return NormalizedEnvelope(
            entity_type="host_observation",
            entity_id=self._make_id("host", record, stable=True),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"fleet:host:{record.external_id}",
            normalized=normalized,
            raw_payload=host,
        )

    def _normalize_vuln(self, record: CollectorRecord) -> NormalizedEnvelope:
        payload = record.payload
        software = payload.get("software") if isinstance(payload.get("software"), dict) else {}
        vuln = payload.get("vulnerability") if isinstance(payload.get("vulnerability"), dict) else {}
        alias = record.host_aliases[0] if record.host_aliases else None
        normalized = {
            "host_id": alias,
            "source_aliases": list(record.host_aliases),
            "hostname": self._str(payload.get("hostname")) or alias,
            "cve": self._str(vuln.get("cve")),
            "severity": self._severity(vuln),
            "package_name": self._str(software.get("name")),
            "installed_version": self._str(software.get("version")),
            "fixed_version": self._str(vuln.get("resolved_in_version")),
        }
        return NormalizedEnvelope(
            entity_type="vulnerability",
            entity_id=self._make_id("vuln", record, stable=True),
            observed_at=record.observed_at,
            source=self.source_name,
            raw_ref=f"fleet:vuln:{record.external_id}",
            normalized=normalized,
            raw_payload=payload,
        )

    def _severity(self, vuln: dict[str, Any]) -> str:
        """CVSS 점수 → 심각도. 점수가 없으면 임의 추정하지 않고 ``info`` 로 둔다.

        (Fleet 무료판은 ``cvss_score`` 를 주지 않을 수 있다 — 그 경우 심각도는 미상이며,
        원본은 ``raw_payload`` 에 그대로 보존된다.)
        """
        score = vuln.get("cvss_score")
        if not isinstance(score, (int, float)):
            return "info"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    # ── 보조 ────────────────────────────────────────────────────────
    def _host_aliases(self, host: dict[str, Any]) -> list[str]:
        aliases: list[str] = []
        for candidate in (
            host.get("hostname"),
            host.get("computer_name"),
            host.get("uuid"),
            host.get("hardware_serial"),
            host.get("primary_ip"),
        ):
            text = self._str(candidate)
            if text and text not in aliases:
                aliases.append(text)
        return aliases

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self._api_url}{path}"
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        req = request.Request(url, headers={"Authorization": f"Bearer {self._token}"}, method="GET")
        context = None
        if not self._verify_tls:
            import ssl

            context = ssl._create_unverified_context()  # noqa: S323 — 사내 자체서명 인증서용 옵트인
        try:
            with request.urlopen(req, timeout=self._request_timeout, context=context) as response:
                body = response.read().decode("utf-8")
        except error.URLError as exc:  # 네트워크/HTTP 오류는 폴러의 재시도에 맡긴다
            raise RuntimeError(f"Fleet API request failed: {path}") from exc
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else {}

    def _make_id(self, prefix: str, record: CollectorRecord, *, stable: bool = False) -> str:
        parts = [self.source_name, prefix, str(record.external_id)]
        if prefix == "vuln":
            software = record.payload.get("software") or {}
            parts.append(str(software.get("name")))
            parts.append(str(software.get("version")))
            parts.append(str(record.payload.get("host_id")))
        if not stable:
            parts.append(record.observed_at.isoformat())
        digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
        return f"{prefix}-{digest[:16]}"

    def _parse_time(self, value: object) -> datetime | None:
        text = self._str(value)
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def _str(self, value: object) -> str | None:
        if isinstance(value, str):
            return value or None
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return None
