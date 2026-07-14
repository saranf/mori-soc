"""Fleet REST API 수집기 — 호스트(자산) + 로컬 계정 + 소프트웨어 취약점.

스키마 근거는 **실제 Fleet 응답 캡처**(``tests/fixtures/fleet/``, F0)이며 추측이 아니다.

수집 경로
---------
``GET /api/v1/fleet/hosts``       → 호스트 목록   → ``host_observation``
``GET /api/v1/fleet/hosts/{id}``  → ``users[]``   → **로컬 계정**(계정 거버넌스, ``host_accounts``)
                                  → ``software[]`` → ``vulnerability``

상세는 **호스트당 1회만** 호출해 계정·취약점을 함께 뽑는다.

로컬 계정은 정규화 엔티티가 아니라 UI 운영 store(``host_accounts``) 라 매퍼를 타지 않는다 —
:attr:`FleetApiCollector.host_accounts` 에 모아두고 ``FleetPoller.post_ingest`` 가 저장한다.
민감정보이므로 **admin 이 어드민 콘솔에서 끄면 수집하지 않는다**(``account_collect_enabled``).

.. warning::
   Fleet 무료판은 ``cvss_score`` 를 주지 않아 **모든 취약점이 ``severity=info``** 로 적재된다
   → "미조치 Critical/High" 집계에 잡히지 않는다. **취약점 판단은 Trivy 를 기준**으로 하고,
   Fleet 취약점은 참고용으로 본다(추정 심각도를 지어내지 않는다).

호스트 ID 접두사(``pc-``)는 **여기서 붙이지 않는다** — ``normalization.ASSET_BUCKET_BY_SOURCE``
가 ``fleet → pc`` 로 스코프를 부여한다. 수집기는 원본 hostname 을 alias 로만 넘긴다.
``primary_ip`` 는 **유니크할 때만** 신원 별칭 — VPN/NAT 로 IP 를 공유하면 서로 다른 단말이
한 host_id 로 병합되므로 공유 IP 는 제외한다.

osquery 로그(status/result)는 이미 fluent-bit → Loki 로 흐르므로 여기서 다시 수집하지 않는다
(MORI 는 증적 층 — 로그 조회는 Grafana/Loki 위임). 그 경로는 :mod:`collectors.fleet_logs` 참고.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib import error, parse, request

from mori_soc.services.account_recon import normalize_account

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope

logger = logging.getLogger("mori.collector.fleet")

# 페이지네이션 방어 상한(서버가 계속 꽉 찬 페이지를 주는 이상 상황 대비)
_MAX_PAGES = 200

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
        host_limit: int = 5000,
        page_size: int = 500,
        include_software: bool = True,
        include_accounts: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._token = token
        self._request_timeout = request_timeout
        self._host_limit = max(1, host_limit)
        self._page_size = max(1, min(page_size, host_limit))
        self._include_software = include_software
        self._include_accounts = include_accounts
        self._verify_tls = verify_tls
        # 수집 배치 안에서 2대 이상이 공유하는 primary_ip. 신원 별칭에서 제외한다.
        self._shared_ips: frozenset[str] = frozenset()
        # 이번 사이클에서 모은 로컬 계정: host_key → [normalize_account(...)]
        # host_accounts 는 정규화 엔티티가 아니라 UI 운영 store 라 매퍼를 타지 않는다.
        # FleetPoller.post_ingest 가 StateRepository 로 직접 저장한다.
        self.host_accounts: dict[str, list[dict[str, Any]]] = {}
        self._no_cvss = 0   # CVSS 점수 없는 취약점 수(사이클당) — 안내 로그용

    @property
    def source_name(self) -> str:
        return "fleet"

    # ── 수집 ────────────────────────────────────────────────────────
    def _fetch_hosts(self) -> list[dict[str, Any]]:
        """호스트 목록을 **페이지 끝까지** 가져온다.

        Fleet 은 ``page``(0-based)·``per_page`` 로 페이지네이션한다. 한 번만 호출하면
        페이지 크기를 넘는 호스트가 **조용히 누락**되는데, 자산 인벤토리에서 조용한 누락은
        곧 "대상 범위 불명확" 결함이다. 그래서 끝까지 돌고, 상한(``host_limit``)에 걸려
        잘리면 **경고를 남긴다**(조용히 버리지 않는다).
        """
        hosts: list[dict[str, Any]] = []
        page = 0
        while True:
            payload = self._get(
                "/api/v1/fleet/hosts", {"page": page, "per_page": self._page_size}
            )
            batch = payload.get("hosts") if isinstance(payload, dict) else None
            if not isinstance(batch, list) or not batch:
                break
            hosts.extend(h for h in batch if isinstance(h, dict))

            if len(hosts) >= self._host_limit:
                logger.warning(
                    "[fleet] 호스트 상한(%d)에 도달해 이후 호스트를 수집하지 않습니다 — "
                    "누락 없이 받으려면 MORI_FLEET_HOST_LIMIT 를 늘리세요.",
                    self._host_limit,
                )
                return hosts[: self._host_limit]
            if len(batch) < self._page_size:
                break  # 마지막 페이지
            page += 1
            if page >= _MAX_PAGES:  # 서버가 계속 꽉 찬 페이지를 주는 이상 상황 방어
                logger.warning(
                    "[fleet] 페이지 상한(%d)에 도달해 중단합니다 — 수집된 호스트 %d대.",
                    _MAX_PAGES, len(hosts),
                )
                break
        return hosts

    def collect(self) -> Iterable[CollectorRecord]:
        collected_at = datetime.now(tz=timezone.utc)
        hosts = self._fetch_hosts()
        if not hosts:
            return []

        # VPN/NAT 뒤의 단말은 primary_ip 를 공유한다. IP 를 신원 별칭으로 쓰면 서로 다른
        # 호스트가 한 host_id 로 병합돼 버리므로(공유 IP → 1대로 붕괴), 공유 IP 는 제외한다.
        self._shared_ips = self._shared_primary_ips(hosts)
        self.host_accounts = {}

        self._no_cvss = 0
        records: list[CollectorRecord] = []
        for host in hosts:
            if not isinstance(host, dict):
                continue
            records.append(self._host_record(host, collected_at))
            if self._include_software or self._include_accounts:
                records.extend(self._detail_records(host, collected_at))

        # 안내: Fleet 무료판은 cvss_score 를 주지 않아 심각도를 매길 수 없다 → 전부 info 로
        # 적재되고 "미조치 Critical/High" 집계에 잡히지 않는다. 취약점 판단은 Trivy 를 기준으로.
        if self._no_cvss:
            logger.warning(
                "[fleet] 취약점 %d건에 CVSS 점수가 없어 severity=info 로 적재됩니다 "
                "(Fleet 무료판 특성) — Critical/High 집계에 잡히지 않으니 취약점은 Trivy 기준으로 보세요.",
                self._no_cvss,
            )
        return records

    def _shared_primary_ips(self, hosts: list[Any]) -> frozenset[str]:
        """2대 이상이 공유하는 primary_ip 집합 (신원 별칭 제외 대상)."""
        counts: dict[str, int] = {}
        for host in hosts:
            if not isinstance(host, dict):
                continue
            ip = self._str(host.get("primary_ip"))
            if ip:
                counts[ip] = counts.get(ip, 0) + 1
        return frozenset(ip for ip, n in counts.items() if n > 1)

    def _host_record(self, host: dict[str, Any], collected_at: datetime) -> CollectorRecord:
        return CollectorRecord(
            source=self.source_name,
            record_type="host",
            observed_at=self._parse_time(host.get("seen_time")) or collected_at,
            external_id=self._str(host.get("id")),
            host_aliases=self._host_aliases(host),
            payload=host,
        )

    def _detail_records(self, host: dict[str, Any], collected_at: datetime) -> list[CollectorRecord]:
        """호스트 상세 1회 조회로 **취약점 + 로컬 계정**을 함께 뽑는다(요청 중복 방지)."""
        host_id = self._str(host.get("id"))
        if not host_id:
            return []
        detail = self._get(f"/api/v1/fleet/hosts/{host_id}")
        detail_host = detail.get("host") if isinstance(detail, dict) else None
        if not isinstance(detail_host, dict):
            return []

        # 로컬 계정(osquery users) — 계정 거버넌스용. 정규화 엔티티가 아니라 UI store 라
        # 레코드로 내보내지 않고 수집기에 모아둔다(FleetPoller.post_ingest 가 저장).
        if self._include_accounts:
            self._capture_accounts(host, detail_host)

        if not self._include_software:
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
            self._no_cvss += 1
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

    # ── 로컬 계정 (osquery users → 계정 거버넌스) ──────────────────────
    def _capture_accounts(self, host: dict[str, Any], detail_host: dict[str, Any]) -> None:
        """Fleet 호스트 상세의 ``users[]`` → host_accounts 저장 형태로 정규화해 모은다.

        Fleet users 항목: ``{uid, username, type, groupname, shell}``.
        sudo 여부는 별도 필드가 없으므로 그룹(wheel/sudo/admin)·uid 0 으로 판정한다
        (``normalize_account`` 이 API push 경로와 동일 규칙을 적용).
        """
        users = detail_host.get("users")
        if not isinstance(users, list):
            return
        host_key = self._str(host.get("hostname")) or self._str(host.get("computer_name"))
        if not host_key:
            return
        # Fleet 은 PC/노트북 인벤토리 → host_type=pc
        accounts: list[dict[str, Any]] = []
        seen: set[str] = set()
        for u in users:
            if not isinstance(u, dict):
                continue
            username = self._str(u.get("username"))
            if not username or username in seen:
                continue
            seen.add(username)
            groupname = self._str(u.get("groupname"))
            accounts.append(
                normalize_account(
                    {
                        "username": username,
                        "uid": u.get("uid"),
                        "gid": u.get("gid"),
                        "shell": self._str(u.get("shell")),
                        "directory": self._str(u.get("directory")),
                        "groups": [groupname] if groupname else [],
                        "source": "fleet",
                    },
                    "pc",
                )
            )
        if accounts:
            self.host_accounts[host_key] = accounts

    # ── 보조 ────────────────────────────────────────────────────────
    def _host_aliases(self, host: dict[str, Any]) -> list[str]:
        aliases: list[str] = []
        for candidate in (
            host.get("hostname"),
            host.get("computer_name"),
            host.get("uuid"),
            host.get("hardware_serial"),
        ):
            text = self._str(candidate)
            if text and text not in aliases:
                aliases.append(text)
        # primary_ip 는 **유니크할 때만** 신원 별칭으로 쓴다. VPN/NAT 로 IP 를 공유하면
        # 서로 다른 단말이 한 host_id 로 병합되므로 제외한다(값 자체는 primary_ip 로 보존).
        ip = self._str(host.get("primary_ip"))
        if ip and ip not in self._shared_ips and ip not in aliases:
            aliases.append(ip)
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
