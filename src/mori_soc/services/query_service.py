from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from mori_soc.api.contracts import EvidenceRef, QueryRequest, QueryResponse
from mori_soc.models import Alert, Host, HostObservation, QueryResult, Vulnerability

from .query_catalog import get_template_query


@dataclass(slots=True)
class InMemoryQueryStore:
    hosts: list[Host] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)
    observations: list[HostObservation] = field(default_factory=list)


class QueryService:
    def __init__(self, store: InMemoryQueryStore) -> None:
        self.store = store

    def execute(self, request: QueryRequest) -> QueryResponse:
        template = get_template_query(request.intent)
        if template is None:
            return QueryResponse(
                summary=f"Unsupported query intent: {request.intent}",
                filters={**request.filters, "time_range": request.scope.time_range},
                evidence=[],
                meta={"intent": request.intent, "supported": False},
            )

        if template.intent == "alert_summary":
            return self._alert_summary(request, template.query_id)
        if template.intent == "offline_hosts":
            return self._offline_hosts(request, template.query_id)
        if template.intent == "top_vulnerable_hosts":
            return self._top_vulnerable_hosts(request, template.query_id)
        if template.intent == "host_timeline":
            return self._host_timeline(request, template.query_id)
        if template.intent == "fleet_checkin_gap":
            return self._fleet_checkin_gap(request, template.query_id)

        return QueryResponse(
            summary=f"Intent recognized but not implemented: {template.intent}",
            filters={**request.filters, "time_range": request.scope.time_range},
            evidence=[],
            meta={"intent": template.intent, "supported": False},
        )

    def _alert_summary(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        severities = self._severity_filter(request.scope.severity) or {"high", "critical"}
        alerts = [
            alert for alert in self.store.alerts if alert.observed_at >= since and alert.severity in severities
        ]
        source_counts = Counter(alert.source for alert in alerts)
        top_sources = ", ".join(f"{source}:{count}" for source, count in source_counts.most_common(3)) or "none"
        evidence = [
            EvidenceRef(
                source=alert.source,
                record_id=alert.alert_id,
                raw_ref=alert.raw_ref,
                summary=alert.message,
            )
            for alert in sorted(alerts, key=lambda item: item.observed_at, reverse=True)[:5]
        ]
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 동안 {len(alerts)}건의 high/critical alert가 있었고 주요 소스는 {top_sources} 입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(alerts)},
        )

    def _offline_hosts(self, request: QueryRequest, query_id: str) -> QueryResponse:
        offline_hosts = [host for host in self.store.hosts if host.status == "offline"]
        evidence = [
            EvidenceRef(source="hosts", record_id=host.host_id, summary=host.hostname) for host in offline_hosts[:10]
        ]
        names = ", ".join(host.hostname for host in offline_hosts[:5]) or "없음"
        return QueryResponse(
            summary=f"현재 offline 상태 호스트는 {len(offline_hosts)}대이며 대표 호스트는 {names} 입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(offline_hosts)},
        )

    def _top_vulnerable_hosts(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        counts: dict[str, int] = defaultdict(int)
        for vuln in self.store.vulnerabilities:
            if vuln.detected_at >= since:
                counts[vuln.host_id] += 1
        ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        hostnames = {host.host_id: host.hostname for host in self.store.hosts}
        evidence = [
            EvidenceRef(source="vulnerabilities", record_id=host_id, summary=f"{hostnames.get(host_id, host_id)}:{count}")
            for host_id, count in ranked[:10]
        ]
        summary = ", ".join(f"{hostnames.get(host_id, host_id)}({count})" for host_id, count in ranked[:5]) or "없음"
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 기준 취약점 상위 호스트는 {summary} 입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(ranked)},
        )

    def _host_timeline(self, request: QueryRequest, query_id: str) -> QueryResponse:
        host_id = self._resolve_host_id(request)
        since = self._since(request.scope.time_range)
        timeline: list[EvidenceRef] = []
        if host_id is None:
            return QueryResponse(
                summary="host_timeline 질의에는 host_id 또는 hostname이 필요합니다.",
                filters=self._filters(request),
                evidence=[],
                meta={"query_id": query_id, "count": 0},
            )
        for alert in self.store.alerts:
            if alert.host_id == host_id and alert.observed_at >= since:
                timeline.append(EvidenceRef(alert.source, alert.alert_id, alert.raw_ref, alert.message))
        for result in self.store.query_results:
            if result.host_id == host_id and result.observed_at >= since:
                timeline.append(EvidenceRef(result.source, result.query_result_id, result.raw_ref, result.query_name))
        for observation in self.store.observations:
            if observation.host_id == host_id and observation.observed_at >= since:
                timeline.append(
                    EvidenceRef(
                        observation.source,
                        observation.observation_id,
                        observation.raw_ref,
                        f"{observation.observation_type}:{observation.metric_name}",
                    )
                )
        return QueryResponse(
            summary=f"호스트 {host_id}의 최근 {request.scope.time_range} 타임라인 이벤트는 {len(timeline)}건입니다.",
            filters=self._filters(request),
            evidence=timeline[:20],
            meta={"query_id": query_id, "count": len(timeline), "host_id": host_id},
        )

    def _fleet_checkin_gap(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        latest_checkins: dict[str, datetime] = {}
        for observation in self.store.observations:
            if observation.source == "fleet" and observation.metric_name == "fleet_status":
                latest = latest_checkins.get(observation.host_id)
                if latest is None or observation.observed_at > latest:
                    latest_checkins[observation.host_id] = observation.observed_at
        stale_hosts = [
            host for host in self.store.hosts if host.host_id not in latest_checkins or latest_checkins[host.host_id] < since
        ]
        evidence = [EvidenceRef(source="fleet", record_id=host.host_id, summary=host.hostname) for host in stale_hosts[:10]]
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 안에 Fleet 체크인이 없거나 오래된 호스트는 {len(stale_hosts)}대입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(stale_hosts)},
        )

    def _since(self, time_range: str) -> datetime:
        amount = int(time_range[:-1])
        unit = time_range[-1]
        mapping = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}
        delta = mapping.get(unit, timedelta(hours=24))
        return datetime.now(tz=timezone.utc) - delta

    def _severity_filter(self, severity: str | None) -> set[str] | None:
        if not severity:
            return None
        return {part.strip() for part in severity.split(",") if part.strip()}

    def _resolve_host_id(self, request: QueryRequest) -> str | None:
        if request.scope.host_id:
            return request.scope.host_id
        if request.scope.hostname:
            for host in self.store.hosts:
                if host.hostname == request.scope.hostname:
                    return host.host_id
        return None

    def _filters(self, request: QueryRequest) -> dict[str, str]:
        filters = {"time_range": request.scope.time_range}
        if request.scope.host_id:
            filters["host_id"] = request.scope.host_id
        if request.scope.hostname:
            filters["hostname"] = request.scope.hostname
        if request.scope.severity:
            filters["severity"] = request.scope.severity
        if request.scope.source:
            filters["source"] = request.scope.source
        for key, value in request.filters.items():
            filters[key] = str(value)
        return filters