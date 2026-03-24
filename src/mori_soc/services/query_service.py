from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from mori_soc.api.contracts import EvidenceRef, QueryRequest, QueryResponse
from mori_soc.models import Alert, Host, HostAlias, HostObservation, QueryResult, SourceSync, Vulnerability

from .query_catalog import get_template_query


@dataclass(slots=True)
class InMemoryQueryStore:
    hosts: list[Host] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)
    observations: list[HostObservation] = field(default_factory=list)
    host_aliases: list[HostAlias] = field(default_factory=list)
    source_syncs: list[SourceSync] = field(default_factory=list)


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
        if template.intent == "host_wazuh_alerts":
            return self._host_wazuh_alerts(request, template.query_id)
        if template.intent == "host_fleet_queries":
            return self._host_fleet_queries(request, template.query_id)
        if template.intent == "new_high_vulns":
            return self._new_high_vulns(request, template.query_id)
        if template.intent == "risky_hosts":
            return self._risky_hosts(request, template.query_id)
        if template.intent == "unmapped_assets":
            return self._unmapped_assets(request, template.query_id)
        if template.intent == "login_failure_spike":
            return self._login_failure_spike(request, template.query_id)
        if template.intent == "collection_errors":
            return self._collection_errors(request, template.query_id)

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
            alert
            for alert in self.store.alerts
            if alert.observed_at >= since
            and alert.severity in severities
            and self._matches_source(alert.source, request.scope.source)
        ]
        source_counts = Counter(alert.source for alert in alerts)
        top_sources = ", ".join(f"{source}:{count}" for source, count in source_counts.most_common(3)) or "none"
        severity_label = request.scope.severity or "high/critical"
        source_label = f"{request.scope.source} " if request.scope.source else ""
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
            summary=f"최근 {request.scope.time_range} 동안 {len(alerts)}건의 {source_label}{severity_label} alert가 있었고 주요 소스는 {top_sources} 입니다.",
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
        limit = self._limit(request, default=5)
        counts: dict[str, int] = defaultdict(int)
        for vuln in self.store.vulnerabilities:
            if vuln.detected_at >= since and self._matches_source(vuln.source, request.scope.source):
                counts[vuln.host_id] += 1
        ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        hostnames = {host.host_id: host.hostname for host in self.store.hosts}
        evidence = [
            EvidenceRef(source="vulnerabilities", record_id=host_id, summary=f"{hostnames.get(host_id, host_id)}:{count}")
            for host_id, count in ranked[:limit]
        ]
        summary = ", ".join(f"{hostnames.get(host_id, host_id)}({count})" for host_id, count in ranked[:limit]) or "없음"
        source_label = f"{request.scope.source} " if request.scope.source else ""
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 기준 {source_label}취약점 상위 호스트는 {summary} 입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(ranked), "limit": limit},
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

    def _host_wazuh_alerts(self, request: QueryRequest, query_id: str) -> QueryResponse:
        host_id = self._resolve_host_id(request)
        since = self._since(request.scope.time_range)
        if host_id is None:
            return QueryResponse(
                summary="host_wazuh_alerts 질의에는 host_id 또는 hostname이 필요합니다.",
                filters=self._filters(request),
                evidence=[],
                meta={"query_id": query_id, "count": 0},
            )
        alerts = [
            a for a in self.store.alerts
            if a.host_id == host_id and a.source == "wazuh" and a.observed_at >= since
        ]
        alerts = sorted(alerts, key=lambda a: a.observed_at, reverse=True)
        evidence = [
            EvidenceRef(source=a.source, record_id=a.alert_id, raw_ref=a.raw_ref, summary=a.message)
            for a in alerts[:10]
        ]
        return QueryResponse(
            summary=f"호스트 {host_id}의 최근 {request.scope.time_range} Wazuh 경보는 {len(alerts)}건입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(alerts), "host_id": host_id},
        )

    def _host_fleet_queries(self, request: QueryRequest, query_id: str) -> QueryResponse:
        host_id = self._resolve_host_id(request)
        since = self._since(request.scope.time_range)
        if host_id is None:
            return QueryResponse(
                summary="host_fleet_queries 질의에는 host_id 또는 hostname이 필요합니다.",
                filters=self._filters(request),
                evidence=[],
                meta={"query_id": query_id, "count": 0},
            )
        results = [
            r for r in self.store.query_results
            if r.host_id == host_id and r.source == "fleet" and r.observed_at >= since
        ]
        results = sorted(results, key=lambda r: r.observed_at, reverse=True)
        evidence = [
            EvidenceRef(source=r.source, record_id=r.query_result_id, raw_ref=r.raw_ref, summary=r.query_name or "fleet_query")
            for r in results[:10]
        ]
        return QueryResponse(
            summary=f"호스트 {host_id}의 최근 {request.scope.time_range} Fleet query 결과는 {len(results)}건입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(results), "host_id": host_id},
        )

    def _new_high_vulns(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        high_severities = {"critical", "high"}
        vulns = [
            v for v in self.store.vulnerabilities
            if v.severity in high_severities
            and v.detected_at >= since
            and self._matches_source(v.source, request.scope.source)
        ]
        vulns = sorted(vulns, key=lambda v: v.detected_at, reverse=True)
        hostnames = {h.host_id: h.hostname for h in self.store.hosts}
        evidence = [
            EvidenceRef(
                source=v.source,
                record_id=v.vuln_id,
                raw_ref=v.raw_ref,
                summary=f"{hostnames.get(v.host_id, v.host_id)} / {v.cve or 'no-cve'} ({v.severity})",
            )
            for v in vulns[:10]
        ]
        source_label = f"{request.scope.source} " if request.scope.source else ""
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 새로 탐지된 {source_label}high 이상 취약점은 {len(vulns)}건입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(vulns)},
        )

    def _risky_hosts(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        alert_counts: dict[str, int] = defaultdict(int)
        for alert in self.store.alerts:
            if alert.observed_at >= since and alert.severity in {"critical", "high"} and alert.host_id:
                alert_counts[alert.host_id] += 1
        unstable_statuses = {"offline", "unknown"}
        risky = [
            h for h in self.store.hosts
            if alert_counts[h.host_id] > 0 or h.status in unstable_statuses
        ]
        risky = sorted(risky, key=lambda h: (alert_counts[h.host_id], h.risk_score), reverse=True)
        evidence = [
            EvidenceRef(
                source="hosts",
                record_id=h.host_id,
                raw_ref=None,
                summary=f"{h.hostname} (alerts:{alert_counts[h.host_id]}, status:{h.status}, risk:{h.risk_score})",
            )
            for h in risky[:10]
        ]
        return QueryResponse(
            summary=f"경보가 많거나 상태가 불안정한 호스트는 {len(risky)}대입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(risky)},
        )

    def _unmapped_assets(self, request: QueryRequest, query_id: str) -> QueryResponse:
        sources_per_host: dict[str, set[str]] = defaultdict(set)
        for alias in self.store.host_aliases:
            sources_per_host[alias.host_id].add(alias.source)
        target_sources = {"fleet", "wazuh", "zabbix"}
        unmapped = [
            h for h in self.store.hosts
            if not target_sources.issubset(sources_per_host[h.host_id])
        ]
        evidence = [
            EvidenceRef(
                source="hosts",
                record_id=h.host_id,
                raw_ref=None,
                summary=f"{h.hostname} (매핑된 소스: {', '.join(sorted(sources_per_host[h.host_id])) or '없음'})",
            )
            for h in unmapped[:10]
        ]
        return QueryResponse(
            summary=f"Fleet/Wazuh/Zabbix 중 하나라도 매핑되지 않은 자산은 {len(unmapped)}대입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(unmapped)},
        )

    def _login_failure_spike(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        login_keywords = {"login", "authentication", "auth", "logon", "pam", "sshd", "failed"}
        failure_alerts = [
            a for a in self.store.alerts
            if a.observed_at >= since
            and any(kw in (a.rule_name or "").lower() or kw in a.message.lower() for kw in login_keywords)
        ]
        host_counts: dict[str, int] = defaultdict(int)
        for a in failure_alerts:
            if a.host_id:
                host_counts[a.host_id] += 1
        ranked = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
        hostnames = {h.host_id: h.hostname for h in self.store.hosts}
        evidence = [
            EvidenceRef(source="alerts", record_id=host_id, raw_ref=None,
                        summary=f"{hostnames.get(host_id, host_id)}: {count}건")
            for host_id, count in ranked[:10]
        ]
        top = ", ".join(f"{hostnames.get(hid, hid)}({cnt})" for hid, cnt in ranked[:3]) or "없음"
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 로그인 실패가 많은 호스트는 {top} 입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(ranked)},
        )

    def _collection_errors(self, request: QueryRequest, query_id: str) -> QueryResponse:
        since = self._since(request.scope.time_range)
        error_keywords = {"error", "fail", "timeout", "unreachable", "unavailable"}
        error_obs = [
            o for o in self.store.observations
            if o.observed_at >= since
            and any(kw in (o.observation_type or "").lower() or kw in (o.metric_name or "").lower() for kw in error_keywords)
        ]
        error_alerts = [
            a for a in self.store.alerts
            if a.observed_at >= since
            and any(kw in (a.rule_name or "").lower() for kw in error_keywords)
        ]
        host_counts: dict[str, int] = defaultdict(int)
        for o in error_obs:
            host_counts[o.host_id] += 1
        for a in error_alerts:
            if a.host_id:
                host_counts[a.host_id] += 1
        ranked = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
        hostnames = {h.host_id: h.hostname for h in self.store.hosts}
        evidence = [
            EvidenceRef(source="observations", record_id=host_id, raw_ref=None,
                        summary=f"{hostnames.get(host_id, host_id)}: {count}건")
            for host_id, count in ranked[:10]
        ]
        top = ", ".join(f"{hostnames.get(hid, hid)}({cnt})" for hid, cnt in ranked[:3]) or "없음"
        return QueryResponse(
            summary=f"최근 {request.scope.time_range} 수집 오류가 반복된 호스트는 {top} 입니다.",
            filters=self._filters(request),
            evidence=evidence,
            meta={"query_id": query_id, "count": len(ranked)},
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

    def _matches_source(self, candidate: str, requested: str | None) -> bool:
        return requested is None or candidate == requested

    def _limit(self, request: QueryRequest, default: int = 10, maximum: int = 100) -> int:
        value = request.filters.get("limit")
        if value is None:
            return default
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return max(1, min(parsed, maximum))