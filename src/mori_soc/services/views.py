"""Phase 1 논리 뷰 집계 레이어.

PHASE1_LOGICAL_SCHEMA.md §5 뷰 후보 3개를 Python 집계 함수로 구현합니다.
실제 Postgres 뷰가 도입되기 전까지 InMemoryQueryStore 위에서 동일한
집계 결과를 제공합니다.

- latest_host_status_view
- host_risk_summary_view
- host_timeline_view
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from mori_soc.services.query_service import InMemoryQueryStore


# ---------------------------------------------------------------------------
# latest_host_status_view
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class LatestHostStatusRow:
    """호스트별 최신 상태 + 마지막 관측 집계 행."""

    host_id: str
    hostname: str
    status: str
    risk_score: int
    last_seen_at: datetime | None
    last_alert_at: datetime | None
    last_observation_at: datetime | None


def latest_host_status_view(store: InMemoryQueryStore) -> list[LatestHostStatusRow]:
    """호스트별 최신 상태와 마지막 관측 시각을 집계한다.

    SQL 뷰 ``latest_host_status_view`` 의 Python 구현체입니다.

    같은 물리 호스트가 구형 host_id (prefix 없음) 와 신형 host_id (server-/pc- prefix)
    로 중복 저장된 경우 hostname 기준으로 dedup 하고, last_seen_at 이 가장 최신인 행만
    남긴다.
    """
    last_alert: dict[str, datetime] = {}
    for alert in store.alerts:
        if alert.host_id:
            prev = last_alert.get(alert.host_id)
            if prev is None or alert.observed_at > prev:
                last_alert[alert.host_id] = alert.observed_at

    last_obs: dict[str, datetime] = {}
    for obs in store.observations:
        prev = last_obs.get(obs.host_id)
        if prev is None or obs.observed_at > prev:
            last_obs[obs.host_id] = obs.observed_at

    _epoch = datetime.min.replace(tzinfo=timezone.utc)

    # hostname → best row (most recent last_seen_at; prefer prefixed host_id on tie)
    best: dict[str, LatestHostStatusRow] = {}
    for h in store.hosts:
        row = LatestHostStatusRow(
            host_id=h.host_id,
            hostname=h.hostname,
            status=h.status,
            risk_score=h.risk_score,
            last_seen_at=h.last_seen_at,
            last_alert_at=last_alert.get(h.host_id),
            last_observation_at=last_obs.get(h.host_id),
        )
        key = h.hostname.lower()
        existing = best.get(key)
        if existing is None:
            best[key] = row
        else:
            row_ts = row.last_seen_at or _epoch
            existing_ts = existing.last_seen_at or _epoch
            # prefer newer timestamp; on tie, prefer prefixed (canonical) host_id
            has_prefix = any(h.host_id.startswith(p) for p in ("server-", "pc-", "neutral-"))
            if row_ts > existing_ts or (row_ts == existing_ts and has_prefix):
                best[key] = row

    return list(best.values())


# ---------------------------------------------------------------------------
# host_risk_summary_view
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class HostRiskSummaryRow:
    """호스트별 위험 요약 집계 행."""

    host_id: str
    hostname: str
    risk_score: int
    alert_count_24h: int
    critical_alert_count_24h: int
    high_alert_count_24h: int
    vuln_count: int
    critical_vuln_count: int
    high_vuln_count: int


def host_risk_summary_view(
    store: InMemoryQueryStore,
    window: timedelta | None = None,
) -> list[HostRiskSummaryRow]:
    """alert 수 + vuln 수 기반 위험 요약을 집계한다.

    SQL 뷰 ``host_risk_summary_view`` 의 Python 구현체입니다.

    Parameters
    ----------
    store:
        조회 대상 InMemoryQueryStore
    window:
        alert 집계 창 (기본값: 24시간)
    """
    if window is None:
        window = timedelta(hours=24)
    since = datetime.now(tz=timezone.utc) - window

    alert_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for alert in store.alerts:
        if alert.host_id and alert.observed_at >= since:
            alert_counts[alert.host_id]["total"] += 1
            alert_counts[alert.host_id][alert.severity] += 1

    vuln_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for vuln in store.vulnerabilities:
        vuln_counts[vuln.host_id]["total"] += 1
        vuln_counts[vuln.host_id][vuln.severity] += 1

    # Build rows and deduplicate by hostname (same logic as latest_host_status_view)
    _epoch = datetime.min.replace(tzinfo=timezone.utc)
    best: dict[str, HostRiskSummaryRow] = {}
    for h in store.hosts:
        row = HostRiskSummaryRow(
            host_id=h.host_id,
            hostname=h.hostname,
            risk_score=h.risk_score,
            alert_count_24h=alert_counts[h.host_id]["total"],
            critical_alert_count_24h=alert_counts[h.host_id]["critical"],
            high_alert_count_24h=alert_counts[h.host_id]["high"],
            vuln_count=vuln_counts[h.host_id]["total"],
            critical_vuln_count=vuln_counts[h.host_id]["critical"],
            high_vuln_count=vuln_counts[h.host_id]["high"],
        )
        key = h.hostname.lower()
        existing = best.get(key)
        if existing is None:
            best[key] = row
        else:
            # prefer higher risk_score; on tie prefer prefixed host_id
            has_prefix = any(h.host_id.startswith(p) for p in ("server-", "pc-", "neutral-"))
            if row.risk_score > existing.risk_score or (
                row.risk_score == existing.risk_score and has_prefix
            ):
                best[key] = row

    rows = list(best.values())
    return sorted(rows, key=lambda r: (r.risk_score, r.alert_count_24h), reverse=True)


# ---------------------------------------------------------------------------
# host_timeline_view
# ---------------------------------------------------------------------------

TimelineEntityType = Literal["alert", "query_result", "observation"]


@dataclass(slots=True)
class HostTimelineEntry:
    """타임라인 병합 행 — alert / query_result / observation 공통 뷰."""

    entity_type: TimelineEntityType
    record_id: str
    host_id: str
    source: str
    observed_at: datetime
    summary: str
    severity: str | None = None
    raw_ref: str | None = None


def host_timeline_view(
    store: InMemoryQueryStore,
    host_id: str,
    since: datetime | None = None,
) -> list[HostTimelineEntry]:
    """alerts + query_results + observations 를 시간 역순으로 병합한다.

    SQL 뷰 ``host_timeline_view`` 의 Python 구현체입니다.
    """
    if since is None:
        since = datetime.now(tz=timezone.utc) - timedelta(hours=24)

    entries: list[HostTimelineEntry] = []

    for alert in store.alerts:
        if alert.host_id == host_id and alert.observed_at >= since:
            entries.append(
                HostTimelineEntry(
                    entity_type="alert",
                    record_id=alert.alert_id,
                    host_id=host_id,
                    source=alert.source,
                    observed_at=alert.observed_at,
                    summary=alert.message,
                    severity=alert.severity,
                    raw_ref=alert.raw_ref,
                )
            )

    for result in store.query_results:
        if result.host_id == host_id and result.observed_at >= since:
            entries.append(
                HostTimelineEntry(
                    entity_type="query_result",
                    record_id=result.query_result_id,
                    host_id=host_id,
                    source=result.source,
                    observed_at=result.observed_at,
                    summary=result.query_name or "fleet_query",
                    raw_ref=result.raw_ref,
                )
            )

    for obs in store.observations:
        if obs.host_id == host_id and obs.observed_at >= since:
            entries.append(
                HostTimelineEntry(
                    entity_type="observation",
                    record_id=obs.observation_id,
                    host_id=host_id,
                    source=obs.source,
                    observed_at=obs.observed_at,
                    summary=f"{obs.observation_type}:{obs.metric_name}",
                    severity=obs.severity,
                    raw_ref=obs.raw_ref,
                )
            )

    return sorted(entries, key=lambda e: e.observed_at, reverse=True)

