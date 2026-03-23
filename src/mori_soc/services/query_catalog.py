from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TemplateQuery:
    query_id: str
    name: str
    description: str
    intent: str
    default_window: str
    required_filters: tuple[str, ...]
    evidence_sources: tuple[str, ...]


PHASE1_QUERY_CATALOG: tuple[TemplateQuery, ...] = (
    TemplateQuery(
        query_id="alert_summary_last_24h",
        name="최근 경보 요약",
        description="지난 24시간 high/critical alert 수와 주요 소스를 요약한다.",
        intent="alert_summary",
        default_window="24h",
        required_filters=("time_range",),
        evidence_sources=("alerts",),
    ),
    TemplateQuery(
        query_id="offline_hosts",
        name="오프라인 호스트 조회",
        description="현재 offline 또는 unavailable 상태 호스트를 조회한다.",
        intent="offline_hosts",
        default_window="1h",
        required_filters=(),
        evidence_sources=("hosts", "host_observations"),
    ),
    TemplateQuery(
        query_id="fleet_checkin_gap",
        name="Fleet 체크인 누락 호스트",
        description="Fleet 등록 자산 중 최근 체크인이 없는 호스트를 조회한다.",
        intent="fleet_checkin_gap",
        default_window="24h",
        required_filters=("time_range",),
        evidence_sources=("hosts", "host_observations", "query_results"),
    ),
    TemplateQuery(
        query_id="top_vulnerable_hosts",
        name="취약점 상위 호스트",
        description="취약점 수가 많은 호스트 Top N을 조회한다.",
        intent="top_vulnerable_hosts",
        default_window="7d",
        required_filters=("time_range",),
        evidence_sources=("vulnerabilities",),
    ),
    TemplateQuery(
        query_id="host_timeline",
        name="호스트 타임라인",
        description="특정 호스트의 최근 alert/query/observation 타임라인을 조회한다.",
        intent="host_timeline",
        default_window="24h",
        required_filters=("host_id",),
        evidence_sources=("host_timeline_view",),
    ),
)


def get_template_query(intent: str) -> TemplateQuery | None:
    for query in PHASE1_QUERY_CATALOG:
        if query.intent == intent or query.query_id == intent:
            return query
    return None