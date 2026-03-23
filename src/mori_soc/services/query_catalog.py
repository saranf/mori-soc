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
    TemplateQuery(
        query_id="host_wazuh_alerts",
        name="호스트 Wazuh 경보 조회",
        description="특정 호스트에서 최근 발생한 Wazuh alert만 조회한다.",
        intent="host_wazuh_alerts",
        default_window="24h",
        required_filters=("host_id",),
        evidence_sources=("alerts",),
    ),
    TemplateQuery(
        query_id="host_fleet_queries",
        name="호스트 Fleet 쿼리 결과 조회",
        description="특정 호스트의 최근 Fleet query 결과를 조회한다.",
        intent="host_fleet_queries",
        default_window="24h",
        required_filters=("host_id",),
        evidence_sources=("query_results",),
    ),
    TemplateQuery(
        query_id="new_high_vulns",
        name="신규 고위험 취약점",
        description="최근 새로 탐지된 high 이상 취약점을 조회한다.",
        intent="new_high_vulns",
        default_window="7d",
        required_filters=("time_range",),
        evidence_sources=("vulnerabilities",),
    ),
    TemplateQuery(
        query_id="risky_hosts",
        name="고위험 불안정 호스트",
        description="경보가 많으면서 동시에 상태가 불안정한 호스트를 조회한다.",
        intent="risky_hosts",
        default_window="24h",
        required_filters=("time_range",),
        evidence_sources=("alerts", "hosts"),
    ),
    TemplateQuery(
        query_id="unmapped_assets",
        name="미매핑 자산 조회",
        description="Fleet/Wazuh/Zabbix 중 하나라도 매핑되지 않은 자산을 조회한다.",
        intent="unmapped_assets",
        default_window="7d",
        required_filters=(),
        evidence_sources=("hosts", "host_aliases"),
    ),
    TemplateQuery(
        query_id="login_failure_spike",
        name="로그인 실패 급증 호스트",
        description="최근 로그인 실패가 많은 사용자 또는 호스트를 조회한다.",
        intent="login_failure_spike",
        default_window="24h",
        required_filters=("time_range",),
        evidence_sources=("alerts",),
    ),
    TemplateQuery(
        query_id="collection_errors",
        name="수집 오류 반복 호스트",
        description="최근 수집 오류 또는 상태 오류가 반복된 호스트를 조회한다.",
        intent="collection_errors",
        default_window="24h",
        required_filters=("time_range",),
        evidence_sources=("host_observations", "alerts"),
    ),
)


def get_template_query(intent: str) -> TemplateQuery | None:
    for query in PHASE1_QUERY_CATALOG:
        if query.intent == intent or query.query_id == intent:
            return query
    return None