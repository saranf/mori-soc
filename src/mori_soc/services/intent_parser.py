from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from mori_soc.api.contracts import QueryRequest, QueryScope

from .query_catalog import get_template_query


QUERY_GUIDE_EXAMPLES = (
    "오프라인 호스트 보여줘",
    "최근 24시간 wazuh high alert 요약",
    "host-1 타임라인 보여줘",
    "mbp-01 호스트 최근 활동 보여줘",
    "fleet 체크인 안 한 호스트 보여줘",
    "host-1 fleet query 결과 보여줘",
    "취약점 많은 호스트 top 5",
    "최근 7일 trivy high 취약점 보여줘",
)


@dataclass(slots=True)
class InterpretationResult:
    request: QueryRequest
    matched_rules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recognized: bool = True
    guide_examples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "intent": self.request.intent,
            "scope": asdict(self.request.scope),
            "filters": dict(self.request.filters),
            "matched_rules": list(self.matched_rules),
            "warnings": list(self.warnings),
            "recognized": self.recognized,
            "guide_examples": list(self.guide_examples),
        }


class NaturalLanguageQueryParser:
    def interpret(self, text: str) -> InterpretationResult:
        question = text.strip()
        if not question:
            raise ValueError("text must be a non-empty string")

        lowered = question.lower()
        matched_rules: list[str] = []
        filters: dict[str, object] = {}
        host_id = _extract_host_id(lowered, matched_rules)
        hostname = _extract_hostname(question, matched_rules)
        time_range = _extract_time_range(lowered, matched_rules)
        severity = _extract_severity(lowered, matched_rules)
        source = _extract_source(lowered, matched_rules)
        limit = _extract_limit(lowered, matched_rules)
        if limit is not None:
            filters["limit"] = limit

        intent, recognized = _select_intent(lowered, matched_rules, has_host_scope=bool(host_id or hostname))
        template = get_template_query(intent)
        scope = QueryScope(
            time_range=time_range or (template.default_window if template else "24h"),
            host_id=host_id,
            hostname=hostname,
            severity=severity,
            source=source,
        )

        warnings: list[str] = []
        if not recognized:
            warnings.append("질문 의도를 정확히 해석하지 못했습니다. 아래 가이드 예시처럼 질문해 주세요.")
        if template and "host_id" in template.required_filters and not (host_id or hostname):
            warnings.append("selected intent usually works best with host_id or hostname")

        return InterpretationResult(
            request=QueryRequest(intent=intent, scope=scope, filters=filters),
            matched_rules=matched_rules,
            warnings=warnings,
            recognized=recognized,
            guide_examples=list(QUERY_GUIDE_EXAMPLES),
        )


def _select_intent(lowered: str, matched_rules: list[str], *, has_host_scope: bool) -> tuple[str, bool]:
    if _contains_any(lowered, ("fleet", "플릿", "osquery")) and _contains_any(
        lowered,
        ("체크인", "checkin", "check-in", "last seen", "마지막 체크인", "미체크인"),
    ) and _contains_any(lowered, ("안", "없", "누락", "오래", "missing", "stale", "gap")):
        matched_rules.append("intent:fleet_checkin_gap")
        return "fleet_checkin_gap", True

    if _contains_any(lowered, ("fleet", "플릿", "osquery")) and _contains_any(
        lowered,
        ("query", "쿼리", "결과", "result"),
    ):
        matched_rules.append("intent:host_fleet_queries")
        return "host_fleet_queries", True

    if _contains_any(lowered, ("wazuh", "와주", "와즈")) and _contains_any(
        lowered,
        ("alert", "경보", "탐지", "이벤트"),
    ):
        if has_host_scope:
            matched_rules.append("intent:host_wazuh_alerts")
            return "host_wazuh_alerts", True
        matched_rules.append("intent:alert_summary(wazuh)")
        return "alert_summary", True

    rules = (
        (("오프라인", "offline", "unavailable", "down", "응답 없", "연결 안", "다운", "죽은"), "offline_hosts", "intent:offline_hosts"),
        (("타임라인", "timeline", "최근 활동", "활동 이력", "이력", "history", "무슨 일"), "host_timeline", "intent:host_timeline"),
        (("미매핑", "unmapped", "매핑 안 된", "연결 안 된 자산", "누락 자산"), "unmapped_assets", "intent:unmapped_assets"),
        (("로그인 실패", "login failure", "auth failed", "인증 실패", "failed password", "brute force"), "login_failure_spike", "intent:login_failure_spike"),
        (("수집 오류", "collection error", "collector error", "sync error", "동기화 실패", "동기화 오류", "timeout", "체크 실패"), "collection_errors", "intent:collection_errors"),
        (("위험", "risky", "불안정", "문제 많은", "리스크 높은", "위험도 높은"), "risky_hosts", "intent:risky_hosts"),
    )
    for keywords, intent, rule in rules:
        if _contains_any(lowered, keywords):
            matched_rules.append(rule)
            return intent, True

    if _contains_any(lowered, ("취약점", "vulnerability", "vuln", "cve", "트리비", "trivy")):
        if _contains_any(lowered, ("top", "상위", "랭킹", "많은 호스트", "취약점 많은", "most")):
            matched_rules.append("intent:top_vulnerable_hosts")
            return "top_vulnerable_hosts", True
        matched_rules.append("intent:new_high_vulns")
        return "new_high_vulns", True

    if _contains_any(lowered, ("alert", "경보", "탐지", "이벤트")) and _contains_any(
        lowered,
        ("요약", "summary", "현황", "정리", "보여줘"),
    ):
        matched_rules.append("intent:alert_summary(generic)")
        return "alert_summary", True

    matched_rules.append("intent:alert_summary(fallback)")
    return "alert_summary", False


def _extract_host_id(lowered: str, matched_rules: list[str]) -> str | None:
    match = re.search(r"\bhost-[a-z0-9_-]+\b", lowered)
    if not match:
        return None
    matched_rules.append("scope:host_id")
    return match.group(0)


def _extract_hostname(question: str, matched_rules: list[str]) -> str | None:
    quoted = re.search(r"['\"]([^'\"]+)['\"]", question)
    if quoted:
        matched_rules.append("scope:hostname(quoted)")
        return quoted.group(1).strip() or None
    explicit = re.search(r"(?:hostname|호스트명)\s*[:=]?\s*([A-Za-z0-9._-]+)", question, re.IGNORECASE)
    if explicit:
        matched_rules.append("scope:hostname(explicit)")
        return explicit.group(1)
    contextual_patterns = (
        (r"(?:호스트|host)(?:\s*[:=]\s*|\s+)([A-Za-z0-9._-]+)", "scope:hostname(context-prefix)"),
        (r"([A-Za-z0-9._-]+)\s+(?:호스트|host)\b", "scope:hostname(context-suffix)"),
        (r"([A-Za-z0-9._-]+)\s*(?:타임라인|timeline|최근 활동|활동 이력|이력|history)", "scope:hostname(activity)"),
    )
    for pattern, rule in contextual_patterns:
        match = re.search(pattern, question, re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1)
        if _looks_like_host_id(candidate):
            continue
        if _looks_like_hostname(candidate):
            matched_rules.append(rule)
            return candidate
    return None


def _extract_time_range(lowered: str, matched_rules: list[str]) -> str | None:
    candidates = (
        (("1h", "1시간", "최근 1시간", "지난 1시간", "한시간"), "1h"),
        (("24h", "24시간", "지난 하루", "최근 하루", "오늘", "금일"), "24h"),
        (("7d", "7일", "최근 7일", "지난 7일", "일주일", "일주일간"), "7d"),
        (("30d", "30일", "최근 30일", "한달", "최근 한달", "지난 한달"), "30d"),
    )
    for keywords, value in candidates:
        if _contains_any(lowered, keywords):
            matched_rules.append(f"scope:time_range={value}")
            return value
    return None


def _extract_severity(lowered: str, matched_rules: list[str]) -> str | None:
    severities = []
    if _contains_any(lowered, ("critical", "치명", "크리티컬", "중대")):
        severities.append("critical")
    if _contains_any(lowered, ("high", "높은", "고위험", "심각")):
        severities.append("high")
    if _contains_any(lowered, ("medium", "중간", "보통")):
        severities.append("medium")
    if not severities:
        return None
    matched_rules.append("scope:severity")
    return ",".join(dict.fromkeys(severities))


def _extract_source(lowered: str, matched_rules: list[str]) -> str | None:
    source_aliases = {
        "wazuh": ("wazuh", "와주", "와즈"),
        "fleet": ("fleet", "플릿", "osquery"),
        "zabbix": ("zabbix", "자빅스"),
        "trivy": ("trivy", "트리비"),
    }
    for source, keywords in source_aliases.items():
        if _contains_any(lowered, keywords):
            matched_rules.append(f"scope:source={source}")
            return source
    return None


def _extract_limit(lowered: str, matched_rules: list[str]) -> int | None:
    match = re.search(r"(?:top|상위)\s*([0-9]+)", lowered)
    if not match:
        return None
    matched_rules.append("filters:limit")
    return int(match.group(1))


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in text for keyword in keywords)


def _looks_like_hostname(value: str) -> bool:
    return bool(value) and (any(char.isdigit() for char in value) or any(char in value for char in ("-", ".", "_")))


def _looks_like_host_id(value: str) -> bool:
    return bool(re.fullmatch(r"host-[A-Za-z0-9_-]+", value))


__all__ = ["InterpretationResult", "NaturalLanguageQueryParser", "QUERY_GUIDE_EXAMPLES"]