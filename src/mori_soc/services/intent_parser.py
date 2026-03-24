from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from mori_soc.api.contracts import QueryRequest, QueryScope

from .query_catalog import get_template_query


@dataclass(slots=True)
class InterpretationResult:
    request: QueryRequest
    matched_rules: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "intent": self.request.intent,
            "scope": asdict(self.request.scope),
            "filters": dict(self.request.filters),
            "matched_rules": list(self.matched_rules),
            "warnings": list(self.warnings),
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

        intent = _select_intent(lowered, matched_rules, has_host_scope=bool(host_id or hostname))
        template = get_template_query(intent)
        scope = QueryScope(
            time_range=time_range or (template.default_window if template else "24h"),
            host_id=host_id,
            hostname=hostname,
            severity=severity,
            source=source,
        )

        warnings: list[str] = []
        if template and "host_id" in template.required_filters and not (host_id or hostname):
            warnings.append("selected intent usually works best with host_id or hostname")

        return InterpretationResult(
            request=QueryRequest(intent=intent, scope=scope, filters=filters),
            matched_rules=matched_rules,
            warnings=warnings,
        )


def _select_intent(lowered: str, matched_rules: list[str], *, has_host_scope: bool) -> str:
    rules = (
        (("오프라인", "offline", "unavailable"), "offline_hosts", "intent:offline_hosts"),
        (("타임라인", "timeline"), "host_timeline", "intent:host_timeline"),
        (("미매핑", "unmapped"), "unmapped_assets", "intent:unmapped_assets"),
        (("로그인 실패", "login failure", "auth failed"), "login_failure_spike", "intent:login_failure_spike"),
        (("수집 오류", "collection error", "timeout", "체크 실패"), "collection_errors", "intent:collection_errors"),
        (("위험", "risky", "불안정"), "risky_hosts", "intent:risky_hosts"),
    )
    for keywords, intent, rule in rules:
        if any(keyword in lowered for keyword in keywords):
            matched_rules.append(rule)
            return intent
    if any(keyword in lowered for keyword in ("취약점", "vulnerability", "vuln")):
        if any(keyword in lowered for keyword in ("신규", "new", "새로")):
            matched_rules.append("intent:new_high_vulns")
            return "new_high_vulns"
        matched_rules.append("intent:top_vulnerable_hosts")
        return "top_vulnerable_hosts"
    if "fleet" in lowered and any(keyword in lowered for keyword in ("query", "쿼리")):
        matched_rules.append("intent:host_fleet_queries")
        return "host_fleet_queries"
    if "wazuh" in lowered and any(keyword in lowered for keyword in ("alert", "경보")):
        if has_host_scope:
            matched_rules.append("intent:host_wazuh_alerts")
            return "host_wazuh_alerts"
        matched_rules.append("intent:alert_summary(wazuh)")
        return "alert_summary"
    matched_rules.append("intent:alert_summary(default)")
    return "alert_summary"


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
    return None


def _extract_time_range(lowered: str, matched_rules: list[str]) -> str | None:
    candidates = (
        (("1h", "1시간"), "1h"),
        (("24h", "24시간", "지난 하루", "최근 하루"), "24h"),
        (("7d", "7일", "최근 7일", "지난 7일", "일주일"), "7d"),
        (("30d", "30일", "최근 30일", "한달"), "30d"),
    )
    for keywords, value in candidates:
        if any(keyword in lowered for keyword in keywords):
            matched_rules.append(f"scope:time_range={value}")
            return value
    return None


def _extract_severity(lowered: str, matched_rules: list[str]) -> str | None:
    severities = []
    if any(keyword in lowered for keyword in ("critical", "치명", "크리티컬")):
        severities.append("critical")
    if any(keyword in lowered for keyword in ("high", "높은", "고위험")):
        severities.append("high")
    if any(keyword in lowered for keyword in ("medium", "중간")):
        severities.append("medium")
    if not severities:
        return None
    matched_rules.append("scope:severity")
    return ",".join(dict.fromkeys(severities))


def _extract_source(lowered: str, matched_rules: list[str]) -> str | None:
    for keyword in ("wazuh", "fleet", "zabbix"):
        if keyword in lowered:
            matched_rules.append(f"scope:source={keyword}")
            return keyword
    return None


def _extract_limit(lowered: str, matched_rules: list[str]) -> int | None:
    match = re.search(r"(?:top|상위)\s*([0-9]+)", lowered)
    if not match:
        return None
    matched_rules.append("filters:limit")
    return int(match.group(1))


__all__ = ["InterpretationResult", "NaturalLanguageQueryParser"]