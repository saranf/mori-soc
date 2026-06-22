from __future__ import annotations

import json
import logging
import os
import uuid
import urllib.request
import urllib.error
from urllib.parse import quote as _url_quote
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.services.intent_parser import QUERY_GUIDE_EXAMPLES, NaturalLanguageQueryParser
from mori_soc.services.query_catalog import PHASE1_QUERY_CATALOG
from mori_soc.services.query_service import InMemoryQueryStore, QueryService, query_response_to_csv
from mori_soc.services.reports import REPORT_TYPES, generate_report, report_to_csv, report_to_pdf
from mori_soc.services.views import host_risk_summary_view, latest_host_status_view
from mori_soc.api.templates import (
    render_login_html,
    render_signup_request_html,
    render_user_dashboard_html,
    render_query_console_html,
    DEFAULT_UI_PAYLOAD,
    DOCS_PORTAL_URL,
    FLEET_UI_URL,
    ZABBIX_UI_URL,
    USER_DASHBOARD_CARD_LABELS,
    USER_DASHBOARD_SECTION_LABELS,
    USER_DASHBOARD_ASSET_COLUMN_LABELS,
    USER_DASHBOARD_GUIDE_LABELS,
    DEFAULT_USER_DASHBOARD_PREFERENCES,
)

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    FastAPI = None
    HTTPException = None
    HTMLResponse = None
    RedirectResponse = None
    StreamingResponse = None

try:
    from ldap3 import Server as _LdapServer, Connection as _LdapConnection, ALL as _LDAP_ALL, SUBTREE as _LDAP_SUBTREE
    _ldap3_available = True
except ImportError:  # pragma: no cover
    _LdapServer = None
    _LdapConnection = None
    _LDAP_ALL = None
    _LDAP_SUBTREE = None
    _ldap3_available = False


logger = logging.getLogger("mori_soc.api")


# Placeholder password patterns that indicate operators have not customised .env.
# Used by `_warn_insecure_defaults` at app startup to emit audit-visible warnings.
_INSECURE_PLACEHOLDER_PREFIXES = ("change_this_", "generate_with_")
_INSECURE_CHECKED_ENV_VARS = (
    "MORI_DB_PASSWORD",
    "MORI_LDAP_BIND_PASSWORD",
    "LDAP_ADMIN_PASSWORD",
    "ZABBIX_DB_PASSWORD",
    "FLEET_DB_PASSWORD",
    "FLEET_DB_ROOT_PASSWORD",
    "FLEET_SERVER_PRIVATE_KEY",
)


def _warn_insecure_defaults() -> list[str]:
    """Scan critical env vars for placeholder values and emit warning logs.

    Returns the list of variable names still using placeholders so callers
    (e.g. /health) can surface the result without re-reading the environment.
    """
    flagged: list[str] = []
    for name in _INSECURE_CHECKED_ENV_VARS:
        value = os.environ.get(name, "")
        if not value:
            continue
        if any(value.startswith(prefix) for prefix in _INSECURE_PLACEHOLDER_PREFIXES):
            flagged.append(name)
    admin_pw = os.environ.get("MORI_ADMIN_PASSWORD", "1234")
    if admin_pw in ("1234", "admin", "password"):
        flagged.append("MORI_ADMIN_PASSWORD")
    if flagged:
        logger.warning(
            "[security] insecure default credentials detected for: %s — update .env before production use",
            ", ".join(flagged),
        )
    return flagged


def create_query_service(store: InMemoryQueryStore | None = None) -> QueryService:
    return QueryService(store or InMemoryQueryStore())


def create_query_service_from_env() -> QueryService:
    database_url = os.getenv("MORI_DATABASE_URL", "").strip()
    backend = os.getenv("MORI_QUERY_BACKEND", "postgres" if database_url else "memory").strip().lower()
    if backend == "memory":
        return create_query_service()
    if backend == "postgres":
        if not database_url:
            raise RuntimeError("MORI_DATABASE_URL must be set when MORI_QUERY_BACKEND=postgres")
        from mori_soc.repositories import PostgresRepository, snapshot_to_query_store

        repository = PostgresRepository(database_url)
        return QueryService(snapshot_to_query_store(repository.snapshot()))
    raise RuntimeError(f"Unsupported MORI_QUERY_BACKEND: {backend}")


def build_query_request(payload: Mapping[str, Any]) -> QueryRequest:
    intent = payload.get("intent")
    if not isinstance(intent, str) or not intent.strip():
        raise ValueError("query payload must include a non-empty string intent")

    scope_payload = payload.get("scope") or {}
    if not isinstance(scope_payload, Mapping):
        raise ValueError("query payload scope must be an object")

    filters_payload = payload.get("filters") or {}
    if not isinstance(filters_payload, Mapping):
        raise ValueError("query payload filters must be an object")

    scope = QueryScope(
        time_range=_optional_string(scope_payload.get("time_range")) or "24h",
        host_id=_optional_string(scope_payload.get("host_id")),
        hostname=_optional_string(scope_payload.get("hostname")),
        severity=_optional_string(scope_payload.get("severity")),
        source=_optional_string(scope_payload.get("source")),
    )
    return QueryRequest(intent=intent.strip(), scope=scope, filters=dict(filters_payload))


def interpret_query_text(text: str) -> dict[str, Any]:
    return NaturalLanguageQueryParser().interpret(text).to_dict()


def build_dashboard_payload(
    service: QueryService,
    *,
    asset_owners: Mapping[str, dict[str, Any]] | None = None,
    vuln_actions: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    store = service.store
    _owners: Mapping[str, dict[str, Any]] = asset_owners or {}
    _vuln_actions: Mapping[str, Mapping[str, Any]] = vuln_actions or {}
    now = datetime.now(tz=timezone.utc)
    since_24h = now - timedelta(hours=24)
    status_rows = sorted(latest_host_status_view(store), key=_latest_status_sort_key)
    risk_rows = host_risk_summary_view(store)
    source_coverage = _source_coverage(store)
    hostnames = {host.host_id: host.hostname for host in store.hosts}

    alerts_24h = [
        alert for alert in store.alerts if alert.observed_at >= since_24h and alert.severity in {"high", "critical"}
    ]
    overview = {
        "total_hosts": len(status_rows),
        "online_hosts": sum(1 for row in status_rows if row.status == "online"),
        "offline_hosts": sum(1 for row in status_rows if row.status == "offline"),
        "unknown_hosts": sum(1 for row in status_rows if row.status not in {"online", "offline"}),
        "alerts_24h": len(alerts_24h),
        "critical_vulns": sum(1 for vuln in store.vulnerabilities if vuln.severity == "critical"),
        "high_vulns": sum(1 for vuln in store.vulnerabilities if vuln.severity == "high"),
        "sources_reporting": sum(1 for item in source_coverage if item["host_count"] > 0),
        "sources_healthy": sum(1 for item in source_coverage if item["status"] == "success" and not item.get("is_stale")),
        "ingested_records": len(store.alerts)
        + len(store.vulnerabilities)
        + len(store.query_results)
        + len(store.observations),
    }

    return {
        "generated_at": _isoformat(now),
        "overview": overview,
        "overview_details": {
            "total_hosts": _status_detail_rows(status_rows),
            "offline_hosts": _status_detail_rows([row for row in status_rows if row.status == "offline"]),
            "alerts_24h": _alert_detail_rows(alerts_24h, hostnames, _owners),
            "critical_vulns": _critical_vuln_detail_rows(store, hostnames, _owners, _vuln_actions),
            "sources_reporting": [item for item in source_coverage if item["host_count"] > 0],
            "sources_healthy": [item for item in source_coverage if item["status"] == "success" and not item.get("is_stale")],
            "ingested_records": _ingested_record_rows(store),
        },
        "source_coverage": source_coverage,
        "latest_status": _status_detail_rows(status_rows[:8]),
        "risk_summary": [
            {
                "host_id": row.host_id,
                "hostname": row.hostname,
                "risk_score": row.risk_score,
                "alert_count_24h": row.alert_count_24h,
                "critical_alert_count_24h": row.critical_alert_count_24h,
                "high_alert_count_24h": row.high_alert_count_24h,
                "vuln_count": row.vuln_count,
                "critical_vuln_count": row.critical_vuln_count,
                "high_vuln_count": row.high_vuln_count,
            }
            for row in risk_rows[:8]
        ],
        "recent_activity": _recent_activity(store),
        "recommended_queries": _recommended_queries(),
    }


def build_pdca_payload(
    service: QueryService,
    *,
    vuln_actions: Mapping[str, Mapping[str, Any]] | None = None,
    alert_triage: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compliance PDCA 대시보드용 집계 데이터를 생성한다.

    `vuln_actions`/`alert_triage`가 주어지면 Trivy critical/high 취약점과
    미해결 critical/high alerts를 pending_remediations에 source 태그와 함께 추가한다.
    """
    store = service.store
    checks = store.control_checks
    now = datetime.now(tz=timezone.utc)
    vuln_actions_map: Mapping[str, Mapping[str, Any]] = vuln_actions or {}
    alert_triage_map: Mapping[str, Mapping[str, Any]] = alert_triage or {}

    # Status 별 카운트
    status_counts: dict[str, int] = {"pass": 0, "fail": 0, "warning": 0, "not_applicable": 0, "not_checked": 0}
    for c in checks:
        status_counts[c.status] = status_counts.get(c.status, 0) + 1

    total = len(checks)
    checked = total - status_counts["not_checked"] - status_counts["not_applicable"]
    pass_rate = round(status_counts["pass"] / checked * 100, 1) if checked > 0 else 0.0

    # Control category 별 집계 (control_id 첫 부분 — e.g. "A.8" or "2.5")
    by_category: dict[str, dict[str, int]] = {}
    for c in checks:
        parts = c.control_id.rsplit(".", 1)
        cat = parts[0] if len(parts) > 1 else c.control_id
        bucket = by_category.setdefault(cat, {"pass": 0, "fail": 0, "warning": 0, "not_applicable": 0, "not_checked": 0, "total": 0})
        bucket[c.status] = bucket.get(c.status, 0) + 1
        bucket["total"] += 1

    categories = [
        {"category": cat, **counts}
        for cat, counts in sorted(by_category.items())
    ]

    # 미조치 항목 (fail + warning, remediation_due_at 기준 정렬)
    pending: list[dict[str, Any]] = []
    for c in checks:
        if c.status in {"fail", "warning"}:
            pending.append({
                "check_id": c.check_id,
                "control_id": c.control_id,
                "entity_type": c.entity_type,
                "entity_id": c.entity_id,
                "status": c.status,
                "checked_at": _isoformat(c.checked_at),
                "owner": c.owner or "",
                "note": c.note or "",
                "remediation_due_at": _isoformat(c.remediation_due_at) if c.remediation_due_at else None,
                "overdue": c.remediation_due_at is not None and c.remediation_due_at < now and c.resolved_at is None,
                "source": "control_check",
            })

    # ── Trivy critical/high 취약점 → 미조치 ───────────────────────────────────
    hostnames = {h.host_id: h.hostname for h in store.hosts}
    trivy_high_count = 0
    for v in store.vulnerabilities:
        if v.source != "trivy" or v.severity not in {"critical", "high"}:
            continue
        if v.resolved_at is not None:
            continue
        action = vuln_actions_map.get(v.vuln_id, {})
        ex_until_str = str(action.get("exception_until", "")).strip()
        ex_active = False
        if ex_until_str:
            try:
                ex_dt = datetime.fromisoformat(ex_until_str.replace("Z", "+00:00"))
                if ex_dt.tzinfo is None:
                    ex_dt = ex_dt.replace(tzinfo=timezone.utc)
                ex_active = ex_dt > now
            except ValueError:
                ex_active = False
        if ex_active:
            continue
        plan_target_str = str(action.get("plan_target_date", "")).strip()
        due_dt = None
        if plan_target_str:
            try:
                due_dt = datetime.fromisoformat(plan_target_str.replace("Z", "+00:00"))
                if due_dt.tzinfo is None:
                    due_dt = due_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                due_dt = None
        cve_label = v.cve or v.vuln_id
        pkg_label = f" · {v.package_name}" if v.package_name else ""
        pending.append({
            "check_id": v.vuln_id,
            "control_id": "A.8.8",
            "entity_type": "host",
            "entity_id": hostnames.get(v.host_id, v.host_id),
            "status": "fail" if v.severity == "critical" else "warning",
            "checked_at": _isoformat(v.detected_at) if v.detected_at else None,
            "owner": str(action.get("plan_updated_by", "") or ""),
            "note": f"{cve_label} ({v.severity}){pkg_label}",
            "remediation_due_at": _isoformat(due_dt) if due_dt else None,
            "overdue": due_dt is not None and due_dt < now,
            "source": "trivy",
        })
        trivy_high_count += 1

    # ── 미해결 critical/high alerts → 미조치 (최근 7일) ───────────────────────
    alert_window_start = now - timedelta(days=7)
    alert_high_count = 0
    for a in store.alerts:
        if a.severity not in {"critical", "high"}:
            continue
        if a.observed_at < alert_window_start:
            continue
        triage = alert_triage_map.get(a.alert_id, {})
        if str(triage.get("status", "")).strip() == "resolved":
            continue
        pending.append({
            "check_id": a.alert_id,
            "control_id": "A.5.24",
            "entity_type": "host",
            "entity_id": hostnames.get(a.host_id or "", a.host_id or "-"),
            "status": "fail" if a.severity == "critical" else "warning",
            "checked_at": _isoformat(a.observed_at),
            "owner": str(triage.get("analyst", "") or ""),
            "note": f"[{a.source}] {a.message}",
            "remediation_due_at": None,
            "overdue": False,
            "source": "alert",
        })
        alert_high_count += 1

    pending.sort(key=lambda x: (0 if x["overdue"] else 1, x.get("remediation_due_at") or "9999"))

    # PDCA 단계 매핑 — Trivy/Alert 미조치도 Do 단계에 포함
    pdca = {
        "plan": status_counts["not_checked"],
        "do": status_counts["warning"] + status_counts["fail"] + trivy_high_count + alert_high_count,
        "check": checked,
        "act": status_counts["pass"],
    }

    return {
        "generated_at": _isoformat(now),
        "total_checks": total,
        "status_counts": status_counts,
        "pass_rate": pass_rate,
        "pdca": pdca,
        "categories": categories,
        "pending_remediations": pending,
        "pending_count": len(pending),
        "overdue_count": sum(1 for p in pending if p["overdue"]),
        "pending_sources": {
            "control_check": sum(1 for p in pending if p["source"] == "control_check"),
            "trivy": trivy_high_count,
            "alert": alert_high_count,
        },
    }


def build_crosscheck_payload(service: QueryService) -> dict[str, Any]:
    """소스 간 교차 검증 데이터를 생성한다."""
    store = service.store
    now = datetime.now(tz=timezone.utc)

    # Host IDs grouped by source (실제 등록된 호스트만)
    all_host_ids = {h.host_id for h in store.hosts}
    source_host_ids: dict[str, set[str]] = {}
    for alias in store.host_aliases:
        if alias.host_id in all_host_ids:
            source_host_ids.setdefault(alias.source, set()).add(alias.host_id)
    hostnames = {h.host_id: h.hostname for h in store.hosts}
    fleet_ids = source_host_ids.get("fleet", set())
    zabbix_ids = source_host_ids.get("zabbix", set())
    trivy_ids = source_host_ids.get("trivy", set())
    wazuh_ids = source_host_ids.get("wazuh", set())

    # 1) Zabbix vs Fleet
    zabbix_only = zabbix_ids - fleet_ids
    fleet_only = fleet_ids - zabbix_ids
    zabbix_fleet_both = zabbix_ids & fleet_ids

    # 2) Source coverage vs total hosts
    any_source = set()
    for ids in source_host_ids.values():
        any_source |= ids
    no_source = all_host_ids - any_source

    # 3) Vuln hosts vs recent observation hosts (30d)
    since_30d = now - timedelta(days=30)
    vuln_host_ids = {v.host_id for v in store.vulnerabilities}
    # 실제 등록된 호스트에 대한 관측만 카운트 (고아 observation 제외)
    recent_obs_ids = {o.host_id for o in store.observations if o.observed_at >= since_30d and o.host_id in all_host_ids}
    vuln_no_obs = vuln_host_ids - recent_obs_ids

    # 4) LDAP accounts vs host owners (if any directory accounts exist)
    ldap_accounts = {a.username for a in store.directory_accounts}

    # Sources per host for detail
    sources_per_host: dict[str, list[str]] = {}
    for alias in store.host_aliases:
        sources_per_host.setdefault(alias.host_id, [])
        if alias.source not in sources_per_host[alias.host_id]:
            sources_per_host[alias.host_id].append(alias.source)

    def _host_row(hid: str) -> dict[str, Any]:
        return {"host_id": hid, "hostname": hostnames.get(hid, hid), "sources": sources_per_host.get(hid, [])}

    return {
        "generated_at": _isoformat(now),
        "checks": [
            {
                "id": "zabbix_vs_fleet",
                "title": "Zabbix 자산 vs Fleet 자산",
                "description": "Zabbix(서버)와 Fleet(PC)에서 수집된 자산을 교차 비교합니다.",
                "zabbix_count": len(zabbix_ids),
                "fleet_count": len(fleet_ids),
                "both_count": len(zabbix_fleet_both),
                "zabbix_only_count": len(zabbix_only),
                "fleet_only_count": len(fleet_only),
                "zabbix_only": sorted([_host_row(h) for h in zabbix_only], key=lambda x: x["hostname"])[:50],
                "fleet_only": sorted([_host_row(h) for h in fleet_only], key=lambda x: x["hostname"])[:50],
            },
            {
                "id": "source_coverage",
                "title": "소스 커버리지 vs 전체 자산",
                "description": "모든 수집 소스에서 한 번도 관측되지 않은 자산을 찾습니다.",
                "total_hosts": len(all_host_ids),
                "covered_hosts": len(any_source),
                "uncovered_hosts": len(no_source),
                "all_hosts": sorted([_host_row(h) for h in all_host_ids], key=lambda x: x["hostname"])[:200],
                "covered": sorted([_host_row(h) for h in any_source], key=lambda x: x["hostname"])[:200],
                "uncovered": sorted([_host_row(h) for h in no_source], key=lambda x: x["hostname"])[:50],
            },
            {
                "id": "vuln_vs_observation",
                "title": "취약점 자산 vs 최근 관측 자산",
                "description": "취약점이 존재하지만 최근 30일 내 관측(로그/메트릭)이 없는 자산을 찾습니다.",
                "vuln_hosts": len(vuln_host_ids),
                "recent_obs_hosts": len(recent_obs_ids),
                "vuln_no_observation_count": len(vuln_no_obs),
                "vuln_no_observation": sorted([_host_row(h) for h in vuln_no_obs], key=lambda x: x["hostname"])[:50],
            },
            {
                "id": "ldap_summary",
                "title": "LDAP/AD 계정 현황",
                "description": "디렉터리 계정 수와 권한 바인딩 현황을 요약합니다.",
                "total_accounts": len(store.directory_accounts),
                "privileged_accounts": sum(1 for a in store.directory_accounts if a.is_privileged),
                "total_privilege_bindings": len(store.privilege_bindings),
                "total_group_memberships": len(store.group_memberships),
            },
        ],
    }


def build_assets_payload(
    service: QueryService,
    owners: dict[str, dict[str, Any]] | None = None,
    plans: dict[str, dict[str, Any]] | None = None,
    vuln_actions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from mori_soc.services.asset_classifier import classify_server_as_dict

    owners = owners or {}
    plans = plans or {}
    vuln_actions = vuln_actions or {}
    store = service.store
    now = datetime.now(tz=timezone.utc)

    # Build sets of host IDs by source using aliases
    fleet_host_ids: set[str] = set()
    zabbix_host_ids: set[str] = set()
    for alias in store.host_aliases:
        if alias.source == "fleet":
            fleet_host_ids.add(alias.host_id)
        elif alias.source == "zabbix":
            zabbix_host_ids.add(alias.host_id)

    # Also classify by host_id prefix for hosts without aliases
    for host in store.hosts:
        hid = host.host_id
        if hid.startswith("pc-") and hid not in fleet_host_ids and hid not in zabbix_host_ids:
            fleet_host_ids.add(hid)
        elif hid.startswith("server-") and hid not in zabbix_host_ids and hid not in fleet_host_ids:
            zabbix_host_ids.add(hid)

    hostnames = {h.host_id: h.hostname for h in store.hosts}

    # Fleet hosts (PC assets) — PC는 자산 분류 불필요, 담당자만 표시
    fleet_hosts = []
    for host in store.hosts:
        if host.host_id not in fleet_host_ids:
            continue
        qr_count = sum(1 for qr in store.query_results if qr.host_id == host.host_id)
        owner_info = owners.get(host.hostname, {})
        plan = plans.get(host.host_id, {})
        fleet_hosts.append({
            "host_id": host.host_id,
            "hostname": host.hostname,
            "asset_type": "PC",
            "platform": host.platform or "-",
            "primary_ip": host.primary_ip or "-",
            "status": host.status,
            "risk_score": host.risk_score,
            "last_seen_at": _isoformat(host.last_seen_at) if host.last_seen_at else None,
            "query_result_count": qr_count,
            "owner": owner_info.get("owner", ""),
            "team": owner_info.get("team", ""),
            "exception_until": owner_info.get("exception_until", ""),
            "exception_reason": owner_info.get("exception_reason", ""),
            "action_plan": plan.get("text", ""),
            "action_target_date": plan.get("target_date", ""),
        })
    fleet_hosts.sort(key=lambda h: (h["status"] != "offline", h["hostname"]))

    # Zabbix hosts (Server assets) — 호스트명 기반 자동 분류 + 담당자
    zabbix_hosts = []
    for host in store.hosts:
        if host.host_id not in zabbix_host_ids:
            continue
        obs = [o for o in store.observations if o.host_id == host.host_id and o.source == "zabbix"]
        obs.sort(key=lambda o: o.observed_at, reverse=True)
        classification = classify_server_as_dict(host.hostname)
        owner_info = owners.get(host.hostname, {})
        plan = plans.get(host.host_id, {})
        # Admin-set importance/category override auto-classification
        effective_category = owner_info.get("category") or classification["category"]
        effective_importance = owner_info.get("importance") or classification["importance"]
        zabbix_hosts.append({
            "host_id": host.host_id,
            "hostname": host.hostname,
            "asset_type": "Server",
            "category": effective_category,
            "importance": effective_importance,
            "isms_control": classification["isms_control"],
            "iso27001_control": classification.get("iso27001_control", ""),
            "platform": host.platform or "-",
            "primary_ip": host.primary_ip or "-",
            "status": host.status,
            "risk_score": host.risk_score,
            "last_seen_at": _isoformat(host.last_seen_at) if host.last_seen_at else None,
            "latest_metric": obs[0].metric_name if obs else None,
            "latest_value": obs[0].metric_value if obs else None,
            "observation_count": len(obs),
            "owner": owner_info.get("owner", ""),
            "team": owner_info.get("team", ""),
            "exception_until": owner_info.get("exception_until", ""),
            "exception_reason": owner_info.get("exception_reason", ""),
            "action_plan": plan.get("text", ""),
            "action_target_date": plan.get("target_date", ""),
        })
    zabbix_hosts.sort(key=lambda h: (
        {"상": 0, "중": 1, "하": 2}.get(h["importance"], 1),
        h["status"] != "offline",
        h["hostname"],
    ))

    # Trivy vulnerabilities grouped by host — 조치계획 포함
    vuln_by_host: dict[str, dict] = {}
    vuln_lists: dict[str, list[dict[str, Any]]] = {}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for vuln in store.vulnerabilities:
        if vuln.source != "trivy":
            continue
        hid = vuln.host_id
        if hid not in vuln_by_host:
            plan = plans.get(hid, {})
            hostname_val = hostnames.get(hid, hid)
            owner_info = owners.get(hostname_val, {})
            vuln_by_host[hid] = {
                "host_id": hid,
                "hostname": hostname_val,
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "total": 0,
                "latest_cve": None,
                "latest_detected_at": None,
                "action_plan": plan.get("text", ""),
                "action_target_date": plan.get("target_date", ""),
                "action_updated_by": plan.get("updated_by", ""),
                "exception_until": owner_info.get("exception_until", ""),
            }
            vuln_lists[hid] = []
        entry = vuln_by_host[hid]
        sev = vuln.severity
        entry[sev] = entry.get(sev, 0) + 1
        entry["total"] += 1
        if entry["latest_detected_at"] is None or vuln.detected_at > entry["latest_detected_at"]:
            entry["latest_detected_at"] = vuln.detected_at
            entry["latest_cve"] = vuln.cve
        action = vuln_actions.get(vuln.vuln_id, {})
        vuln_lists[hid].append({
            "vuln_id": vuln.vuln_id,
            "cve": vuln.cve or "",
            "severity": sev,
            "package_name": vuln.package_name or "",
            "installed_version": vuln.installed_version or "",
            "fixed_version": vuln.fixed_version or "",
            "detected_at": _isoformat(vuln.detected_at) if vuln.detected_at else "",
            "plan_text": action.get("plan_text", ""),
            "plan_target_date": action.get("plan_target_date", ""),
            "plan_updated_by": action.get("plan_updated_by", ""),
            "exception_until": action.get("exception_until", ""),
            "exception_reason": action.get("exception_reason", ""),
            "exception_updated_by": action.get("exception_updated_by", ""),
            "action_updated_at": action.get("updated_at", ""),
        })

    trivy_rows = sorted(vuln_by_host.values(), key=lambda r: (-r["critical"], -r["high"], -r["total"]))
    for row in trivy_rows:
        if row["latest_detected_at"]:
            row["latest_detected_at"] = _isoformat(row["latest_detected_at"])
        vlist = vuln_lists.get(row["host_id"], [])
        # severity 오름차순 (critical 먼저), 동일 severity 내에서는 detected_at 내림차순
        vlist.sort(key=lambda v: (sev_order.get(v["severity"], 9), v["detected_at"]))
        vlist.reverse()
        vlist.sort(key=lambda v: sev_order.get(v["severity"], 9))
        row["vulns"] = vlist
        # CVE별 상세 계획/예외 존재 여부 — UI에서 host-level 편집을 안내 모달로 전환
        plans_count = sum(1 for v in vlist if v.get("plan_text"))
        exceptions_count = sum(1 for v in vlist if v.get("exception_until"))
        row["vuln_plans_count"] = plans_count
        row["vuln_exceptions_count"] = exceptions_count
        row["has_vuln_plans"] = plans_count > 0
        row["has_vuln_exceptions"] = exceptions_count > 0

    return {
        "generated_at": _isoformat(now),
        "fleet": {
            "hosts": fleet_hosts,
            "total": len(fleet_hosts),
            "online": sum(1 for h in fleet_hosts if h["status"] == "online"),
            "offline": sum(1 for h in fleet_hosts if h["status"] == "offline"),
        },
        "zabbix": {
            "hosts": zabbix_hosts,
            "total": len(zabbix_hosts),
            "online": sum(1 for h in zabbix_hosts if h["status"] == "online"),
            "offline": sum(1 for h in zabbix_hosts if h["status"] == "offline"),
        },
        "trivy": {
            "rows": trivy_rows,
            "total_vulns": sum(r["total"] for r in trivy_rows),
            "critical": sum(r["critical"] for r in trivy_rows),
            "high": sum(r["high"] for r in trivy_rows),
            "affected_hosts": len(trivy_rows),
        },
    }


def _assets_csv(payload: dict[str, Any], source: str) -> str:
    import csv
    import io
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL)
    if source == "fleet":
        writer.writerow(["호스트ID", "호스트명", "자산유형", "플랫폼", "IP주소", "상태",
                         "위험점수", "최종확인일시", "쿼리결과수", "담당자", "팀"])
        for h in payload["fleet"]["hosts"]:
            writer.writerow([
                h["host_id"], h["hostname"], h["asset_type"], h["platform"], h["primary_ip"],
                h["status"], h["risk_score"], h["last_seen_at"] or "", h["query_result_count"],
                h.get("owner", ""), h.get("team", ""),
            ])
    elif source == "zabbix":
        writer.writerow(["호스트ID", "호스트명", "분류", "중요도", "플랫폼",
                         "IP주소", "상태", "위험점수", "최종확인일시",
                         "관측수", "최근메트릭", "최근값", "담당자", "팀"])
        for h in payload["zabbix"]["hosts"]:
            writer.writerow([
                h["host_id"], h["hostname"], h.get("category", ""), h.get("importance", ""),
                h["platform"], h["primary_ip"],
                h["status"], h["risk_score"], h["last_seen_at"] or "",
                h["observation_count"], h["latest_metric"] or "", h["latest_value"] or "",
                h.get("owner", ""), h.get("team", ""),
            ])
    elif source == "trivy":
        writer.writerow(["호스트ID", "호스트명", "심각", "높음", "중간", "낮음", "정보", "합계",
                         "최근CVE", "탐지일", "조치계획", "목표완료일", "작성자"])
        for r in payload["trivy"]["rows"]:
            writer.writerow([
                r["host_id"], r["hostname"], r["critical"], r["high"], r["medium"],
                r["low"], r["info"], r["total"], r["latest_cve"] or "", r["latest_detected_at"] or "",
                r.get("action_plan", ""), r.get("action_target_date", ""), r.get("action_updated_by", ""),
            ])
    return out.getvalue()


def _default_dashboard_preferences() -> dict[str, Any]:
    return {
        "docs_url": DOCS_PORTAL_URL,
        "user_dashboard": {
            "cards": dict(DEFAULT_USER_DASHBOARD_PREFERENCES["cards"]),
            "sections": dict(DEFAULT_USER_DASHBOARD_PREFERENCES["sections"]),
            "asset_columns": dict(DEFAULT_USER_DASHBOARD_PREFERENCES["asset_columns"]),
        },
    }


def _dashboard_preferences_response(preferences: Mapping[str, Any]) -> dict[str, Any]:
    docs_url = preferences.get("docs_url") if isinstance(preferences.get("docs_url"), str) else DOCS_PORTAL_URL
    user_dashboard = preferences.get("user_dashboard") if isinstance(preferences.get("user_dashboard"), Mapping) else {}
    cards = user_dashboard.get("cards") if isinstance(user_dashboard.get("cards"), Mapping) else {}
    sections = user_dashboard.get("sections") if isinstance(user_dashboard.get("sections"), Mapping) else {}
    asset_columns = user_dashboard.get("asset_columns") if isinstance(user_dashboard.get("asset_columns"), Mapping) else {}
    guides = user_dashboard.get("guides") if isinstance(user_dashboard.get("guides"), Mapping) else {}
    return {
        "docs_url": docs_url,
        "user_dashboard": {
            "cards": {
                key: bool(cards.get(key, DEFAULT_USER_DASHBOARD_PREFERENCES["cards"][key]))
                for key in USER_DASHBOARD_CARD_LABELS
            },
            "sections": {
                key: bool(sections.get(key, DEFAULT_USER_DASHBOARD_PREFERENCES["sections"][key]))
                for key in USER_DASHBOARD_SECTION_LABELS
            },
            "asset_columns": {
                key: bool(asset_columns.get(key, DEFAULT_USER_DASHBOARD_PREFERENCES["asset_columns"][key]))
                for key in USER_DASHBOARD_ASSET_COLUMN_LABELS
            },
            "guides": {
                key: bool(guides.get(key, DEFAULT_USER_DASHBOARD_PREFERENCES["guides"][key]))
                for key in USER_DASHBOARD_GUIDE_LABELS
            },
        },
        "card_labels": dict(USER_DASHBOARD_CARD_LABELS),
        "section_labels": dict(USER_DASHBOARD_SECTION_LABELS),
        "asset_column_labels": dict(USER_DASHBOARD_ASSET_COLUMN_LABELS),
        "guide_labels": dict(USER_DASHBOARD_GUIDE_LABELS),
    }


def _merge_dashboard_preferences(current: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValueError("dashboard preferences payload must be an object")

    merged = _dashboard_preferences_response(current)
    if "docs_url" in payload:
        docs_url = payload.get("docs_url")
        if not isinstance(docs_url, str) or not docs_url.strip():
            raise ValueError("docs_url must be a non-empty string")
        merged["docs_url"] = docs_url.strip()

    user_dashboard = payload.get("user_dashboard")
    if user_dashboard is not None:
        if not isinstance(user_dashboard, Mapping):
            raise ValueError("user_dashboard must be an object")
        for group_name, labels in (
            ("cards", USER_DASHBOARD_CARD_LABELS),
            ("sections", USER_DASHBOARD_SECTION_LABELS),
            ("asset_columns", USER_DASHBOARD_ASSET_COLUMN_LABELS),
            ("guides", USER_DASHBOARD_GUIDE_LABELS),
        ):
            group_payload = user_dashboard.get(group_name)
            if group_payload is None:
                continue
            if not isinstance(group_payload, Mapping):
                raise ValueError(f"user_dashboard.{group_name} must be an object")
            for key, value in group_payload.items():
                if key not in labels:
                    raise ValueError(f"unknown user dashboard {group_name} key: {key}")
                if not isinstance(value, bool):
                    raise ValueError(f"user_dashboard.{group_name}.{key} must be a boolean")
                merged["user_dashboard"][group_name][key] = value

    return {
        "docs_url": merged["docs_url"],
        "user_dashboard": {
            "cards": dict(merged["user_dashboard"]["cards"]),
            "sections": dict(merged["user_dashboard"]["sections"]),
            "asset_columns": dict(merged["user_dashboard"]["asset_columns"]),
            "guides": dict(merged["user_dashboard"]["guides"]),
        },
    }


def _ldap_verify(username: str, password: str, ldap_url: str, bind_dn: str, bind_pw: str, base_dn: str, user_attr: str) -> bool:
    """Synchronous LDAP credential verification. Returns True if authenticated."""
    if not _ldap3_available or _LdapServer is None:
        return False
    try:
        server = _LdapServer(ldap_url, get_info=_LDAP_ALL, connect_timeout=5)
        user_dn: str
        if bind_dn and base_dn:
            # Search-then-bind: use service account to find the user DN
            admin_conn = _LdapConnection(server, bind_dn, bind_pw, auto_bind=True)
            admin_conn.search(base_dn, f"({user_attr}={username})", search_scope=_LDAP_SUBTREE, attributes=["dn"])
            if not admin_conn.entries:
                return False
            user_dn = str(admin_conn.entries[0].entry_dn)
        else:
            # Simple bind: construct DN directly
            user_dn = f"{user_attr}={username},{base_dn}" if base_dn else f"{user_attr}={username}"
        conn = _LdapConnection(server, user_dn, password, auto_bind=True)
        return conn.bound
    except Exception:
        return False


# ── i18n shared runtime ──────────────────────────────────────────────────────
# The runtime script + translation dictionaries live in ``i18n.py`` and are
# imported at the top of this module (Task J-1 modularization). The login/signup
# page templates live in ``templates.py`` (Task J-2) and are imported above; the
# larger dashboard/console templates below embed the i18n runtime via
# :func:`_i18n_script`.


def create_app(service: QueryService | None = None, service_factory=None) -> Any:
    if FastAPI is None or HTTPException is None:
        raise RuntimeError(
            "FastAPI is not installed. Install fastapi and uvicorn to run MVC 1 HTTP server."
        )

    app = FastAPI(title="MORI SOC — Audit-Ready Security Operations API", version="0.2.0")
    insecure_defaults = _warn_insecure_defaults()
    admin_dashboard_preferences = _default_dashboard_preferences()
    # Per-user dashboard preferences: username -> preferences dict
    user_dashboard_prefs: dict[str, dict[str, Any]] = {}

    # ── Auth configuration ────────────────────────────────────────────────────
    _ldap_url = os.environ.get("LDAP_URL", "").strip()
    _ldap_bind_dn = os.environ.get("LDAP_BIND_DN", "").strip()
    _ldap_bind_pw = os.environ.get("LDAP_BIND_PASSWORD", "").strip()
    _ldap_base_dn = os.environ.get("LDAP_BASE_DN", "").strip()
    _ldap_user_attr = os.environ.get("LDAP_USER_ATTR", "uid").strip()
    _ldap_enabled = bool(_ldap_url and _ldap3_available)
    _admin_user = os.environ.get("MORI_ADMIN_USER", "admin")
    _admin_password = os.environ.get("MORI_ADMIN_PASSWORD", "1234")
    _auth_enabled = bool(os.environ.get("MORI_AUTH_ENABLED", "") or _ldap_enabled)

    # Predefined local accounts: username -> {password, role}
    local_users: dict[str, dict[str, str]] = {
        _admin_user: {"password": _admin_password, "role": "admin"},
        "security": {"password": "1234", "role": "security"},
        "monitor": {"password": "1234", "role": "monitor"},
        "auditor": {"password": "1234", "role": "auditor"},
        "helpdesk": {"password": "1234", "role": "helpdesk"},
    }

    # Sessions: token -> {username, role, created_at}
    sessions: dict[str, dict[str, Any]] = {}
    # Signup requests: [{id, name, email, department, reason, status, created_at}]
    signup_requests: list[dict[str, Any]] = []
    # User action audit log: [{ts, username, action, detail}]
    action_audit_log: list[dict[str, Any]] = []

    def _log_action(username: str, action: str, detail: str = "") -> None:
        """사용자 행동을 action_audit_log에 기록 (최근 2000건 유지)."""
        entry = {
            "ts": _isoformat(datetime.now(tz=timezone.utc)),
            "username": username,
            "action": action,
            "detail": detail,
        }
        action_audit_log.append(entry)
        if len(action_audit_log) > 2000:
            del action_audit_log[:-2000]

    # Role permissions: role -> list of allowed tab ids
    _DEFAULT_ROLE_PERMISSIONS: dict[str, list[str]] = {
        "admin": ["dashboard", "triage", "incidents", "assets", "compliance", "guides"],
        "security": ["dashboard", "triage", "incidents", "assets", "compliance", "guides"],
        "monitor": ["dashboard", "triage", "assets", "compliance", "guides"],
        "auditor": ["dashboard", "compliance", "guides"],
        "helpdesk": ["dashboard", "assets", "guides"],
        "user": ["dashboard", "assets", "guides"],
    }
    role_permissions: dict[str, list[str]] = {k: list(v) for k, v in _DEFAULT_ROLE_PERMISSIONS.items()}

    # Per-user tab overrides: username -> list of allowed tab ids (overrides role default)
    user_tab_permissions: dict[str, list[str]] = {}

    def _verify_credentials(username: str, password: str) -> bool:
        """LDAP(설정 시) → 로컬 계정 순으로 인증."""
        if _ldap_enabled:
            try:
                ok = _ldap_verify(username, password, _ldap_url, _ldap_bind_dn, _ldap_bind_pw, _ldap_base_dn, _ldap_user_attr)
                if ok:
                    return True
            except Exception:
                pass
        user = local_users.get(username)
        return user is not None and user["password"] == password

    if _auth_enabled:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.requests import Request as _StarletteRequest
        from starlette.responses import Response as _StarletteResponse

        _AUTH_PUBLIC_PATHS = {
            "/login", "/signup-request",
            "/auth/login", "/auth/logout", "/auth/signup-request", "/auth/me",
            "/docs", "/openapi.json", "/redoc", "/health",
        }

        class _SessionAuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: _StarletteRequest, call_next):  # type: ignore[override]
                path = request.url.path
                if path in _AUTH_PUBLIC_PATHS or path.startswith("/redoc") or path.startswith("/static"):
                    return await call_next(request)
                token = request.cookies.get("mori_session", "")
                if token and token in sessions:
                    return await call_next(request)
                # Not authenticated
                accept = request.headers.get("accept", "")
                if "text/html" in accept:
                    return _StarletteResponse(
                        status_code=302,
                        headers={"location": f"/login?next={_url_quote(path)}"},
                        content="",
                    )
                return _StarletteResponse(
                    status_code=401,
                    content='{"detail":"Unauthorized. Please login at /login"}',
                    media_type="application/json",
                )

        app.add_middleware(_SessionAuthMiddleware)

    # Triage: alert_id -> {status, analyst, note, updated_at}
    triage_store: dict[str, dict[str, Any]] = {}
    # Slack webhooks: [{id, name, url, created_at}]
    webhooks: list[dict[str, Any]] = []
    # Incidents: incident_id -> {incident_id, title, status, alert_ids, notes, created_at, updated_at}
    incidents: dict[str, dict[str, Any]] = {}
    # Asset owners: hostname -> {owner, email, team, updated_at}
    asset_owners: dict[str, dict[str, Any]] = {}
    # Asset audit log: [{log_id, hostname, field, old_value, new_value, changed_by, changed_at}]
    asset_audit_log: list[dict[str, Any]] = []
    # Action plans: host_id -> {text, target_date, updated_by, updated_at}
    action_plans: dict[str, dict[str, Any]] = {}
    # Per-vulnerability actions: vuln_id -> {plan_text, plan_target_date, plan_updated_by,
    #                                        exception_until, exception_reason, exception_updated_by, updated_at}
    vuln_actions: dict[str, dict[str, Any]] = {}
    # User profiles: username -> {display_name, department, assigned_servers: [hostname...], updated_at}
    user_profiles: dict[str, dict[str, Any]] = {}

    # ── Demo seed (in-memory) ────────────────────────────────────────────────
    # triage_store / asset_owners / user_profiles 는 런타임 인메모리 저장소라 SQL 시드로
    # 채울 수 없다. MORI_DEMO_SEED 활성화 시에만 초기값을 주입해 데모 임팩트를 확보한다.
    # (hostname/alert_id 는 scripts/mori-seed-sample-data.sh 의 값과 일치)
    if os.environ.get("MORI_DEMO_SEED", "").strip().lower() in ("1", "true", "yes", "on"):
        _seed_now = _isoformat(datetime.now(tz=timezone.utc))
        _demo_triage = {
            "al-01": {"status": "reviewing", "analyst": "보안담당자", "note": "SSH 브루트포스 출처 IP 차단 진행 중"},
            "al-02": {"status": "resolved", "analyst": "보안담당자", "note": "루트킷 격리·재이미지 완료"},
            "al-03": {"status": "pending", "analyst": "", "note": ""},
            "al-07": {"status": "reviewing", "analyst": "운영자1", "note": "비정상 아웃바운드 트래픽 조사 중"},
        }
        for _aid, _t in _demo_triage.items():
            triage_store.setdefault(_aid, {
                "status": _t["status"],
                "analyst": _t["analyst"],
                "note": _t["note"],
                "changed_by": _t["analyst"] or "system",
                "updated_at": _seed_now,
                "history": [{"to_status": _t["status"], "analyst": _t["analyst"] or "system", "changed_at": _seed_now}],
            })
        _demo_owners = [
            {"hostname": "web-server-01", "owner": "보안담당자", "team": "보안팀", "category": "웹 서버", "importance": "상"},
            {"hostname": "web-server-02", "owner": "보안담당자", "team": "보안팀", "category": "웹 서버", "importance": "중"},
            {"hostname": "db-primary", "owner": "DBA", "team": "DBA팀", "category": "DB 서버", "importance": "상"},
            {"hostname": "app-server-01", "owner": "운영자1", "team": "인프라팀", "category": "앱 서버", "importance": "중"},
        ]
        for _o in _demo_owners:
            asset_owners.setdefault(_o["hostname"], {
                "hostname": _o["hostname"], "owner": _o["owner"], "category": _o["category"],
                "importance": _o["importance"], "exception_until": "", "exception_reason": "",
                "email": "", "team": _o["team"], "updated_at": _seed_now,
            })
        _demo_profiles = {
            "admin": {"display_name": "시스템관리자", "department": "IT팀",
                      "assigned_servers": ["web-server-01", "db-primary", "app-server-01"]},
            "security": {"display_name": "보안담당자", "department": "보안팀",
                         "assigned_servers": ["web-server-01", "web-server-02"]},
        }
        for _u, _p in _demo_profiles.items():
            user_profiles.setdefault(_u, {
                "display_name": _p["display_name"], "department": _p["department"],
                "assigned_servers": list(_p["assigned_servers"]), "updated_at": _seed_now,
            })

    # Guides: guide_id -> {id, title, content, updated_at}
    guides: dict[str, dict[str, Any]] = {
        "zabbix_setup": {
            "id": "zabbix_setup",
            "title": "Zabbix 에이전트 설정 방법",
            "content": """## Zabbix 에이전트 설치 가이드

### 1. 에이전트 다운로드
- Zabbix 공식 사이트(https://www.zabbix.com/download)에서 OS에 맞는 에이전트를 다운로드합니다.

### 2. 설치 (Linux - Ubuntu/Debian)
```bash
wget https://repo.zabbix.com/zabbix/6.4/ubuntu/pool/main/z/zabbix-release/zabbix-release_6.4-1+ubuntu22.04_all.deb
dpkg -i zabbix-release_6.4-1+ubuntu22.04_all.deb
apt update && apt install -y zabbix-agent2
```

### 3. 설정 파일 편집
```bash
vi /etc/zabbix/zabbix_agent2.conf
```
주요 설정:
- `Server=<ZABBIX_SERVER_IP>` — Zabbix 서버 IP 입력
- `ServerActive=<ZABBIX_SERVER_IP>` — Active 모드 서버 IP
- `Hostname=<서버_호스트명>` — 서버 고유 이름 (대소문자 주의)

### 4. 서비스 시작
```bash
systemctl enable zabbix-agent2
systemctl start zabbix-agent2
```

### 5. Zabbix 웹 콘솔에서 호스트 등록
1. Configuration → Hosts → Create host
2. Host name: 에이전트의 Hostname 값과 동일하게 입력
3. Groups: 적절한 그룹 선택
4. Agent interface에 서버 IP 입력

### 6. 확인
```bash
systemctl status zabbix-agent2
zabbix_agent2 -t system.uptime
```

> **ISMS 관련**: 서버 자산 등록 및 모니터링은 ISMS-P 2.10 시스템 및 서비스 보안, ISO 27001 A.8.16 모니터링활동에 해당합니다.""",
            "updated_at": None,
        },
        "fleet_install": {
            "id": "fleet_install",
            "title": "Fleet(osquery) 에이전트 설치 방법",
            "content": """## Fleet osquery 에이전트 설치 가이드

### 개요
Fleet는 osquery 기반 PC/서버 자산 관리 도구입니다. 설치 후 자동으로 Fleet 서버에 등록되어 자산 현황 대시보드에 표시됩니다.

### 1. Fleet 서버 주소 확인
IT 담당자에게 Fleet 서버 Enrollment 패키지 또는 URL을 요청합니다.

### 2. Windows 설치
1. Fleet 서버 콘솔 → Hosts → Add Hosts → Windows 선택
2. 제공되는 PowerShell 명령어를 관리자 권한으로 실행:
```powershell
# 예시 (실제 명령어는 Fleet 서버에서 생성)
Invoke-WebRequest -Uri "https://<FLEET_SERVER>/enroll" -OutFile "fleet-osquery.msi"
msiexec /i fleet-osquery.msi /quiet
```

### 3. macOS 설치
```bash
# Fleet 서버 콘솔에서 생성된 명령어 실행
sudo installer -pkg fleet-osquery.pkg -target /
```

### 4. Linux 설치 (Ubuntu/Debian)
```bash
sudo dpkg -i fleet-osquery_*.deb
sudo systemctl enable orbit
sudo systemctl start orbit
```

### 5. 설치 확인
- Fleet 콘솔 → Hosts 에서 해당 PC가 등록되었는지 확인
- 대시보드 → PC 자산(Fleet) 탭에서 온라인 상태 확인

### 6. 오프라인 PC 조치
오프라인 표시 시:
- PC가 켜져 있는지 확인
- orbit 서비스 재시작: `sudo systemctl restart orbit`
- 방화벽에서 Fleet 서버로의 아웃바운드 허용 확인

> **ISMS 관련**: PC 자산 관리는 ISMS-P 2.1 정보자산 식별, ISO 27001 A.8.1 사용자단말기 정책에 해당합니다.""",
            "updated_at": None,
        },
        "isms_criteria": {
            "id": "isms_criteria",
            "title": "ISMS-P 인증 심사 대비 기준",
            "content": """## ISMS-P 인증 심사 대비 체크리스트

### 2.1 정보자산 식별 및 관리
- [ ] 전체 IT 자산 목록 (서버, PC, 네트워크 장비) 보유 여부
- [ ] 자산별 중요도(상/중/하) 분류 여부
- [ ] 자산별 담당자/소유자 지정 여부
- [ ] 자산 목록 최신화 주기 (분기/반기)

**증적 방법**: 대시보드 → 자산 현황 → CSV 내보내기 (분류·중요도·담당자 포함)

---

### 2.5 인증 및 접근통제
- [ ] 서버 접근 계정 목록 관리
- [ ] 퇴사자 계정 즉시 비활성화 절차
- [ ] 특수권한(관리자) 계정 별도 관리

**증적 방법**: Zabbix → 도메인컨트롤러/인증서버 모니터링 데이터

---

### 2.6 네트워크 보안
- [ ] 방화벽 정책 현황 문서화
- [ ] 내/외부 네트워크 분리 여부
- [ ] VPN 사용 현황

**증적 방법**: Zabbix → 네트워크 보안 장비 자산 목록

---

### 2.9 데이터베이스 보안
- [ ] DB 접근 계정 관리
- [ ] DB 접근 로그 보존
- [ ] 중요 데이터 암호화 여부

**증적 방법**: Trivy → DB 서버 취약점 스캔 결과 + 조치계획

---

### 2.10 시스템 및 서비스 보안
- [ ] 서버별 취약점 점검 주기 (분기 1회 이상)
- [ ] 패치 관리 현황
- [ ] 불필요 서비스 비활성화

**증적 방법**: Trivy 스캔 결과 CSV + 조치계획 등록

---

### 2.11 이벤트 처리
- [ ] 보안 이벤트 모니터링 현황
- [ ] 경보 발생 시 대응 절차 문서화
- [ ] 이벤트 로그 보존 기간 (최소 1년)

**증적 방법**: Alert Triage 현황 + 인시던트 목록

---

### 2.12 업무연속성 보안
- [ ] 백업 서버 운영 현황
- [ ] 백업 주기 및 복구 테스트 이력

**증적 방법**: Zabbix → 백업 서버 자산 모니터링 데이터""",
            "updated_at": None,
        },
        "iso27001_criteria": {
            "id": "iso27001_criteria",
            "title": "ISO/IEC 27001:2022 대비 기준",
            "content": """## ISO/IEC 27001:2022 심사 대비 체크리스트

### A.5 조직 통제 (Organizational Controls)
#### A.5.12 정보 분류 / A.5.13 정보 레이블링
- [ ] 정보자산 중요도 분류 체계 수립 (상/중/하 또는 기밀/내부/공개)
- [ ] 서버/PC 자산에 중요도 레이블 부여

**증적**: 자산 현황 CSV (importance 컬럼)

#### A.5.15 접근통제 / A.5.16 신원 관리
- [ ] 접근통제 정책 문서화
- [ ] 사용자 계정 생애주기 관리 절차

---

### A.8 기술 통제 (Technological Controls)
#### A.8.1 사용자 단말기 정책
- [ ] PC 자산 전수 등록 및 모니터링
- [ ] 오프라인 PC 발생 시 조치 절차

**증적**: Fleet PC 자산 목록 + 오프라인 현황 CSV

#### A.8.2 특수 접근권한
- [ ] 관리자 계정 목록 및 주기적 검토

#### A.8.8 기술적 취약점 관리
- [ ] 분기별 취약점 스캔 실시
- [ ] CVE 기반 위험 평가 (Critical/High 우선)
- [ ] 취약점별 조치계획 수립 및 이행 추적

**증적**: Trivy 스캔 결과 CSV + 조치계획 (target_date, 담당자 포함)

#### A.8.13 정보 백업
- [ ] 백업 주기 및 보존 기간 정의
- [ ] 복구 테스트 주기적 실시

**증적**: 백업 서버 Zabbix 모니터링 데이터

#### A.8.15 로깅 / A.8.16 모니터링 활동
- [ ] 보안 이벤트 로그 수집 및 보존
- [ ] 이상 징후 모니터링 현황

**증적**: Alert Triage 이력 + Zabbix 이벤트 데이터

#### A.8.20 네트워크 보안 / A.8.22 네트워크 분리
- [ ] 네트워크 보안 장비 운영 현황
- [ ] 내/외부 네트워크 분리 구성

**증적**: Zabbix 네트워크 보안장비 자산 목록

#### A.8.31 개발·운영 환경 분리
- [ ] 개발/테스트 서버와 운영 서버 분리 여부

**증적**: 자산 현황 → 개발/테스트 서버 분류 확인""",
            "updated_at": None,
        },
        "ldap_setup": {
            "id": "ldap_setup",
            "title": "LDAP 통합 인증 설정 가이드",
            "content": """## LDAP 통합 인증 설정 가이드

Grafana, Zabbix, Fleet, MORI SOC를 하나의 LDAP 서버로 통합 관리하면 계정 하나로 모든 도구에 로그인할 수 있습니다.

---

### Step 1. OpenLDAP 서버 설치 (Docker Compose)

```yaml
# docker-compose.ldap.yml
services:
  openldap:
    image: osixia/openldap:1.5.0
    environment:
      LDAP_ORGANISATION: "My Company"
      LDAP_DOMAIN: "company.local"
      LDAP_ADMIN_PASSWORD: "AdminSecret123"
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d

  phpldapadmin:
    image: osixia/phpldapadmin:0.9.0
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: openldap
    ports:
      - "8080:80"

volumes:
  ldap_data:
  ldap_config:
```

```bash
docker compose -f docker-compose.ldap.yml up -d
# 관리 UI: http://localhost:8080  (Login DN: cn=admin,dc=company,dc=local)
```

---

### Step 2. Zabbix LDAP 설정

1. **Zabbix 웹 → Administration → Authentication → LDAP**
2. 아래 값 입력:

| 항목 | 값 |
|---|---|
| LDAP host | `ldap://openldap` (또는 서버 IP) |
| Port | 389 |
| Base DN | `dc=company,dc=local` |
| Search attribute | `uid` |
| Bind DN | `cn=admin,dc=company,dc=local` |
| Bind password | AdminSecret123 |

3. **Enable LDAP authentication** 체크 후 저장
4. 사용자 계정: Zabbix → Users → 해당 사용자 → **LDAP** 타입 선택

> **ISMS/ISO 27001**: 중앙집중식 접근통제 → A.5.15 / ISMS-P 2.5

---

### Step 3. Grafana LDAP 설정

`/etc/grafana/grafana.ini` 또는 환경변수 추가:

```ini
[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml
allow_sign_up = true
```

`/etc/grafana/ldap.toml`:

```toml
[[servers]]
host = "openldap"
port = 389
use_ssl = false
bind_dn = "cn=admin,dc=company,dc=local"
bind_password = "AdminSecret123"
search_filter = "(uid=%s)"
search_base_dns = ["dc=company,dc=local"]

[servers.attributes]
name = "cn"
username = "uid"
member_of = "memberOf"
email = "mail"

[[servers.group_mappings]]
group_dn = "cn=grafana-admins,ou=groups,dc=company,dc=local"
org_role = "Admin"

[[servers.group_mappings]]
group_dn = "*"
org_role = "Viewer"
```

```bash
# Docker 환경이면 환경변수로도 가능
GF_AUTH_LDAP_ENABLED=true
GF_AUTH_LDAP_CONFIG_FILE=/etc/grafana/ldap.toml
```

---

### Step 4. Fleet SSO (SAML/LDAP 대안)

Fleet는 직접 LDAP을 지원하지 않고 **SAML SSO**를 통해 IdP와 연동합니다. OpenLDAP + Keycloak 조합 권장:

1. **Keycloak** 설치 후 OpenLDAP을 User Federation으로 연결
2. Fleet → Settings → Single Sign-On → SAML 설정:
   - Identity Provider URL: Keycloak SAML endpoint
   - Issuer URI: Fleet 서버 URL

> 간단한 구성을 원하면 Keycloak 없이 Google Workspace / Azure AD를 SAML IdP로 사용하는 방법도 있습니다.

---

### Step 5. MORI SOC LDAP 인증 설정

MORI SOC는 환경변수로 LDAP 인증을 활성화합니다. `ldap3` 라이브러리가 필요합니다.

```bash
# MORI SOC 환경변수 (.env 또는 docker-compose)
LDAP_URL=ldap://openldap:389
LDAP_BASE_DN=dc=company,dc=local
LDAP_BIND_DN=cn=admin,dc=company,dc=local
LDAP_BIND_PASSWORD=AdminSecret123
LDAP_USER_ATTR=uid
```

**Docker Compose 예시 (`docker-compose.yml`):**

```yaml
services:
  mori-soc:
    image: mori-soc:latest
    environment:
      LDAP_URL: "ldap://openldap:389"
      LDAP_BASE_DN: "dc=company,dc=local"
      LDAP_BIND_DN: "cn=admin,dc=company,dc=local"
      LDAP_BIND_PASSWORD: "AdminSecret123"
      LDAP_USER_ATTR: "uid"
    depends_on:
      - openldap
```

LDAP이 설정되면 모든 API/UI 접근에 HTTP Basic Auth가 요구됩니다.
`/docs`, `/health`, `/openapi.json`은 인증 없이 접근 가능합니다.

---

### LDAP 사용자 추가 (phpLDAPadmin 또는 CLI)

```bash
# ldif 파일로 사용자 추가
cat > user.ldif << 'EOF'
dn: uid=alice,ou=people,dc=company,dc=local
objectClass: inetOrgPerson
uid: alice
cn: Alice Kim
sn: Kim
mail: alice@company.local
userPassword: {SSHA}hashedpassword
EOF

ldapadd -x -D "cn=admin,dc=company,dc=local" -w AdminSecret123 -f user.ldif
```

---

> **보안 권고**: 프로덕션 환경에서는 반드시 LDAPS(636포트, TLS) 또는 StartTLS를 사용하세요.""",
            "updated_at": None,
        },
        "incident_response": {
            "id": "incident_response",
            "title": "인시던트 대응 절차 가이드",
            "content": """## 인시던트 대응 절차 (Incident Response)

보안 이벤트 발생 시 아래 절차에 따라 신속하게 대응합니다.

---

### 1단계. 탐지 및 초기 분류 (Detection & Triage)

- [ ] Alert Triage 탭에서 미확인(🔴) 경보 확인
- [ ] 경보 유형, 영향 호스트, 심각도 파악
- [ ] 상태를 **검토중(🟡)** 으로 변경하고 담당자 지정
- [ ] 오탐 여부 1차 판단 (오탐 시 → `resolved` 처리 + 메모 기록)

---

### 2단계. 인시던트 생성 (Incident Creation)

실제 보안 사고로 판단되면 인시던트를 생성합니다:

1. **인시던트** 탭 → **+ 새 인시던트** 클릭
2. 제목, 심각도, 관련 Alert 연결
3. 담당자 지정 후 상태 → **조사중(investigating)**

---

### 3단계. 분석 및 봉쇄 (Analysis & Containment)

- [ ] 영향 호스트 목록 파악 (자산 현황 탭 참조)
- [ ] 네트워크 격리 또는 서비스 중단 여부 판단
- [ ] 공격 벡터 분석 (로그, Zabbix 이벤트, Fleet 쿼리 결과)
- [ ] 인시던트 **메모**에 분석 내용 지속 기록

---

### 4단계. 제거 및 복구 (Eradication & Recovery)

- [ ] 악성 파일/계정 제거
- [ ] 취약점 패치 적용 (Trivy 스캔 결과 → 조치계획 등록)
- [ ] 서비스 정상화 확인
- [ ] 상태 → **해결됨(resolved)**

---

### 5단계. 사후 분석 (Post-Incident Review)

- [ ] 인시던트 상태 → **종료(closed)**
- [ ] 근본 원인 분석(RCA) 작성 및 인시던트 메모에 첨부
- [ ] 재발 방지 대책 수립
- [ ] ISMS-P 2.11 이벤트 처리 / ISO 27001 A.5.26 증적으로 활용

---

> **ISMS-P 관련 통제**: 2.11 이벤트 처리, 2.12 업무연속성 보안
> **ISO 27001 관련 통제**: A.5.24 정보보안사고 관리 계획, A.5.26 정보보안사고 대응""",
            "updated_at": None,
        },
        "security_policy": {
            "id": "security_policy",
            "title": "보안 정책 및 운영 가이드",
            "content": """## 보안 정책 및 운영 가이드

MORI SOC 플랫폼을 활용한 보안 운영 정책을 안내합니다.

---

### 1. 자산 관리 정책

| 항목 | 주기 | 담당 |
|---|---|---|
| 전체 자산 목록 갱신 | 분기 1회 | IT팀 |
| 자산 중요도 분류 검토 | 반기 1회 | 보안팀 |
| 담당자(Owner) 정보 업데이트 | 변경 발생 시 즉시 | 부서장 |
| 자산 현황 CSV 다운로드 (증적) | 심사 전 | 보안팀 |

---

### 2. 취약점 관리 정책

- **Critical/High 취약점**: 발견 후 **14일** 이내 조치 완료
- **Medium 취약점**: 발견 후 **30일** 이내 조치 완료
- **Low 취약점**: 분기별 일괄 검토 및 조치
- Trivy 스캔은 **주 1회** 실행 권장
- 조치계획은 반드시 MORI SOC 조치계획 탭에 등록

---

### 3. Alert 대응 정책

| 심각도 | 초기 대응 시간 | 에스컬레이션 |
|---|---|---|
| Critical | 15분 이내 | 즉시 팀장 보고 |
| High | 1시간 이내 | 2시간 내 미해결 시 팀장 보고 |
| Medium | 4시간 이내 | 당일 처리 원칙 |
| Low | 익일까지 | 주간 보고에 포함 |

---

### 4. 인시던트 관리 정책

- 보안 사고는 반드시 인시던트로 등록
- 인시던트 종료 후 **5일** 이내 사후 분석 보고서 작성
- 심각 인시던트(Critical)는 경영진 보고 필수
- 모든 인시던트 이력은 최소 **3년** 보존

---

### 5. 접근통제 정책

- 관리자 계정(admin)은 반드시 복잡한 비밀번호 사용
- LDAP 연동 시 그룹 기반 접근통제 적용
- 퇴사/부서 이동 시 즉시 계정 비활성화
- 비밀번호 변경 주기: **90일**

---

### 6. 로그 보존 정책

| 로그 종류 | 보존 기간 |
|---|---|
| 보안 이벤트 (Alert) | 1년 이상 |
| 인시던트 이력 | 3년 이상 |
| 접근 로그 | 6개월 이상 |
| 취약점 스캔 결과 | 2년 이상 |

---

> **ISMS-P 관련 통제**: 2.9 시스템 및 서비스 운영관리, 2.11 이벤트 처리
> **ISO 27001 관련 통제**: A.5.1 정보보안 정책, A.8.15 로깅""",
            "updated_at": None,
        },
    }

    def get_query_service() -> QueryService:
        if service is not None:
            return service
        if service_factory is not None:
            return service_factory()
        return create_query_service()

    # ── Auth routes ──────────────────────────────────────────────────────────
    @app.get("/login", include_in_schema=False, response_class=HTMLResponse)
    def login_page(next: str = "/ui") -> str:
        return render_login_html(next_url=next)

    @app.post("/auth/login", tags=["Auth"])
    def auth_login(payload: dict[str, Any]) -> dict[str, Any]:
        """로그인: {username, password} → 세션 쿠키 설정."""
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password:
            raise HTTPException(status_code=400, detail="아이디와 비밀번호를 입력하세요.")
        if not _verify_credentials(username, password):
            _log_action(username, "LOGIN_FAIL", "잘못된 비밀번호")
            raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
        token = str(uuid.uuid4())
        _role = local_users.get(username, {}).get("role", "user")
        sessions[token] = {
            "username": username,
            "role": _role,
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        _log_action(username, "LOGIN", f"role={_role}")
        from fastapi.responses import JSONResponse
        resp = JSONResponse({"ok": True, "username": username})
        resp.set_cookie("mori_session", token, httponly=True, samesite="lax", max_age=86400 * 7)
        return resp

    @app.get("/auth/logout", include_in_schema=False)
    def auth_logout(request: Any = None) -> Any:
        """로그아웃: 세션 쿠키 삭제 후 /login 리디렉션."""
        token = ""
        if hasattr(request, "cookies"):
            token = request.cookies.get("mori_session", "")
        sess = sessions.pop(token, {})
        _log_action(sess.get("username", "unknown"), "LOGOUT", "")
        resp = RedirectResponse(url="/login", status_code=302)
        resp.delete_cookie("mori_session")
        return resp

    @app.get("/signup-request", include_in_schema=False, response_class=HTMLResponse)
    def signup_request_page() -> str:
        return render_signup_request_html()

    @app.post("/auth/signup-request", tags=["Auth"])
    def submit_signup_request(payload: dict[str, Any]) -> dict[str, Any]:
        """가입 요청 제출: {name, email, department, reason}."""
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip()
        if not name or not email:
            raise HTTPException(status_code=400, detail="이름과 이메일은 필수입니다.")
        req = {
            "id": str(uuid.uuid4()),
            "name": name,
            "email": email,
            "department": str(payload.get("department", "")).strip(),
            "reason": str(payload.get("reason", "")).strip(),
            "status": "pending",
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
            "reviewed_at": None,
        }
        signup_requests.append(req)
        return {"ok": True, "message": "가입 요청이 접수되었습니다. 운영자 승인 후 안내드리겠습니다."}

    @app.get("/auth/signup-requests", tags=["Auth"])
    def list_signup_requests() -> dict[str, Any]:
        """가입 요청 목록 조회 (어드민용)."""
        return {"requests": signup_requests, "total": len(signup_requests)}

    @app.patch("/auth/signup-requests/{req_id}", tags=["Auth"])
    def update_signup_request(req_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """가입 요청 승인/거절 (어드민용). status: approved | rejected."""
        valid_statuses = {"approved", "rejected", "pending"}
        new_status = str(payload.get("status", "")).strip()
        if new_status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid_statuses))}")
        for req in signup_requests:
            if req["id"] == req_id:
                req["status"] = new_status
                req["reviewed_at"] = _isoformat(datetime.now(tz=timezone.utc))
                return req
        raise HTTPException(status_code=404, detail="가입 요청을 찾을 수 없습니다.")

    def _user_profile(uname: str) -> dict[str, Any]:
        """username → 프로필 dict (없으면 빈 기본값)."""
        p = user_profiles.get(uname, {})
        return {
            "display_name": p.get("display_name", ""),
            "department": p.get("department", ""),
            "assigned_servers": list(p.get("assigned_servers", [])),
        }

    @app.get("/auth/me", tags=["Auth"])
    def auth_me(request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자 정보 조회."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        if not sess:
            return {
                "username": "anonymous",
                "role": "user",
                "allowed_tabs": _DEFAULT_ROLE_PERMISSIONS.get("user", ["dashboard", "assets", "guides"]),
                **_user_profile("anonymous"),
            }
        role = sess.get("role", "user")
        uname = sess["username"]
        # 유저별 개별 설정이 있으면 우선 적용, 없으면 역할 기본값
        if uname in user_tab_permissions:
            allowed = user_tab_permissions[uname]
        else:
            allowed = role_permissions.get(role, _DEFAULT_ROLE_PERMISSIONS.get(role, ["dashboard", "assets", "guides"]))
        return {
            "username": uname,
            "role": role,
            "allowed_tabs": allowed,
            **_user_profile(uname),
        }

    @app.get("/auth/profile", tags=["Auth"])
    def get_profile(request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자의 프로필 조회."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        if not sess:
            raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
        uname = sess["username"]
        return {"username": uname, **_user_profile(uname)}

    @app.post("/auth/profile", tags=["Auth"])
    def update_profile(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자의 프로필 업서트. {display_name, department, assigned_servers[]}"""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        if not sess:
            raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
        uname = sess["username"]
        display_name = str(payload.get("display_name", "")).strip()
        department = str(payload.get("department", "")).strip()
        raw_servers = payload.get("assigned_servers", [])
        if isinstance(raw_servers, str):
            raw_servers = [s for s in raw_servers.replace(",", "\n").splitlines()]
        assigned_servers = [str(s).strip() for s in raw_servers if str(s).strip()]
        user_profiles[uname] = {
            "display_name": display_name,
            "department": department,
            "assigned_servers": assigned_servers,
            "updated_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        return {"ok": True, "username": uname, **_user_profile(uname)}

    @app.get("/admin/role-permissions", tags=["Admin"])
    def get_role_permissions_api() -> dict[str, Any]:
        """역할별 탭 권한 조회."""
        return {"permissions": role_permissions}

    @app.post("/admin/role-permissions", tags=["Admin"])
    def update_role_permissions_api(payload: dict[str, Any]) -> dict[str, Any]:
        """역할별 탭 권한 업데이트. {role: [tab_id, ...]}"""
        nonlocal role_permissions
        valid_tabs = {"dashboard", "triage", "incidents", "assets", "compliance", "guides"}
        for role_key, tabs in payload.items():
            if not isinstance(tabs, list):
                raise HTTPException(status_code=400, detail=f"tabs for {role_key} must be a list")
            role_permissions[role_key] = [t for t in tabs if t in valid_tabs]
        return {"permissions": role_permissions}

    @app.get("/admin/user-tab-permissions", tags=["Admin"])
    def get_user_tab_permissions_api() -> dict[str, Any]:
        """유저별 탭 권한 오버라이드 목록 + 전체 유저 목록 조회."""
        # 로컬 유저 + 로그인 이력이 있는 세션 유저
        all_users: dict[str, str] = {}
        for uname, info in local_users.items():
            all_users[uname] = info.get("role", "user")
        for _tok, sess in sessions.items():
            uname = sess.get("username", "")
            if uname and uname not in all_users:
                all_users[uname] = sess.get("role", "user")
        users_list = []
        for uname, role in sorted(all_users.items()):
            role_default = role_permissions.get(role, _DEFAULT_ROLE_PERMISSIONS.get(role, ["dashboard", "assets", "guides"]))
            override = user_tab_permissions.get(uname)
            users_list.append({
                "username": uname,
                "role": role,
                "role_default_tabs": role_default,
                "user_tabs": override,  # None이면 역할 기본값 사용 중
                "has_override": override is not None,
            })
        return {"users": users_list}

    @app.post("/admin/user-tab-permissions/{username}", tags=["Admin"])
    def set_user_tab_permissions_api(username: str, payload: dict[str, Any]) -> dict[str, Any]:
        """특정 유저의 탭 권한 개별 설정. {"tabs": ["dashboard","assets",...]}"""
        valid_tabs = {"dashboard", "triage", "incidents", "assets", "compliance", "guides"}
        tabs = payload.get("tabs")
        if not isinstance(tabs, list):
            raise HTTPException(status_code=400, detail="tabs must be a list")
        user_tab_permissions[username] = [t for t in tabs if t in valid_tabs]
        _log_action("admin", "USER_TAB_PERM_SET", f"user={username} tabs={user_tab_permissions[username]}")
        return {"username": username, "tabs": user_tab_permissions[username]}

    @app.delete("/admin/user-tab-permissions/{username}", tags=["Admin"])
    def reset_user_tab_permissions_api(username: str) -> dict[str, Any]:
        """특정 유저의 탭 권한 개별 설정 초기화 (역할 기본값으로 복원)."""
        removed = user_tab_permissions.pop(username, None)
        _log_action("admin", "USER_TAB_PERM_RESET", f"user={username}")
        return {"username": username, "reset": removed is not None}

    @app.get("/admin/action-audit-log", tags=["Admin"])
    def get_action_audit_log(limit: int = 500, username: str = "") -> dict[str, Any]:
        """사용자 행동 감사 로그 조회 (최신순). ?username=xxx 로 필터 가능."""
        logs = list(reversed(action_audit_log))
        if username:
            logs = [e for e in logs if e["username"] == username]
        return {"logs": logs[:limit], "total": len(logs)}

    @app.post("/admin/action-audit-log", tags=["Admin"])
    def record_action_audit(payload: dict[str, Any], request: Any = None) -> dict[str, Any]:
        """프런트엔드에서 탭 전환·쿼리 실행 등을 기록할 때 호출."""
        token = ""
        if hasattr(request, "cookies"):
            token = request.cookies.get("mori_session", "")
        sess = sessions.get(token, {})
        uname = sess.get("username", "anonymous")
        action = str(payload.get("action", "UNKNOWN"))
        detail = str(payload.get("detail", ""))
        _log_action(uname, action, detail)
        return {"ok": True}

    @app.get("/", include_in_schema=False)
    def index() -> Any:
        return RedirectResponse(url="/ui", status_code=307)

    @app.get("/ui", include_in_schema=False, response_class=HTMLResponse)
    def ui() -> str:
        return render_user_dashboard_html(
            docs_url=admin_dashboard_preferences["docs_url"],
            fleet_ui_url=FLEET_UI_URL,
            zabbix_ui_url=ZABBIX_UI_URL,
        )

    @app.get("/admin", include_in_schema=False, response_class=HTMLResponse)
    def admin() -> str:
        return render_query_console_html(admin_dashboard_preferences["docs_url"])

    @app.get("/health")
    def health() -> dict[str, Any]:
        try:
            query_service = get_query_service()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"query service unavailable: {exc}") from exc

        # ── PostgreSQL ping (only if MORI_DATABASE_URL is configured) ────
        database_url = os.getenv("MORI_DATABASE_URL", "").strip()
        db_status: dict[str, Any]
        if database_url:
            try:
                import psycopg  # type: ignore

                with psycopg.connect(database_url, connect_timeout=2) as conn, conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()
                db_status = {"configured": True, "reachable": True}
            except Exception as exc:
                db_status = {"configured": True, "reachable": False, "error": str(exc)[:200]}
        else:
            db_status = {"configured": False, "reachable": None}

        # ── Source freshness summary (counts only — full detail at /dashboard/summary) ──
        coverage_summary: dict[str, int] = {"total": 0, "healthy": 0, "stale": 0, "error": 0, "unknown": 0}
        try:
            coverage = _source_coverage(query_service.store)
            for row in coverage:
                coverage_summary["total"] += 1
                status_val = row.get("status") or "unknown"
                if status_val == "error":
                    coverage_summary["error"] += 1
                elif row.get("is_stale"):
                    coverage_summary["stale"] += 1
                elif status_val in ("success", "running"):
                    coverage_summary["healthy"] += 1
                else:
                    coverage_summary["unknown"] += 1
        except Exception:
            pass

        return {
            "status": "ok",
            "engine": type(query_service.store).__name__,
            "query_count": len(PHASE1_QUERY_CATALOG),
            "database": db_status,
            "source_coverage": coverage_summary,
            "insecure_defaults": insecure_defaults,
        }

    @app.get("/catalog")
    def catalog() -> dict[str, Any]:
        return {
            "queries": [
                {
                    "query_id": query.query_id,
                    "intent": query.intent,
                    "name": query.name,
                    "default_window": query.default_window,
                    "required_filters": list(query.required_filters),
                    "evidence_sources": list(query.evidence_sources),
                }
                for query in PHASE1_QUERY_CATALOG
            ]
        }

    @app.get("/dashboard/summary")
    def dashboard_summary() -> dict[str, Any]:
        try:
            return build_dashboard_payload(get_query_service(), asset_owners=asset_owners, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"dashboard summary unavailable: {exc}") from exc

    @app.get("/compliance/pdca", tags=["Compliance"])
    def compliance_pdca_summary() -> dict[str, Any]:
        """Compliance PDCA 대시보드 요약 데이터."""
        try:
            return build_pdca_payload(
                get_query_service(),
                vuln_actions=vuln_actions,
                alert_triage=triage_store,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"compliance pdca unavailable: {exc}") from exc

    @app.get("/compliance/pdca/pending.csv", tags=["Compliance"])
    def compliance_pdca_pending_csv() -> Any:
        """미조치 / 기한 초과 항목(PDCA Do 단계)을 CSV로 다운로드."""
        try:
            payload = build_pdca_payload(
                get_query_service(),
                vuln_actions=vuln_actions,
                alert_triage=triage_store,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"compliance pdca unavailable: {exc}") from exc
        import io, csv as csv_mod
        buf = io.StringIO()
        header_map = {
            "source": "출처",
            "control_id": "통제ID",
            "entity_type": "대상유형",
            "entity_id": "대상",
            "status": "상태",
            "owner": "담당자",
            "checked_at": "점검일시",
            "remediation_due_at": "조치기한",
            "overdue": "기한초과",
            "note": "비고",
        }
        fieldnames = list(header_map.keys())
        writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writerow(header_map)
        for item in payload.get("pending_remediations", []):
            row = {k: item.get(k, "") for k in fieldnames}
            row["overdue"] = "Y" if item.get("overdue") else "N"
            writer.writerow(row)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="mori-pdca-pending-{timestamp}.csv"'},
        )

    @app.get("/compliance/crosscheck", tags=["Compliance"])
    def compliance_crosscheck() -> dict[str, Any]:
        """소스 간 교차 검증 데이터."""
        try:
            return build_crosscheck_payload(get_query_service())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"crosscheck unavailable: {exc}") from exc

    def _get_session_username(request: Request) -> str | None:
        """현재 세션의 사용자명을 반환 (미인증 시 None)."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        return sess.get("username") if sess else None

    @app.get("/dashboard/preferences")
    def dashboard_preferences_get(request: Request) -> dict[str, Any]:
        """현재 사용자의 대시보드 설정 조회 (개인 설정 → 관리자 기본값 순)."""
        username = _get_session_username(request)
        if username and username in user_dashboard_prefs:
            return _dashboard_preferences_response(user_dashboard_prefs[username])
        return _dashboard_preferences_response(admin_dashboard_preferences)

    @app.post("/dashboard/preferences")
    def dashboard_preferences_update(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
        """현재 사용자의 대시보드 설정 저장 (개인별)."""
        nonlocal admin_dashboard_preferences
        username = _get_session_username(request)
        if username:
            base = user_dashboard_prefs.get(username, dict(admin_dashboard_preferences))
            try:
                user_dashboard_prefs[username] = _merge_dashboard_preferences(base, payload)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            return _dashboard_preferences_response(user_dashboard_prefs[username])
        # 인증 미사용 환경: 글로벌 설정 업데이트
        try:
            admin_dashboard_preferences = _merge_dashboard_preferences(admin_dashboard_preferences, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _dashboard_preferences_response(admin_dashboard_preferences)

    @app.get("/admin/dashboard/preferences", tags=["Admin"])
    def admin_dashboard_preferences_get() -> dict[str, Any]:
        """관리자 기본 대시보드 설정 조회 (모든 사용자 기본값)."""
        return _dashboard_preferences_response(admin_dashboard_preferences)

    @app.post("/admin/dashboard/preferences", tags=["Admin"])
    def admin_dashboard_preferences_update(payload: dict[str, Any]) -> dict[str, Any]:
        """관리자 기본 대시보드 설정 변경 (모든 사용자 기본값)."""
        nonlocal admin_dashboard_preferences
        try:
            admin_dashboard_preferences = _merge_dashboard_preferences(admin_dashboard_preferences, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _dashboard_preferences_response(admin_dashboard_preferences)

    @app.get("/admin/dashboard/user-preferences", tags=["Admin"])
    def admin_user_prefs_list() -> dict[str, Any]:
        """모든 사용자의 개인 설정 목록 조회 (관리자용)."""
        return {
            "users": {
                uname: _dashboard_preferences_response(prefs)
                for uname, prefs in user_dashboard_prefs.items()
            }
        }

    @app.delete("/admin/dashboard/user-preferences/{username}", tags=["Admin"])
    def admin_user_prefs_reset(username: str) -> dict[str, Any]:
        """특정 사용자의 개인 설정 초기화 (관리자 기본값으로 복원)."""
        removed = user_dashboard_prefs.pop(username, None)
        return {"username": username, "reset": removed is not None}

    @app.post("/query")
    def query(payload: dict[str, Any], format: str = "json") -> Any:
        try:
            request = build_query_request(payload)
            response = get_query_service().execute(request)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"query execution failed: {exc}") from exc
        if format == "csv":
            csv_payload = query_response_to_csv(response)
            filename = _query_csv_filename(request.intent)
            return StreamingResponse(
                iter([csv_payload]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        if format != "json":
            raise HTTPException(status_code=400, detail="format must be either json or csv")
        return response.to_dict()

    @app.post("/interpret")
    def interpret(payload: dict[str, Any]) -> dict[str, Any]:
        text = payload.get("text")
        if not isinstance(text, str) or not text.strip():
            raise HTTPException(status_code=400, detail="payload must include non-empty string text")
        try:
            return interpret_query_text(text)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # ── Alert Triage ────────────────────────────────────────────────────────────
    @app.get("/alerts", tags=["Alerts"])
    def alerts_list() -> dict[str, Any]:
        store = get_query_service().store
        hostnames = {host.host_id: host.hostname for host in store.hosts}
        rows = _alert_detail_rows(store.alerts, hostnames)
        for row in rows:
            row["triage"] = triage_store.get(row["alert_id"], {"status": "pending"})
        return {"alerts": rows, "total": len(rows)}

    @app.patch("/alerts/{alert_id}/triage", tags=["Alerts"])
    def alert_triage_update(alert_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        status = payload.get("status", "")
        valid_statuses = {"pending", "reviewing", "resolved"}
        if status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid_statuses))}")
        entry = triage_store.setdefault(alert_id, {})
        prev_status = entry.get("status", "pending")
        entry["status"] = status
        entry["analyst"] = payload.get("analyst", "")
        entry["note"] = payload.get("note", entry.get("note", ""))
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        # 변경자: payload의 actor → 세션 사용자 → "unknown"
        changed_by = str(payload.get("actor", "")).strip() or _get_session_username(request) or "unknown"
        entry["changed_by"] = changed_by
        # history: 상태 변경 이력
        history = entry.setdefault("history", [])
        history.append({
            "from_status": prev_status,
            "to_status": status,
            "analyst": entry["analyst"],
            "note": entry["note"],
            "changed_by": changed_by,
            "changed_at": entry["updated_at"],
        })
        # Slack 알림: reviewing/resolved 전환 시
        if status in {"reviewing", "resolved"} and webhooks:
            store = get_query_service().store
            alert_obj = next((a for a in store.alerts if a.alert_id == alert_id), None)
            if alert_obj:
                label = {"reviewing": "검토중", "resolved": "조치예정/완료"}.get(status, status)
                msg = f":mag: [MORI Triage] `{alert_id}` → *{label}*\n*Alert:* {alert_obj.message}\n*담당자:* {entry['analyst'] or 'unknown'}"
                _notify_all_webhooks(webhooks, msg)
        return {"alert_id": alert_id, "triage": entry}

    # ── Slack Webhooks ───────────────────────────────────────────────────────────
    @app.get("/webhooks")
    def webhooks_list() -> dict[str, Any]:
        return {"webhooks": webhooks}

    @app.post("/webhooks")
    def webhooks_add(payload: dict[str, Any]) -> dict[str, Any]:
        name = str(payload.get("name", "")).strip()
        url = str(payload.get("url", "")).strip()
        if not url.startswith("https://hooks.slack.com/") and not url.startswith("http"):
            raise HTTPException(status_code=400, detail="url must be a valid webhook URL")
        entry: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "name": name or "Slack Webhook",
            "url": url,
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        webhooks.append(entry)
        return entry

    @app.delete("/webhooks/{webhook_id}")
    def webhooks_delete(webhook_id: str) -> dict[str, Any]:
        idx = next((i for i, w in enumerate(webhooks) if w["id"] == webhook_id), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="webhook not found")
        removed = webhooks.pop(idx)
        return {"deleted": removed["id"]}

    @app.post("/webhooks/{webhook_id}/test")
    def webhooks_test(webhook_id: str) -> dict[str, Any]:
        wh = next((w for w in webhooks if w["id"] == webhook_id), None)
        if wh is None:
            raise HTTPException(status_code=404, detail="webhook not found")
        ok, err = _send_slack_message(wh["url"], ":white_check_mark: MORI SOC 알림 테스트 메시지입니다.")
        if not ok:
            raise HTTPException(status_code=502, detail=f"slack delivery failed: {err}")
        return {"ok": True}

    # ── Incidents ────────────────────────────────────────────────────────────────
    @app.get("/incidents", tags=["Incidents"])
    def incidents_list(date_from: str = "", date_to: str = "", search: str = "", format: str = "json") -> Any:
        import io, csv as csv_mod
        all_items = list(incidents.values())
        # Date filtering on created_at
        if date_from:
            try:
                from_dt = datetime.fromisoformat(date_from.replace("Z", "+00:00"))
                if from_dt.tzinfo is None:
                    from_dt = from_dt.replace(tzinfo=timezone.utc)
                all_items = [i for i in all_items if i.get("created_at", "") >= _isoformat(from_dt)]
            except ValueError:
                raise HTTPException(status_code=400, detail="date_from must be ISO format (YYYY-MM-DD)")
        if date_to:
            try:
                to_dt = datetime.fromisoformat(date_to.replace("Z", "+00:00"))
                if to_dt.tzinfo is None:
                    to_dt = to_dt.replace(tzinfo=timezone.utc)
                # Include the whole day
                to_dt = to_dt.replace(hour=23, minute=59, second=59)
                all_items = [i for i in all_items if i.get("created_at", "") <= _isoformat(to_dt)]
            except ValueError:
                raise HTTPException(status_code=400, detail="date_to must be ISO format (YYYY-MM-DD)")
        # Text search: title, analyst, status
        if search:
            kw = search.lower()
            all_items = [
                i for i in all_items
                if kw in i.get("title", "").lower()
                or kw in i.get("analyst", "").lower()
                or kw in i.get("status", "").lower()
            ]
        if format == "csv":
            buf = io.StringIO()
            fieldnames = ["인시던트ID", "제목", "상태", "생성일시", "수정일시", "상태변경일시", "경보수", "노트수"]
            writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for inc in all_items:
                writer.writerow({
                    "인시던트ID": inc.get("incident_id", ""),
                    "제목": inc.get("title", ""),
                    "상태": inc.get("status", ""),
                    "생성일시": inc.get("created_at", ""),
                    "수정일시": inc.get("updated_at", ""),
                    "상태변경일시": inc.get("status_updated_at", ""),
                    "경보수": len(inc.get("alert_ids", [])),
                    "노트수": len(inc.get("notes", [])),
                })
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-incidents-{timestamp}.csv"'},
            )
        # Enrich incidents with related host/owner info
        try:
            store = get_query_service().store
            hostnames_map = {host.host_id: host.hostname for host in store.hosts}
            alert_map = {a.alert_id: a for a in store.alerts}
        except Exception:
            hostnames_map = {}
            alert_map = {}
        enriched = []
        for inc in all_items:
            item = dict(inc)
            # Resolve related hostnames/owners from alert_ids
            related_hosts: list[str] = []
            for aid in inc.get("alert_ids", []):
                alert_obj = alert_map.get(aid)
                if alert_obj:
                    hn = hostnames_map.get(alert_obj.host_id or "", alert_obj.host_id or "")
                    if hn and hn not in related_hosts:
                        related_hosts.append(hn)
            item["related_hosts"] = related_hosts
            owners_list = []
            for hn in related_hosts:
                owner_entry = asset_owners.get(hn, {})
                label = " / ".join(p for p in [owner_entry.get("owner", ""), owner_entry.get("team", "")] if p)
                if label and label not in owners_list:
                    owners_list.append(label)
            item["related_owners"] = owners_list
            enriched.append(item)
        return {"incidents": enriched}

    @app.post("/incidents", tags=["Incidents"])
    def incidents_create(payload: dict[str, Any]) -> dict[str, Any]:
        title = str(payload.get("title", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="title is required")
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        analyst = str(payload.get("analyst", "")).strip() or "unknown"
        handler = str(payload.get("handler", "")).strip()
        hostname = str(payload.get("hostname", "")).strip()
        incident: dict[str, Any] = {
            "incident_id": str(uuid.uuid4()),
            "title": title,
            "status": "open",
            "status_updated_at": now_str,
            "hostname": hostname,
            "analyst": analyst,
            "handler": handler or analyst,
            "alert_ids": list(payload.get("alert_ids") or []),
            "notes": [],
            "history": [{"event": "created", "to_status": "open", "analyst": analyst, "changed_at": now_str}],
            "created_at": now_str,
            "updated_at": now_str,
        }
        incidents[incident["incident_id"]] = incident
        return incident

    @app.patch("/incidents/{incident_id}", tags=["Incidents"])
    def incidents_update(incident_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        incident = incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        valid_statuses = {"open", "investigating", "resolved", "closed"}
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        actor = str(payload.get("actor", "")).strip() or _get_session_username(request) or "unknown"
        if "status" in payload:
            new_status = payload["status"]
            if new_status not in valid_statuses:
                raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid_statuses))}")
            prev_status = incident.get("status", "open")
            if new_status != prev_status:
                incident.setdefault("history", []).append({
                    "event": "status_changed",
                    "from_status": prev_status,
                    "to_status": new_status,
                    "analyst": actor,
                    "changed_at": now_str,
                })
                incident["status_updated_at"] = now_str
            incident["status"] = new_status
        if "analyst" in payload:
            new_analyst = str(payload["analyst"]).strip()
            prev_analyst = incident.get("analyst", "")
            if new_analyst and new_analyst != prev_analyst:
                incident.setdefault("history", []).append({
                    "event": "analyst_changed",
                    "from_analyst": prev_analyst,
                    "to_analyst": new_analyst,
                    "analyst": actor,
                    "changed_at": now_str,
                })
                incident["analyst"] = new_analyst
        if "handler" in payload:
            new_handler = str(payload["handler"]).strip()
            prev_handler = incident.get("handler", "")
            if new_handler and new_handler != prev_handler:
                incident.setdefault("history", []).append({
                    "event": "handler_changed",
                    "from_handler": prev_handler,
                    "to_handler": new_handler,
                    "analyst": actor,
                    "changed_at": now_str,
                })
                incident["handler"] = new_handler
        if "title" in payload:
            incident["title"] = str(payload["title"]).strip()
        if "alert_ids" in payload:
            incident["alert_ids"] = list(payload["alert_ids"] or [])
        incident["updated_at"] = now_str
        return incident

    @app.post("/incidents/{incident_id}/notes", tags=["Incidents"])
    def incidents_add_note(incident_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        incident = incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        text = str(payload.get("text", "")).strip()
        if not text:
            raise HTTPException(status_code=400, detail="text is required")
        note: dict[str, Any] = {
            "note_id": str(uuid.uuid4()),
            "text": text,
            "analyst": str(payload.get("analyst", "")).strip() or "unknown",
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        incident["notes"].append(note)
        incident["updated_at"] = note["created_at"]
        return note

    # ── Asset Owners ─────────────────────────────────────────────────────────
    @app.get("/assets/owners", tags=["Assets"])
    def owners_list() -> Any:
        return {"owners": list(asset_owners.values())}

    @app.post("/assets/owners")
    def owners_upsert(payload: dict[str, Any], request: Request) -> Any:
        hostname = str(payload.get("hostname", "")).strip()
        if not hostname:
            raise HTTPException(status_code=400, detail="hostname is required")
        owner_name = str(payload.get("owner", "")).strip()
        # 수정자는 현재 로그인한 사용자로 자동 설정
        changed_by = _get_session_username(request) or "unknown"
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        old_entry = asset_owners.get(hostname, {})
        new_category = str(payload.get("category", old_entry.get("category", ""))).strip()
        new_importance = str(payload.get("importance", old_entry.get("importance", ""))).strip()
        new_exception_until = str(payload.get("exception_until", old_entry.get("exception_until", ""))).strip()
        new_exception_reason = str(payload.get("exception_reason", old_entry.get("exception_reason", ""))).strip()
        entry = {
            "hostname": hostname,
            "owner": owner_name,
            "category": new_category,
            "importance": new_importance,
            "exception_until": new_exception_until,
            "exception_reason": new_exception_reason,
            "email": str(payload.get("email", "")).strip(),
            "team": str(payload.get("team", "")).strip(),
            "updated_at": now_str,
        }
        # Audit log: record changes for owner, category, importance, exception_until, exception_reason fields
        for field in ("owner", "category", "importance", "exception_until", "exception_reason"):
            old_val = old_entry.get(field, "")
            new_val = entry[field]
            if new_val != old_val:
                asset_audit_log.append({
                    "log_id": str(uuid.uuid4()),
                    "hostname": hostname,
                    "field": field,
                    "old_value": old_val,
                    "new_value": new_val,
                    "changed_by": changed_by,
                    "changed_at": now_str,
                })
        asset_owners[hostname] = entry
        return entry

    @app.delete("/assets/owners/{hostname}")
    def owners_delete(hostname: str) -> Any:
        if hostname not in asset_owners:
            raise HTTPException(status_code=404, detail="owner not found")
        asset_owners.pop(hostname)
        return {"deleted": hostname}

    # ── Asset Audit Log ───────────────────────────────────────────────────────
    @app.get("/admin/audit-log", tags=["Assets"])
    def audit_log_list(hostname: str = "", field: str = "") -> Any:
        """자산 담당자/카테고리 변경 이력 조회 (어드민 전용)."""
        result = list(reversed(asset_audit_log))  # 최신 순
        if hostname:
            result = [r for r in result if r["hostname"] == hostname]
        if field:
            result = [r for r in result if r["field"] == field]
        return {"audit_log": result, "total": len(result)}

    # ── Action Plans ──────────────────────────────────────────────────────────
    @app.get("/assets/plans/{host_id}")
    def plan_get(host_id: str) -> Any:
        return action_plans.get(host_id, {"host_id": host_id, "text": "", "target_date": "", "updated_by": "", "updated_at": None})

    @app.put("/assets/plans/{host_id}")
    def plan_upsert(host_id: str, payload: dict[str, Any]) -> Any:
        entry = {
            "host_id": host_id,
            "text": str(payload.get("text", "")).strip(),
            "target_date": str(payload.get("target_date", "")).strip(),
            "updated_by": str(payload.get("updated_by", "")).strip() or "unknown",
            "updated_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        action_plans[host_id] = entry
        return entry

    # ── Per-Vulnerability Actions (조치 계획 / 조치 예외) ─────────────────────
    def _vuln_action_default(vuln_id: str) -> dict[str, Any]:
        return {
            "vuln_id": vuln_id,
            "plan_text": "", "plan_target_date": "", "plan_updated_by": "",
            "exception_until": "", "exception_reason": "", "exception_updated_by": "",
            "updated_at": None,
        }

    def _vuln_exists(vuln_id: str) -> bool:
        for v in get_query_service().store.vulnerabilities:
            if v.vuln_id == vuln_id:
                return True
        return False

    def _vuln_lookup(vuln_id: str) -> tuple[Any, str, str]:
        """vuln_id → (vuln_obj, hostname, cve_label) 반환. 없으면 (None, "", vuln_id)."""
        store_ = get_query_service().store
        for v in store_.vulnerabilities:
            if v.vuln_id == vuln_id:
                hostname = next((h.hostname for h in store_.hosts if h.host_id == v.host_id), v.host_id)
                return v, hostname, (v.cve or vuln_id)
        return None, "", vuln_id

    def _record_vuln_audit(
        hostname: str,
        cve_label: str,
        old_entry: dict[str, Any],
        new_entry: dict[str, Any],
        changed_by: str,
        now_str: str,
        fields: tuple[str, ...],
    ) -> None:
        """vuln_actions 변경분을 asset_audit_log에 기록한다."""
        if not hostname:
            return
        for fld in fields:
            old_val = old_entry.get(fld, "")
            new_val = new_entry.get(fld, "")
            if old_val == new_val:
                continue
            asset_audit_log.append({
                "log_id": str(uuid.uuid4()),
                "hostname": hostname,
                "field": f"vuln_{fld} [{cve_label}]",
                "old_value": old_val,
                "new_value": new_val,
                "changed_by": changed_by,
                "changed_at": now_str,
            })

    @app.get("/vulnerabilities/{vuln_id}/action", tags=["Vulnerabilities"])
    def vuln_action_get(vuln_id: str) -> Any:
        if not _vuln_exists(vuln_id):
            raise HTTPException(status_code=404, detail="vulnerability not found")
        return vuln_actions.get(vuln_id, _vuln_action_default(vuln_id))

    @app.put("/vulnerabilities/{vuln_id}/plan", tags=["Vulnerabilities"])
    def vuln_plan_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        old_entry = dict(vuln_actions.get(vuln_id, _vuln_action_default(vuln_id)))
        entry = old_entry | {"vuln_id": vuln_id}
        entry["plan_text"] = str(payload.get("plan_text", "")).strip()
        entry["plan_target_date"] = str(payload.get("plan_target_date", "")).strip()
        entry["plan_updated_by"] = str(payload.get("plan_updated_by", "")).strip() or "unknown"
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        vuln_actions[vuln_id] = entry
        changed_by = entry["plan_updated_by"] if entry["plan_updated_by"] != "unknown" else (_get_session_username(request) or "unknown")
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("plan_text", "plan_target_date"))
        return entry

    @app.put("/vulnerabilities/{vuln_id}/exception", tags=["Vulnerabilities"])
    def vuln_exception_upsert(vuln_id: str, payload: dict[str, Any], request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        old_entry = dict(vuln_actions.get(vuln_id, _vuln_action_default(vuln_id)))
        entry = old_entry | {"vuln_id": vuln_id}
        entry["exception_until"] = str(payload.get("exception_until", "")).strip()
        entry["exception_reason"] = str(payload.get("exception_reason", "")).strip()
        entry["exception_updated_by"] = str(payload.get("exception_updated_by", "")).strip() or "unknown"
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        vuln_actions[vuln_id] = entry
        changed_by = entry["exception_updated_by"] if entry["exception_updated_by"] != "unknown" else (_get_session_username(request) or "unknown")
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("exception_until", "exception_reason"))
        return entry

    @app.delete("/vulnerabilities/{vuln_id}/exception", tags=["Vulnerabilities"])
    def vuln_exception_clear(vuln_id: str, request: Request) -> Any:
        vuln_obj, hostname, cve_label = _vuln_lookup(vuln_id)
        if vuln_obj is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        entry = vuln_actions.get(vuln_id)
        if entry is None:
            return {"ok": True}
        old_entry = dict(entry)
        entry["exception_until"] = ""
        entry["exception_reason"] = ""
        entry["exception_updated_by"] = ""
        entry["updated_at"] = _isoformat(datetime.now(tz=timezone.utc))
        changed_by = _get_session_username(request) or "unknown"
        _record_vuln_audit(hostname, cve_label, old_entry, entry, changed_by, entry["updated_at"], ("exception_until", "exception_reason"))
        return {"ok": True, "vuln_id": vuln_id}

    # ── Guides ───────────────────────────────────────────────────────────────
    @app.get("/guides")
    def guides_list() -> Any:
        return {"guides": list(guides.values())}

    @app.get("/guides/{guide_id}")
    def guide_get(guide_id: str) -> Any:
        if guide_id not in guides:
            raise HTTPException(status_code=404, detail="guide not found")
        return guides[guide_id]

    @app.put("/guides/{guide_id}")
    def guide_upsert(guide_id: str, payload: dict[str, Any]) -> Any:
        existing = guides.get(guide_id, {"id": guide_id})
        entry = {
            **existing,
            "title": str(payload.get("title", existing.get("title", guide_id))).strip(),
            "content": str(payload.get("content", existing.get("content", ""))),
            "updated_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        guides[guide_id] = entry
        return entry

    # ── Asset Collection Board ───────────────────────────────────────────────
    @app.get("/assets", tags=["Assets"])
    def assets_get(format: str = "json", source: str = "all") -> Any:
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"assets unavailable: {exc}") from exc
        if format == "csv":
            valid_sources = {"fleet", "zabbix", "trivy"}
            if source not in valid_sources:
                raise HTTPException(status_code=400, detail=f"source must be one of: {', '.join(sorted(valid_sources))}")
            csv_content = _assets_csv(payload, source)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"mori-assets-{source}-{timestamp}.csv"
            return StreamingResponse(
                iter([csv_content]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        return payload

    # ── On-demand 수집 (사용자 새로고침 시 즉시 폴링) ──────────────────────
    @app.post("/assets/refresh", tags=["Assets"])
    def assets_refresh(payload: dict[str, Any], request: Request) -> Any:
        """사용자가 새로고침 버튼을 누르면 해당 소스를 on-demand 수집한다.

        요청: ``{"source": "zabbix"}`` 또는 ``{"source": "fleet"}``
        응답: 수집 결과 상태
        """
        source = str(payload.get("source", "")).strip().lower()
        valid_sources = {"zabbix", "fleet", "wazuh", "trivy"}
        if source not in valid_sources:
            raise HTTPException(status_code=400, detail=f"source must be one of: {', '.join(sorted(valid_sources))}")

        from mori_soc.pollers.zabbix import ZabbixPoller
        from mori_soc.pollers.fleet import FleetPoller
        from mori_soc.pollers.wazuh import WazuhPoller
        from mori_soc.pollers.trivy import TrivyPoller
        from mori_soc.services import EnvelopeEntityMapper as _EM

        poller_map: dict[str, type] = {
            "zabbix": ZabbixPoller,
            "fleet": FleetPoller,
            "wazuh": WazuhPoller,
            "trivy": TrivyPoller,
        }
        poller_cls = poller_map[source]
        poller = poller_cls()

        try:
            mapper = _EM()
            from mori_soc.pollers.base import _repository_from_env
            repository = _repository_from_env()
            result = poller.run_cycle(repository, mapper)
            username = _get_session_username(request) or "unknown"
            logger.info("[on-demand] %s refresh triggered by %s — %s", source, username, result.status)
            return {"status": result.status, "source": source, "message": result.message or "completed"}
        except Exception as exc:
            logger.error("[on-demand] %s refresh failed: %s", source, exc)
            return {"status": "error", "source": source, "message": str(exc)}

    # ── Fleet 전용 API ───────────────────────────────────────────────────────
    @app.get("/fleet/hosts", tags=["Fleet"])
    def fleet_hosts_get(format: str = "json") -> Any:
        """Fleet(PC 자산) 전용 호스트 목록 API."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"fleet hosts unavailable: {exc}") from exc
        fleet_data = payload.get("fleet", {})
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            hosts = fleet_data.get("hosts", [])
            if hosts:
                _fleet_header_map = {"hostname": "호스트명", "asset_type": "자산유형", "platform": "플랫폼", "primary_ip": "IP주소", "status": "상태", "risk_score": "위험점수", "last_seen_at": "최종확인일시", "owner": "담당자", "team": "팀"}
                fieldnames = list(_fleet_header_map.keys())
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writerow(_fleet_header_map)
                writer.writerows(hosts)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-fleet-hosts-{timestamp}.csv"'},
            )
        return {"source": "fleet", **fleet_data}

    # ── Zabbix 전용 API ──────────────────────────────────────────────────────
    @app.get("/zabbix/hosts", tags=["Zabbix"])
    def zabbix_hosts_get(format: str = "json") -> Any:
        """Zabbix(서버 자산) 전용 호스트 목록 API."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"zabbix hosts unavailable: {exc}") from exc
        zabbix_data = payload.get("zabbix", {})
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            hosts = zabbix_data.get("hosts", [])
            if hosts:
                _zabbix_header_map = {"hostname": "호스트명", "category": "분류", "importance": "중요도", "primary_ip": "IP주소", "status": "상태", "latest_metric": "최근메트릭", "latest_value": "최근값", "owner": "담당자", "team": "팀"}
                fieldnames = list(_zabbix_header_map.keys())
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writerow(_zabbix_header_map)
                writer.writerows(hosts)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-zabbix-hosts-{timestamp}.csv"'},
            )
        return {"source": "zabbix", **zabbix_data}

    # ── Trivy 전용 API ───────────────────────────────────────────────────────
    @app.get("/trivy/vulnerabilities", tags=["Trivy"])
    def trivy_vulnerabilities_get(format: str = "json", severity: str = "all") -> Any:
        """Trivy(취약점) 전용 취약점 목록 API. severity=critical|high|medium|low|all"""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"trivy vulnerabilities unavailable: {exc}") from exc
        trivy_data = payload.get("trivy", {})
        rows = trivy_data.get("by_host", [])
        valid_severities = {"critical", "high", "medium", "low", "all"}
        if severity not in valid_severities:
            raise HTTPException(status_code=400, detail=f"severity must be one of: {', '.join(sorted(valid_severities))}")
        if severity != "all":
            rows = [r for r in rows if (r.get(severity, 0) or 0) > 0]
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            if rows:
                _trivy_header_map = {"hostname": "호스트명", "critical": "심각", "high": "높음", "medium": "중간", "low": "낮음", "info": "정보", "total": "합계", "latest_cve": "최근CVE", "action_plan": "조치계획", "action_target_date": "목표완료일"}
                fieldnames = list(_trivy_header_map.keys())
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writerow(_trivy_header_map)
                writer.writerows(rows)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-trivy-vulns-{timestamp}.csv"'},
            )
        return {"source": "trivy", "severity_filter": severity, "count": len(rows), "by_host": rows}

    # ── Compliance Reports (증적 Export) ────────────────────────────────────
    @app.get("/compliance/reports", tags=["Compliance"])
    def compliance_reports_list() -> dict[str, Any]:
        """사용 가능한 증적 리포트 타입 목록."""
        labels = {
            "asset_inspection": "자산 점검 리포트",
            "account_privilege": "계정/권한 점검 리포트",
            "log_collection_status": "로그 수집 상태 리포트",
            "vulnerability_assessment": "취약점 점검 리포트",
            "monthly_operations": "월간 운영 리포트",
        }
        return {
            "report_types": [
                {
                    "id": rt,
                    "label": labels.get(rt, rt),
                    "url_json": f"/compliance/reports/{rt}",
                    "url_csv": f"/compliance/reports/{rt}?format=csv",
                    "url_pdf": f"/compliance/reports/{rt}?format=pdf",
                }
                for rt in REPORT_TYPES
            ]
        }

    @app.get("/compliance/reports/{report_type}", tags=["Compliance"])
    def compliance_report_get(report_type: str, format: str = "json") -> Any:
        """증적 리포트 생성. format=json|csv|pdf"""
        if report_type not in REPORT_TYPES:
            raise HTTPException(status_code=400, detail=f"Unknown report type: {report_type}. Valid: {', '.join(REPORT_TYPES)}")
        try:
            report = generate_report(report_type, get_query_service())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"report generation failed: {exc}") from exc
        if format == "csv":
            csv_content = "\ufeff" + report_to_csv(report)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"mori-{report_type.replace('_', '-')}-{timestamp}.csv"
            return StreamingResponse(
                iter([csv_content]),
                media_type="text/csv; charset=utf-8-sig",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        if format == "pdf":
            try:
                pdf_bytes = report_to_pdf(report)
            except RuntimeError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"PDF rendering failed: {exc}") from exc
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            filename = f"mori-{report_type.replace('_', '-')}-{timestamp}.pdf"
            return StreamingResponse(
                iter([pdf_bytes]),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        return report

    return app


def create_app_from_env() -> Any:
    return create_app(service_factory=create_query_service_from_env)


def _query_csv_filename(intent: str) -> str:
    safe_intent = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in intent).strip("-")
    if not safe_intent:
        safe_intent = "query"
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"mori-query-{safe_intent}-{timestamp}.csv"


# ── 소스별 stale 판단 기준 (docs/collection-standards.md 기준) ──────
_SOURCE_STALE_THRESHOLDS: dict[str, int] = {
    "zabbix": 300,       # 5분 (서버: 30초 주기)
    "fleet": 864000,     # 10일 (PC: 주 1회 수집)
    "wazuh": 600,        # 10분
    "trivy": 604800,     # 7일
    "ldap": 28800,       # 8시간
    "host_log": 600,     # 10분 (기본)
}
_DEFAULT_STALE_THRESHOLD = 600  # 기준표에 없는 소스는 10분


def _source_coverage(store: InMemoryQueryStore) -> list[dict[str, Any]]:
    now = datetime.now(tz=timezone.utc)
    all_host_ids = {h.host_id for h in store.hosts}
    hostnames_map = {h.host_id: h.hostname.lower() for h in store.hosts}
    ordered_sources = ["fleet", "wazuh", "zabbix", "trivy", "host_log"]
    # hostname 기준으로 중복 제거 (동일 호스트가 여러 host_id를 가질 수 있음)
    sources: dict[str, set[str]] = {source: set() for source in ordered_sources}
    for alias in store.host_aliases:
        # 실제 등록된 호스트만 카운트 (고아 alias 제외)
        if alias.host_id in all_host_ids:
            hostname_key = hostnames_map.get(alias.host_id, alias.host_id)
            sources.setdefault(alias.source, set()).add(hostname_key)
    sync_map = {item.source: item for item in store.source_syncs}
    for source in sync_map:
        sources.setdefault(source, set())
    rows: list[dict[str, Any]] = []
    for source, host_ids in sources.items():
        sync = sync_map.get(source)
        # stale 판단: last_success_at 이 stale_threshold 이상 경과
        stale_threshold = _SOURCE_STALE_THRESHOLDS.get(source, _DEFAULT_STALE_THRESHOLD)
        is_stale = True  # sync 기록 없으면 stale
        if sync and sync.last_success_at:
            elapsed = (now - sync.last_success_at).total_seconds()
            is_stale = elapsed > stale_threshold
        rows.append(
            {
                "source": source,
                "host_count": len(host_ids),
                "status": sync.status if sync else "unknown",
                "is_stale": is_stale,
                "stale_threshold_seconds": stale_threshold,
                "last_sync_at": _isoformat(sync.last_sync_at) if sync else None,
                "last_success_at": _isoformat(sync.last_success_at) if sync else None,
                "last_error_at": _isoformat(sync.last_error_at) if sync else None,
                "message": sync.message if sync else None,
                "records_collected": sync.records_collected if sync else 0,
                "envelopes_normalized": sync.envelopes_normalized if sync else 0,
                "entities_saved": sync.entities_saved if sync else 0,
            }
        )
    return rows


def _status_detail_rows(rows: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "host_id": row.host_id,
            "hostname": row.hostname,
            "status": row.status,
            "risk_score": row.risk_score,
            "last_seen_at": _isoformat(row.last_seen_at),
            "last_alert_at": _isoformat(row.last_alert_at),
            "last_observation_at": _isoformat(row.last_observation_at),
            "source_url": _host_source_url(row.host_id, row.hostname),
        }
        for row in rows
    ]


def _owner_label_for(hostname: str, owners: Mapping[str, dict[str, Any]]) -> str:
    """hostname → '담당자 / 팀' 문자열.  owners 가 없으면 '-'."""
    entry = owners.get(hostname, {})
    parts = [entry.get("owner", ""), entry.get("team", "")]
    return " / ".join(p for p in parts if p) or "-"


def _alert_detail_rows(alerts: list[Any], hostnames: Mapping[str, str],
                        owners: Mapping[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    _owners = owners or {}
    rows = []
    for alert in sorted(alerts, key=lambda item: item.observed_at, reverse=True):
        hn = hostnames.get(alert.host_id or "", alert.host_id or "-")
        rows.append({
            "alert_id": alert.alert_id,
            "host_id": alert.host_id,
            "hostname": hn,
            "owner": _owner_label_for(hn, _owners),
            "source": alert.source,
            "severity": alert.severity,
            "message": alert.message,
            "observed_at": _isoformat(alert.observed_at),
        })
    return rows


def _critical_vuln_detail_rows(store: InMemoryQueryStore, hostnames: Mapping[str, str],
                                owners: Mapping[str, dict[str, Any]] | None = None,
                                vuln_actions: Mapping[str, Mapping[str, Any]] | None = None) -> list[dict[str, Any]]:
    _owners = owners or {}
    _vuln_actions = vuln_actions or {}
    critical_vulns = [vuln for vuln in store.vulnerabilities if vuln.severity == "critical"]
    rows = []
    for vuln in sorted(critical_vulns, key=lambda item: item.detected_at, reverse=True):
        hn = hostnames.get(vuln.host_id, vuln.host_id)
        action = _vuln_actions.get(vuln.vuln_id, {}) or {}
        rows.append({
            "vuln_id": vuln.vuln_id,
            "host_id": vuln.host_id,
            "hostname": hn,
            "owner": _owner_label_for(hn, _owners),
            "source": vuln.source,
            "cve": vuln.cve,
            "package_name": vuln.package_name,
            "detected_at": _isoformat(vuln.detected_at),
            "plan_text": str(action.get("plan_text", "") or ""),
            "plan_target_date": str(action.get("plan_target_date", "") or ""),
            "plan_updated_by": str(action.get("plan_updated_by", "") or ""),
            "exception_until": str(action.get("exception_until", "") or ""),
            "exception_reason": str(action.get("exception_reason", "") or ""),
            "exception_updated_by": str(action.get("exception_updated_by", "") or ""),
        })
    return rows


def _ingested_record_rows(store: InMemoryQueryStore) -> list[dict[str, Any]]:
    return [
        {"entity_type": "alerts", "count": len(store.alerts)},
        {"entity_type": "vulnerabilities", "count": len(store.vulnerabilities)},
        {"entity_type": "query_results", "count": len(store.query_results)},
        {"entity_type": "observations", "count": len(store.observations)},
    ]


GRAFANA_BASE_URL = os.getenv("MORI_GRAFANA_URL", "http://mori.rmstudio.co.kr:13000")
# Grafana 데이터소스 UID — Grafana 관리 화면 > Configuration > Data sources > 해당 소스 상세에서 확인
# 기본값 "loki" 는 datasource 이름으로도 동작하지만, UID 를 넣으면 더 안정적
_LOKI_DATASOURCE_UID = os.getenv("MORI_LOKI_DATASOURCE_UID", "loki")
_LOKI_DATASOURCE_TYPE = os.getenv("MORI_LOKI_DATASOURCE_TYPE", "loki")

# 호스트 소스 딥링크용 외부 UI URL
# server- prefix → Zabbix 웹 UI (예: http://mori.rmstudio.co.kr:8080)
_ZABBIX_UI_URL = os.getenv("MORI_ZABBIX_UI_URL", "").rstrip("/")
# pc- prefix → Fleet 웹 UI (예: https://fleet.example.com)
_FLEET_UI_URL = os.getenv("MORI_FLEET_UI_URL", "").rstrip("/")


def _grafana_explore_url(host_id: str | None, raw_ref: str | None = None) -> str | None:
    """Grafana 10+ Explore 딥링크 URL 생성 (panes 포맷).

    Grafana 10 부터 left= 파라미터가 제거되고 panes= 포맷으로 변경됐다.
    host_id 또는 raw_ref 기준으로 Loki LogQL 쿼리를 생성한다.
    """
    if host_id:
        loki_query = '{host_id="' + host_id + '"}'
    elif raw_ref:
        loki_query = '{raw_ref="' + raw_ref + '"}'
    else:
        return None

    ds_uid = _LOKI_DATASOURCE_UID
    ds_type = _LOKI_DATASOURCE_TYPE

    pane = {
        "datasource": ds_uid,
        "queries": [
            {
                "refId": "A",
                "expr": loki_query,
                "queryType": "range",
                "datasource": {"type": ds_type, "uid": ds_uid},
            }
        ],
        "range": {"from": "now-6h", "to": "now"},
    }
    panes_json = _url_quote(json.dumps({"pane": pane}, separators=(",", ":")), safe="")
    return f"{GRAFANA_BASE_URL}/explore?schemaVersion=1&panes={panes_json}&orgId=1"


def _host_source_url(host_id: str, hostname: str) -> str | None:
    """호스트 ID prefix 에 따라 Zabbix / Fleet 호스트 페이지 URL 을 반환한다.

    환경변수 ``MORI_ZABBIX_UI_URL`` / ``MORI_FLEET_UI_URL`` 이 설정되지 않으면 None.
    """
    if host_id.startswith("server-") and _ZABBIX_UI_URL:
        # Zabbix 호스트 목록에서 이름으로 필터링
        return f"{_ZABBIX_UI_URL}/zabbix.php?action=host.list&filter_set=1&filter_host={_url_quote(hostname)}"
    if host_id.startswith("pc-") and _FLEET_UI_URL:
        # Fleet 호스트 목록에서 hostname 검색
        return f"{_FLEET_UI_URL}/hosts?query={_url_quote(hostname)}"
    return None


def _recent_activity(store: InMemoryQueryStore, limit: int = 10) -> list[dict[str, Any]]:
    activity: list[dict[str, Any]] = []
    for alert in store.alerts:
        activity.append(
            {
                "entity_type": "alert",
                "record_id": alert.alert_id,
                "host_id": alert.host_id,
                "source": alert.source,
                "summary": alert.message,
                "severity": alert.severity,
                "observed_at": _isoformat(alert.observed_at),
                "grafana_url": _grafana_explore_url(alert.host_id, getattr(alert, "raw_ref", None)),
                "sort_at": alert.observed_at,
            }
        )
    for result in store.query_results:
        activity.append(
            {
                "entity_type": "query_result",
                "record_id": result.query_result_id,
                "host_id": result.host_id,
                "source": result.source,
                "summary": result.query_name or "fleet_query",
                "severity": None,
                "observed_at": _isoformat(result.observed_at),
                "grafana_url": _grafana_explore_url(result.host_id, getattr(result, "raw_ref", None)),
                "sort_at": result.observed_at,
            }
        )
    for observation in store.observations:
        value = observation.metric_value or "-"
        suffix = observation.unit or ""
        activity.append(
            {
                "entity_type": "observation",
                "record_id": observation.observation_id,
                "host_id": observation.host_id,
                "source": observation.source,
                "summary": f"{observation.observation_type}:{observation.metric_name}={value}{suffix}",
                "severity": observation.severity,
                "observed_at": _isoformat(observation.observed_at),
                "grafana_url": _grafana_explore_url(observation.host_id, getattr(observation, "raw_ref", None)),
                "sort_at": observation.observed_at,
            }
        )
    activity.sort(key=lambda item: item["sort_at"], reverse=True)
    trimmed = activity[:limit]
    for item in trimmed:
        item.pop("sort_at", None)
    return trimmed


def _recommended_queries() -> list[dict[str, Any]]:
    return [
        {
            "label": "오프라인 호스트",
            "text": "오프라인 호스트 보여줘",
            "payload": {"intent": "offline_hosts", "scope": {"time_range": "24h"}, "filters": {}},
        },
        {
            "label": "Wazuh high alert",
            "text": "최근 24시간 wazuh high alert 요약",
            "payload": {
                "intent": "alert_summary",
                "scope": {"time_range": "24h", "source": "wazuh", "severity": "high"},
                "filters": {},
            },
        },
        {
            "label": "취약점 상위 호스트",
            "text": "취약점 많은 호스트 top 5",
            "payload": {"intent": "top_vulnerable_hosts", "scope": {"time_range": "7d"}, "filters": {"limit": 5}},
        },
        {
            "label": "리스크 호스트",
            "text": "위험한 호스트 보여줘",
            "payload": {"intent": "risky_hosts", "scope": {"time_range": "24h"}, "filters": {}},
        },
    ]


def _latest_status_sort_key(row: Any) -> tuple[int, int, float]:
    status_rank = {"offline": 0, "unknown": 1, "online": 2}
    return (status_rank.get(row.status, 3), -row.risk_score, -_timestamp(row.last_seen_at))


def _timestamp(value: datetime | None) -> float:
    if value is None:
        return 0.0
    return value.timestamp()


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("query scope values must be strings")
    value = value.strip()
    return value or None


def _send_slack_message(webhook_url: str, text: str) -> tuple[bool, str]:
    """Slack Incoming Webhook으로 메시지를 전송한다. (ok, error_message) 반환."""
    try:
        data = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200, ""
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        return False, str(exc)


def _notify_all_webhooks(webhooks: list[dict], message: str) -> None:
    """설정된 모든 Slack webhook으로 메시지를 전송한다. 실패는 무시."""
    for wh in webhooks:
        try:
            _send_slack_message(wh["url"], message)
        except Exception:
            pass


__all__ = [
    "DEFAULT_UI_PAYLOAD",
    "build_dashboard_payload",
    "build_query_request",
    "create_app",
    "create_app_from_env",
    "create_query_service",
    "create_query_service_from_env",
    "interpret_query_text",
    "render_query_console_html",
    "render_user_dashboard_html",
]