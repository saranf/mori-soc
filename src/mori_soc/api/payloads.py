"""Pure payload builders and low-level rendering helpers (Task J-4a).

Extracted verbatim from ``server.py`` so route modules can share them without
importing the FastAPI app factory. Stateless: every function takes its inputs
explicitly. Dependency direction: ``i18n -> templates -> payloads -> server``.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error
from urllib.parse import quote as _url_quote
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.services.intent_parser import NaturalLanguageQueryParser
from mori_soc.services.query_service import InMemoryQueryStore, QueryService
from mori_soc.services.views import host_risk_summary_view, latest_host_status_view
from mori_soc.api.templates import (
    DOCS_PORTAL_URL,
    DEFAULT_USER_DASHBOARD_PREFERENCES,
    USER_DASHBOARD_CARD_LABELS,
    USER_DASHBOARD_SECTION_LABELS,
    USER_DASHBOARD_ASSET_COLUMN_LABELS,
    USER_DASHBOARD_GUIDE_LABELS,
)


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
    since_12h = now - timedelta(hours=12)
    status_rows = sorted(latest_host_status_view(store), key=_latest_status_sort_key)
    risk_rows = host_risk_summary_view(store)
    source_coverage = _source_coverage(store)
    hostnames = {host.host_id: host.hostname for host in store.hosts}

    alerts_24h = [
        alert for alert in store.alerts if alert.observed_at >= since_24h and alert.severity in {"high", "critical"}
    ]
    alerts_12h = [alert for alert in alerts_24h if alert.observed_at >= since_12h]
    overview = {
        "total_hosts": len(status_rows),
        "online_hosts": sum(1 for row in status_rows if row.status == "online"),
        "offline_hosts": sum(1 for row in status_rows if row.status == "offline"),
        "unknown_hosts": sum(1 for row in status_rows if row.status not in {"online", "offline"}),
        "alerts_24h": len(alerts_24h),
        "alerts_12h": len(alerts_12h),
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

    # Control category 별 집계 — 통제 카탈로그의 '섹션명'으로 그룹핑해 카탈로그 트리와 매칭시킴.
    # (기존엔 control_id 프리픽스 "2.5"만 써서 이름 없음·문자열정렬로 카탈로그와 불일치)
    from mori_soc.services.control_catalog import load_catalog
    _catalog = load_catalog()
    _sec_of: dict[str, str] = {}
    _fw_of: dict[str, str] = {}
    for cc in _catalog.get("controls", []):
        cid = str(cc.get("id", ""))
        _sec_of[cid] = cc.get("section") or cc.get("domain") or cid.rsplit(".", 1)[0]
        _fw_of[cid] = cc.get("framework", "")

    def _cat_of(control_id: str) -> str:
        sec = _sec_of.get(control_id)
        if sec:
            return sec
        parts = control_id.rsplit(".", 1)
        return parts[0] if len(parts) > 1 else control_id

    by_category: dict[str, dict[str, int]] = {}
    cat_fw: dict[str, str] = {}
    for c in checks:
        cat = _cat_of(c.control_id)
        cat_fw.setdefault(cat, _fw_of.get(c.control_id, ""))
        bucket = by_category.setdefault(cat, {"pass": 0, "fail": 0, "warning": 0, "not_applicable": 0, "not_checked": 0, "total": 0})
        bucket[c.status] = bucket.get(c.status, 0) + 1
        bucket["total"] += 1

    def _sort_key(cat: str):
        # 프레임워크(ISMS-P 먼저) → 섹션 번호 자연 정렬 ("2.5"가 "2.10"보다 앞)
        fw_rank = 0 if cat_fw.get(cat, "") == "isms-p" else 1
        head = cat.split(" ", 1)[0]  # "2.5" 또는 "A.8"
        key = [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-]", head)]
        return (fw_rank, key)

    categories = [
        {"category": cat, **counts}
        for cat, counts in sorted(by_category.items(), key=lambda kv: _sort_key(kv[0]))
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
            "resolved_at": _isoformat(alert.resolved_at) if getattr(alert, "resolved_at", None) else None,
            "source_event_id": getattr(alert, "source_event_id", None),  # Zabbix eventid 등
            "rule_id": getattr(alert, "rule_id", None),                  # Zabbix triggerid 등
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
