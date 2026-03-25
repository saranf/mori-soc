from __future__ import annotations

import json
import os
import uuid
import urllib.request
import urllib.error
from urllib.parse import quote as _url_quote
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.services.intent_parser import QUERY_GUIDE_EXAMPLES, NaturalLanguageQueryParser
from mori_soc.services.query_catalog import PHASE1_QUERY_CATALOG
from mori_soc.services.query_service import InMemoryQueryStore, QueryService, query_response_to_csv
from mori_soc.services.views import host_risk_summary_view, latest_host_status_view

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


DEFAULT_UI_PAYLOAD = {
    "intent": "offline_hosts",
    "scope": {"time_range": "24h"},
    "filters": {},
}

DOCS_PORTAL_URL = os.getenv("MORI_DOCS_PORTAL_URL", "http://mori.rmstudio.co.kr:37854/")
FLEET_UI_URL = os.getenv("MORI_FLEET_UI_URL", "")
ZABBIX_UI_URL = os.getenv("MORI_ZABBIX_UI_URL", "")
USER_DASHBOARD_CARD_LABELS = {
    "total_hosts": "Total Hosts",
    "offline_hosts": "Offline Hosts",
    "alerts_24h": "High Alerts 24h",
    "critical_vulns": "Critical Vulns",
    "sources_reporting": "Sources Reporting",
    "sources_healthy": "Healthy Collectors",
    "ingested_records": "Ingested Records",
}
USER_DASHBOARD_SECTION_LABELS = {
    "source_coverage": "Source Coverage",
    "latest_status": "Latest Host Status",
    "risk_summary": "Risk Summary",
    "recent_activity": "Recent Activity",
}
USER_DASHBOARD_ASSET_COLUMN_LABELS = {
    "show_importance": "중요도 컬럼",
    "show_isms_control": "ISMS-P 통제 컬럼",
    "show_iso27001_control": "ISO 27001 통제 컬럼",
}
USER_DASHBOARD_GUIDE_LABELS = {
    "zabbix_setup": "🖧 Zabbix 에이전트 설정",
    "fleet_install": "🖥️ Fleet 에이전트 설치",
    "isms_criteria": "📋 ISMS-P 심사 기준",
    "iso27001_criteria": "🌐 ISO 27001 기준",
    "ldap_setup": "🔐 LDAP 통합 설정",
    "incident_response": "🚨 인시던트 대응 절차",
    "security_policy": "📜 보안 정책 가이드",
}
DEFAULT_USER_DASHBOARD_PREFERENCES = {
    "cards": {
        "total_hosts": True,
        "offline_hosts": True,
        "alerts_24h": True,
        "critical_vulns": True,
        "sources_reporting": False,
        "sources_healthy": False,
        "ingested_records": False,
    },
    "sections": {
        "source_coverage": False,
        "latest_status": True,
        "risk_summary": True,
        "recent_activity": True,
    },
    "asset_columns": {
        "show_importance": True,
        "show_isms_control": True,
        "show_iso27001_control": True,
    },
    "guides": {
        "zabbix_setup": True,
        "fleet_install": True,
        "isms_criteria": True,
        "iso27001_criteria": True,
        "ldap_setup": True,
        "incident_response": True,
        "security_policy": True,
    },
}


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


def build_dashboard_payload(service: QueryService) -> dict[str, Any]:
    store = service.store
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
        "sources_healthy": sum(1 for item in source_coverage if item["status"] == "success"),
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
            "alerts_24h": _alert_detail_rows(alerts_24h, hostnames),
            "critical_vulns": _critical_vuln_detail_rows(store, hostnames),
            "sources_reporting": [item for item in source_coverage if item["host_count"] > 0],
            "sources_healthy": [item for item in source_coverage if item["status"] == "success"],
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


def build_assets_payload(
    service: QueryService,
    owners: dict[str, dict[str, Any]] | None = None,
    plans: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from mori_soc.services.asset_classifier import classify_server_as_dict

    owners = owners or {}
    plans = plans or {}
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
        zabbix_hosts.append({
            "host_id": host.host_id,
            "hostname": host.hostname,
            "asset_type": "Server",
            "category": classification["category"],
            "importance": classification["importance"],
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
        })
    zabbix_hosts.sort(key=lambda h: (
        {"상": 0, "중": 1, "하": 2}.get(h["importance"], 1),
        h["status"] != "offline",
        h["hostname"],
    ))

    # Trivy vulnerabilities grouped by host — 조치계획 포함
    vuln_by_host: dict[str, dict] = {}
    for vuln in store.vulnerabilities:
        if vuln.source != "trivy":
            continue
        hid = vuln.host_id
        if hid not in vuln_by_host:
            plan = plans.get(hid, {})
            vuln_by_host[hid] = {
                "host_id": hid,
                "hostname": hostnames.get(hid, hid),
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "total": 0,
                "latest_cve": None,
                "latest_detected_at": None,
                "action_plan": plan.get("text", ""),
                "action_target_date": plan.get("target_date", ""),
                "action_updated_by": plan.get("updated_by", ""),
            }
        entry = vuln_by_host[hid]
        sev = vuln.severity
        entry[sev] = entry.get(sev, 0) + 1
        entry["total"] += 1
        if entry["latest_detected_at"] is None or vuln.detected_at > entry["latest_detected_at"]:
            entry["latest_detected_at"] = vuln.detected_at
            entry["latest_cve"] = vuln.cve

    trivy_rows = sorted(vuln_by_host.values(), key=lambda r: (-r["critical"], -r["high"], -r["total"]))
    for row in trivy_rows:
        if row["latest_detected_at"]:
            row["latest_detected_at"] = _isoformat(row["latest_detected_at"])

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
        writer.writerow(["host_id", "hostname", "asset_type", "platform", "primary_ip", "status",
                         "risk_score", "last_seen_at", "query_result_count", "owner", "team"])
        for h in payload["fleet"]["hosts"]:
            writer.writerow([
                h["host_id"], h["hostname"], h["asset_type"], h["platform"], h["primary_ip"],
                h["status"], h["risk_score"], h["last_seen_at"] or "", h["query_result_count"],
                h.get("owner", ""), h.get("team", ""),
            ])
    elif source == "zabbix":
        writer.writerow(["host_id", "hostname", "category", "importance", "platform",
                         "primary_ip", "status", "risk_score", "last_seen_at",
                         "observation_count", "latest_metric", "latest_value", "owner", "team"])
        for h in payload["zabbix"]["hosts"]:
            writer.writerow([
                h["host_id"], h["hostname"], h.get("category", ""), h.get("importance", ""),
                h["platform"], h["primary_ip"],
                h["status"], h["risk_score"], h["last_seen_at"] or "",
                h["observation_count"], h["latest_metric"] or "", h["latest_value"] or "",
                h.get("owner", ""), h.get("team", ""),
            ])
    elif source == "trivy":
        writer.writerow(["host_id", "hostname", "critical", "high", "medium", "low", "info", "total",
                         "latest_cve", "latest_detected_at", "action_plan", "action_target_date", "action_updated_by"])
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


def render_login_html(error: str = "", next_url: str = "/ui") -> str:
    """로그인 페이지 HTML 반환."""
    error_html = f'<div class="login-error">{error}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MORI SOC — 로그인</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a1628; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .login-card {{ background: #0f2035; border: 1px solid #1e3a5f; border-radius: 16px; padding: 40px 36px;
                   width: 100%; max-width: 400px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
    .login-logo {{ text-align: center; margin-bottom: 28px; }}
    .login-logo h1 {{ font-size: 28px; font-weight: 800; color: #7dd3fc; letter-spacing: -0.5px; }}
    .login-logo p {{ font-size: 13px; color: #64748b; margin-top: 6px; }}
    label {{ display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; font-weight: 600; letter-spacing: .5px; }}
    input {{ width: 100%; background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px;
             color: #e2e8f0; padding: 10px 14px; font-size: 14px; outline: none; transition: border-color .2s; }}
    input:focus {{ border-color: #3b82f6; }}
    .field {{ margin-bottom: 16px; }}
    .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700;
            cursor: pointer; transition: all .2s; margin-top: 8px; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .login-error {{ background: #450a0a; border: 1px solid #991b1b; color: #fca5a5; border-radius: 8px;
                    padding: 10px 14px; font-size: 13px; margin-bottom: 16px; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; color: #64748b; }}
    .login-footer a {{ color: #7dd3fc; text-decoration: none; }}
    .status-line {{ font-size: 12px; color: #94a3b8; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  <div class="login-card">
    <div class="login-logo">
      <h1>🛡️ MORI SOC</h1>
      <p>Security Operations Center</p>
    </div>
    {error_html}
    <div class="field"><label>아이디</label><input id="username" type="text" autocomplete="username" placeholder="admin" /></div>
    <div class="field"><label>비밀번호</label><input id="password" type="password" autocomplete="current-password" placeholder="••••••" /></div>
    <button class="btn btn-primary" id="login_btn">로그인</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer">
      계정이 없으신가요? <a href="/signup-request">가입 요청 →</a>
    </div>
  </div>
  <script>
    const nextUrl = {json.dumps(next_url)};
    async function doLogin() {{
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;
      const statusEl = document.getElementById('status');
      if (!username || !password) {{ statusEl.textContent = '아이디와 비밀번호를 입력하세요.'; return; }}
      statusEl.textContent = '로그인 중…';
      try {{
        const res = await fetch('/auth/login', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{username, password}})
        }});
        if (res.ok) {{
          window.location.href = nextUrl || '/ui';
        }} else {{
          const d = await res.json().catch(() => ({{}}));
          statusEl.textContent = d.detail || '아이디 또는 비밀번호가 올바르지 않습니다.';
        }}
      }} catch(e) {{ statusEl.textContent = '네트워크 오류: ' + e.message; }}
    }}
    document.getElementById('login_btn').addEventListener('click', doLogin);
    document.addEventListener('keydown', e => {{ if (e.key === 'Enter') doLogin(); }});
  </script>
</body>
</html>"""


def render_signup_request_html(success: bool = False) -> str:
    """가입 요청 페이지 HTML 반환."""
    body_html = """
    <p style="color:#94a3b8;font-size:14px;margin-bottom:20px;">계정 사용을 원하시면 아래 정보를 입력하고 운영자에게 가입을 요청하세요.</p>
    <div class="field"><label>이름 *</label><input id="req_name" placeholder="홍길동" /></div>
    <div class="field"><label>이메일 *</label><input id="req_email" type="email" placeholder="hong@company.com" /></div>
    <div class="field"><label>부서</label><input id="req_dept" placeholder="보안팀" /></div>
    <div class="field"><label>요청 사유</label><textarea id="req_reason" style="width:100%;background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;color:#e2e8f0;padding:10px 14px;font-size:14px;min-height:80px;outline:none;" placeholder="업무 목적 및 필요 권한을 간략히 작성해주세요."></textarea></div>
    <button class="btn btn-primary" id="submit_btn">가입 요청 제출</button>
    <div class="status-line" id="status"></div>
    <div class="login-footer"><a href="/login">← 로그인으로 돌아가기</a></div>
    <script>
      document.getElementById('submit_btn').addEventListener('click', async () => {{
        const name = document.getElementById('req_name').value.trim();
        const email = document.getElementById('req_email').value.trim();
        const department = document.getElementById('req_dept').value.trim();
        const reason = document.getElementById('req_reason').value.trim();
        const statusEl = document.getElementById('status');
        if (!name || !email) {{ statusEl.textContent = '이름과 이메일은 필수입니다.'; return; }}
        statusEl.textContent = '제출 중…';
        try {{
          const res = await fetch('/auth/signup-request', {{
            method: 'POST', headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify({{name, email, department, reason}})
          }});
          if (res.ok) {{
            document.querySelector('.login-card').innerHTML = '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">✅</div><h2 style="color:#22c55e;margin:16px 0 8px">가입 요청 완료</h2><p style="color:#94a3b8">운영자 승인 후 계정이 생성됩니다.<br>이메일로 안내드리겠습니다.</p><div style="margin-top:24px"><a href="/login" style="color:#7dd3fc">← 로그인으로 돌아가기</a></div></div>';
          }} else {{
            const d = await res.json().catch(() => ({{}}));
            statusEl.textContent = d.detail || '오류가 발생했습니다.';
          }}
        }} catch(e) {{ statusEl.textContent = '네트워크 오류: ' + e.message; }}
      }});
    </script>""" if not success else '<div style="text-align:center;padding:40px 0"><div style="font-size:48px">✅</div><h2 style="color:#22c55e">가입 요청 완료</h2><p style="color:#94a3b8;margin-top:8px">운영자 승인 후 계정이 생성됩니다.</p><div style="margin-top:24px"><a href="/login" style="color:#7dd3fc">← 로그인으로 돌아가기</a></div></div>'
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MORI SOC — 가입 요청</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a1628; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
    .login-card {{ background: #0f2035; border: 1px solid #1e3a5f; border-radius: 16px; padding: 40px 36px;
                   width: 100%; max-width: 440px; box-shadow: 0 20px 60px rgba(0,0,0,.5); }}
    .login-logo {{ text-align: center; margin-bottom: 24px; }}
    .login-logo h1 {{ font-size: 24px; font-weight: 800; color: #7dd3fc; }}
    label {{ display: block; font-size: 12px; color: #94a3b8; margin-bottom: 5px; font-weight: 600; letter-spacing: .5px; }}
    input {{ width: 100%; background: #0a1628; border: 1px solid #1e3a5f; border-radius: 8px;
             color: #e2e8f0; padding: 10px 14px; font-size: 14px; outline: none; transition: border-color .2s; }}
    input:focus {{ border-color: #3b82f6; }}
    .field {{ margin-bottom: 14px; }}
    .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; font-size: 15px; font-weight: 700;
            cursor: pointer; transition: all .2s; margin-top: 4px; }}
    .btn-primary {{ background: #2563eb; color: #fff; }}
    .btn-primary:hover {{ background: #1d4ed8; }}
    .login-footer {{ text-align: center; margin-top: 20px; font-size: 13px; }}
    .login-footer a {{ color: #7dd3fc; text-decoration: none; }}
    .status-line {{ font-size: 12px; color: #ef4444; min-height: 18px; margin-top: 6px; text-align: center; }}
  </style>
</head>
<body>
  <div class="login-card">
    <div class="login-logo"><h1>🛡️ MORI SOC 가입 요청</h1></div>
    {body_html}
  </div>
</body>
</html>"""


def create_app(service: QueryService | None = None, service_factory=None) -> Any:
    if FastAPI is None or HTTPException is None:
        raise RuntimeError(
            "FastAPI is not installed. Install fastapi and uvicorn to run MVC 1 HTTP server."
        )

    app = FastAPI(title="MORI SOC Query API", version="0.1.0")
    dashboard_preferences = _default_dashboard_preferences()

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
        "moniter": {"password": "1234", "role": "monitor"},
    }

    # Sessions: token -> {username, role, created_at}
    sessions: dict[str, dict[str, Any]] = {}
    # Signup requests: [{id, name, email, department, reason, status, created_at}]
    signup_requests: list[dict[str, Any]] = []

    # Role permissions: role -> list of allowed tab ids
    _DEFAULT_ROLE_PERMISSIONS: dict[str, list[str]] = {
        "admin": ["dashboard", "triage", "incidents", "assets", "guides"],
        "security": ["dashboard", "triage", "incidents", "assets", "guides"],
        "monitor": ["dashboard", "assets", "guides"],
        "user": ["dashboard", "assets", "guides"],
    }
    role_permissions: dict[str, list[str]] = {k: list(v) for k, v in _DEFAULT_ROLE_PERMISSIONS.items()}

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
            "/auth/login", "/auth/logout", "/auth/signup-request",
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
            raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
        token = str(uuid.uuid4())
        _role = local_users.get(username, {}).get("role", "user")
        sessions[token] = {
            "username": username,
            "role": _role,
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        from fastapi.responses import JSONResponse
        resp = JSONResponse({"ok": True, "username": username})
        resp.set_cookie("mori_session", token, httponly=True, samesite="lax", max_age=86400 * 7)
        return resp

    @app.get("/auth/logout", include_in_schema=False)
    def auth_logout(request: Any = None) -> Any:
        """로그아웃: 세션 쿠키 삭제 후 /login 리디렉션."""
        from fastapi import Request as _FRequest
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

    @app.get("/auth/me", tags=["Auth"])
    def auth_me(request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자 정보 조회."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        role = sess.get("role", "user")
        return {
            "username": sess["username"],
            "role": role,
            "allowed_tabs": role_permissions.get(role, _DEFAULT_ROLE_PERMISSIONS.get(role, ["dashboard", "assets", "guides"])),
        }

    @app.get("/admin/role-permissions", tags=["Admin"])
    def get_role_permissions_api() -> dict[str, Any]:
        """역할별 탭 권한 조회."""
        return {"permissions": role_permissions}

    @app.post("/admin/role-permissions", tags=["Admin"])
    def update_role_permissions_api(payload: dict[str, Any]) -> dict[str, Any]:
        """역할별 탭 권한 업데이트. {role: [tab_id, ...]}"""
        nonlocal role_permissions
        valid_tabs = {"dashboard", "triage", "incidents", "assets", "guides"}
        for role_key, tabs in payload.items():
            if not isinstance(tabs, list):
                raise HTTPException(status_code=400, detail=f"tabs for {role_key} must be a list")
            role_permissions[role_key] = [t for t in tabs if t in valid_tabs]
        return {"permissions": role_permissions}

    @app.get("/", include_in_schema=False)
    def index() -> Any:
        return RedirectResponse(url="/ui", status_code=307)

    @app.get("/ui", include_in_schema=False, response_class=HTMLResponse)
    def ui() -> str:
        return render_user_dashboard_html(
            docs_url=dashboard_preferences["docs_url"],
            fleet_ui_url=FLEET_UI_URL,
            zabbix_ui_url=ZABBIX_UI_URL,
        )

    @app.get("/admin", include_in_schema=False, response_class=HTMLResponse)
    def admin() -> str:
        return render_query_console_html(dashboard_preferences["docs_url"])

    @app.get("/health")
    def health() -> dict[str, Any]:
        try:
            query_service = get_query_service()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"query service unavailable: {exc}") from exc
        return {
            "status": "ok",
            "engine": type(query_service.store).__name__,
            "query_count": len(PHASE1_QUERY_CATALOG),
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
            return build_dashboard_payload(get_query_service())
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"dashboard summary unavailable: {exc}") from exc

    @app.get("/dashboard/preferences")
    def dashboard_preferences_get() -> dict[str, Any]:
        return _dashboard_preferences_response(dashboard_preferences)

    @app.post("/dashboard/preferences")
    def dashboard_preferences_update(payload: dict[str, Any]) -> dict[str, Any]:
        nonlocal dashboard_preferences
        try:
            dashboard_preferences = _merge_dashboard_preferences(dashboard_preferences, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _dashboard_preferences_response(dashboard_preferences)

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
    def alert_triage_update(alert_id: str, payload: dict[str, Any]) -> dict[str, Any]:
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
        # history: 상태 변경 이력
        history = entry.setdefault("history", [])
        history.append({
            "from_status": prev_status,
            "to_status": status,
            "analyst": entry["analyst"],
            "note": entry["note"],
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
    def incidents_list(date_from: str = "", date_to: str = "", format: str = "json") -> Any:
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
        if format == "csv":
            buf = io.StringIO()
            fieldnames = ["incident_id", "title", "status", "created_at", "updated_at", "status_updated_at", "alert_count", "note_count"]
            writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for inc in all_items:
                writer.writerow({
                    "incident_id": inc.get("incident_id", ""),
                    "title": inc.get("title", ""),
                    "status": inc.get("status", ""),
                    "created_at": inc.get("created_at", ""),
                    "updated_at": inc.get("updated_at", ""),
                    "status_updated_at": inc.get("status_updated_at", ""),
                    "alert_count": len(inc.get("alert_ids", [])),
                    "note_count": len(inc.get("notes", [])),
                })
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-incidents-{timestamp}.csv"'},
            )
        return {"incidents": all_items}

    @app.post("/incidents", tags=["Incidents"])
    def incidents_create(payload: dict[str, Any]) -> dict[str, Any]:
        title = str(payload.get("title", "")).strip()
        if not title:
            raise HTTPException(status_code=400, detail="title is required")
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        analyst = str(payload.get("analyst", "")).strip() or "unknown"
        incident: dict[str, Any] = {
            "incident_id": str(uuid.uuid4()),
            "title": title,
            "status": "open",
            "status_updated_at": now_str,
            "alert_ids": list(payload.get("alert_ids") or []),
            "notes": [],
            "history": [{"event": "created", "to_status": "open", "analyst": analyst, "changed_at": now_str}],
            "created_at": now_str,
            "updated_at": now_str,
        }
        incidents[incident["incident_id"]] = incident
        return incident

    @app.patch("/incidents/{incident_id}", tags=["Incidents"])
    def incidents_update(incident_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        incident = incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        valid_statuses = {"open", "investigating", "resolved", "closed"}
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        analyst = str(payload.get("analyst", "")).strip() or "unknown"
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
                    "analyst": analyst,
                    "changed_at": now_str,
                })
                incident["status_updated_at"] = now_str
            incident["status"] = new_status
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
    def owners_upsert(payload: dict[str, Any]) -> Any:
        hostname = str(payload.get("hostname", "")).strip()
        if not hostname:
            raise HTTPException(status_code=400, detail="hostname is required")
        owner_name = str(payload.get("owner", "")).strip()
        changed_by = str(payload.get("changed_by", "")).strip() or "unknown"
        now_str = _isoformat(datetime.now(tz=timezone.utc))
        old_entry = asset_owners.get(hostname, {})
        new_category = str(payload.get("category", old_entry.get("category", ""))).strip()
        entry = {
            "hostname": hostname,
            "owner": owner_name,
            "category": new_category,
            "email": str(payload.get("email", "")).strip(),
            "team": str(payload.get("team", "")).strip(),
            "updated_at": now_str,
        }
        # Audit log: record changes for owner and category fields
        for field in ("owner", "category"):
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
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans)
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

    # ── Fleet 전용 API ───────────────────────────────────────────────────────
    @app.get("/fleet/hosts", tags=["Fleet"])
    def fleet_hosts_get(format: str = "json") -> Any:
        """Fleet(PC 자산) 전용 호스트 목록 API."""
        try:
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"fleet hosts unavailable: {exc}") from exc
        fleet_data = payload.get("fleet", {})
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            hosts = fleet_data.get("hosts", [])
            if hosts:
                fieldnames = ["hostname", "asset_type", "platform", "primary_ip", "status", "risk_score", "last_seen_at", "owner", "team"]
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
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
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"zabbix hosts unavailable: {exc}") from exc
        zabbix_data = payload.get("zabbix", {})
        if format == "csv":
            import io, csv as csv_mod
            buf = io.StringIO()
            hosts = zabbix_data.get("hosts", [])
            if hosts:
                fieldnames = ["hostname", "category", "importance", "primary_ip", "status", "latest_metric", "latest_value", "owner", "team"]
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
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
            payload = build_assets_payload(get_query_service(), owners=asset_owners, plans=action_plans)
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
                fieldnames = ["hostname", "critical", "high", "medium", "low", "info", "total", "latest_cve", "action_plan", "action_target_date"]
                writer = csv_mod.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            return StreamingResponse(
                iter([buf.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="mori-trivy-vulns-{timestamp}.csv"'},
            )
        return {"source": "trivy", "severity_filter": severity, "count": len(rows), "by_host": rows}

    return app


def create_app_from_env() -> Any:
    return create_app(service_factory=create_query_service_from_env)


def _query_csv_filename(intent: str) -> str:
    safe_intent = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in intent).strip("-")
    if not safe_intent:
        safe_intent = "query"
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"mori-query-{safe_intent}-{timestamp}.csv"


def render_user_dashboard_html(
    docs_url: str = DOCS_PORTAL_URL,
    fleet_ui_url: str = FLEET_UI_URL,
    zabbix_ui_url: str = ZABBIX_UI_URL,
) -> str:
    default_preferences_json = json.dumps(DEFAULT_USER_DASHBOARD_PREFERENCES, ensure_ascii=False)
    card_labels_json = json.dumps(USER_DASHBOARD_CARD_LABELS, ensure_ascii=False)
    section_labels_json = json.dumps(USER_DASHBOARD_SECTION_LABELS, ensure_ascii=False)
    guide_labels_json = json.dumps(USER_DASHBOARD_GUIDE_LABELS, ensure_ascii=False)
    nlq_guide_examples_json = json.dumps(list(QUERY_GUIDE_EXAMPLES), ensure_ascii=False)
    html = """<!doctype html>
<html lang=\"ko\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>MORI Security Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b1220; color: #e5e7eb; }
    .wrap { max-width: 1280px; margin: 0 auto; padding: 28px 20px 48px; }
    .hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 18px; }
    .hero h1 { margin: 0 0 8px; font-size: 32px; }
    .hero p { margin: 0; color: #94a3b8; max-width: 860px; line-height: 1.5; }
    .links { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    .links a, .top-actions button { display: inline-flex; align-items: center; justify-content: center; color: #cfe3ff; text-decoration: none; border: 1px solid #334155; padding: 8px 12px; border-radius: 999px; background: #0f172a; }
    .top-actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .metrics { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 16px; }
    .layout { display: grid; gap: 16px; }
    .stack { display: grid; gap: 16px; }
    .card { background: linear-gradient(180deg, #101827 0%, #0f172a 100%); border: 1px solid #233046; border-radius: 16px; padding: 18px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.18); }
    .metric-card { cursor: pointer; transition: transform 0.15s ease, border-color 0.15s ease; }
    .metric-card:hover { transform: translateY(-1px); border-color: #38bdf8; }
    .metric-card:focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px; }
    .metric-label { color: #94a3b8; font-size: 13px; margin-bottom: 8px; }
    .metric-value { font-size: 28px; font-weight: 800; }
    .metric-sub { margin-top: 6px; color: #7dd3fc; font-size: 13px; }
    .card h2 { margin: 0 0 12px; font-size: 18px; }
    .subtext { color: #94a3b8; font-size: 13px; margin-bottom: 12px; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #1f2937; vertical-align: top; }
    th { color: #94a3b8; font-weight: 600; }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .badge.online { background: rgba(34, 197, 94, 0.12); color: #86efac; }
    .badge.offline { background: rgba(248, 113, 113, 0.12); color: #fca5a5; }
    .badge.unknown { background: rgba(250, 204, 21, 0.12); color: #fde68a; }
    .coverage { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .coverage-item { background: #0b1220; border: 1px solid #223148; border-radius: 14px; padding: 14px; }
    .coverage-item strong { display: block; font-size: 22px; margin-top: 8px; }
    .list { display: grid; gap: 10px; }
    .list-item { border: 1px solid #1f2937; border-radius: 12px; padding: 12px; background: #0b1220; }
    .list-item .top { display: flex; gap: 12px; justify-content: space-between; margin-bottom: 6px; }
    .list-item .meta { color: #94a3b8; font-size: 12px; }
    .status-line, .empty { color: #94a3b8; font-size: 14px; }
    .hidden { display: none !important; }
    dialog { border: 1px solid #334155; border-radius: 18px; padding: 0; background: #0f172a; color: #e5e7eb; width: min(760px, calc(100vw - 32px)); }
    dialog::backdrop { background: rgba(2, 6, 23, 0.74); }
    .guide-dialog { padding: 20px; }
    .guide-dialog-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .guide-dialog-head h3 { margin: 0; font-size: 20px; }
    .guide-dialog-copy { color: #94a3b8; font-size: 14px; line-height: 1.5; }
    .dialog-body { padding: 0 20px 20px; max-height: 60vh; overflow: auto; }
    .row { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
    .row label { font-size: 13px; color: #94a3b8; }
    .row input, .row select, .row textarea { background: #0b1220; color: #e5e7eb; border: 1px solid #334155; border-radius: 8px; padding: 8px 10px; font-size: 14px; width: 100%; box-sizing: border-box; }
    .actions { display: flex; gap: 10px; margin-top: 12px; }
    button { cursor: pointer; padding: 8px 16px; border-radius: 999px; border: 1px solid #334155; background: #1d4ed8; color: #fff; font-size: 14px; font-weight: 600; }
    button.secondary { background: #0f172a; color: #cfe3ff; }
    button.ghost { background: transparent; color: #94a3b8; }
    .tabs-nav { display: flex; gap: 0; border-bottom: 1px solid #233046; margin-bottom: 20px; overflow-x: auto; }
    .tabs-nav button { background: none; border: none; border-bottom: 2px solid transparent; padding: 10px 22px; color: #94a3b8; font-size: 15px; font-weight: 600; cursor: pointer; margin-bottom: -1px; border-radius: 0; white-space: nowrap; }
    .tabs-nav button.active { color: #38bdf8; border-bottom-color: #38bdf8; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .result-badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }
    .result-badge.wazuh { background: rgba(167,139,250,.15); color: #c4b5fd; }
    .result-badge.zabbix { background: rgba(56,189,248,.15); color: #7dd3fc; }
    .result-badge.fleet { background: rgba(52,211,153,.15); color: #6ee7b7; }
    .result-badge.trivy { background: rgba(251,146,60,.15); color: #fdba74; }
    .result-badge.hosts { background: rgba(148,163,184,.15); color: #cbd5e1; }
    /* ── NLQ FAB ── */
    .nlq-fab { position: fixed; bottom: 88px; right: 20px; z-index: 999; background: linear-gradient(135deg,#1d4ed8,#0ea5e9); color: #fff; border: none; border-radius: 999px; padding: 14px 20px; font-size: 14px; font-weight: 700; box-shadow: 0 6px 24px rgba(14,165,233,.45); cursor: pointer; display: flex; align-items: center; gap: 8px; transition: transform 0.15s, box-shadow 0.15s; }
    .nlq-fab:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(14,165,233,.55); }
    @media (min-width: 769px) { .nlq-fab { bottom: 32px; } }
    .nlq-dialog { width: min(640px, calc(100vw - 24px)); }
    .nlq-dialog-body { padding: 20px; }
    /* ── Bottom Nav (mobile only) ── */
    .bottom-nav { display: none; }
    @media (max-width: 960px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 768px) {
      html, body { overflow-x: hidden; }
      .wrap { padding: 16px 12px 80px; max-width: 100%; box-sizing: border-box; }
      .hero { flex-direction: column; gap: 10px; margin-bottom: 12px; }
      .hero h1 { font-size: 22px; }
      .hero p { font-size: 13px; }
      .links, .top-actions { flex-wrap: wrap; gap: 8px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .card { padding: 14px 12px; border-radius: 12px; box-sizing: border-box; }
      .card h2 { font-size: 15px; }
      .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      table { min-width: 480px; }
      /* 상단 탭 숨기고 하단 탭 표시 */
      .tabs-nav { display: none; }
      .bottom-nav {
        display: flex;
        position: fixed;
        bottom: 0; left: 0; right: 0;
        z-index: 1000;
        background: #0f172a;
        border-top: 1px solid #233046;
        padding: 0;
        box-shadow: 0 -4px 20px rgba(0,0,0,.4);
      }
      .bottom-nav button {
        flex: 1;
        background: none;
        border: none;
        border-top: 2px solid transparent;
        padding: 8px 4px 10px;
        color: #64748b;
        font-size: 10px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        border-radius: 0;
        transition: color 0.15s;
      }
      .bottom-nav button .bn-icon { font-size: 20px; line-height: 1; }
      .bottom-nav button.active { color: #38bdf8; border-top-color: #38bdf8; }
    }
    @media (max-width: 480px) {
      .metrics { grid-template-columns: 1fr 1fr; }
      .coverage { grid-template-columns: 1fr 1fr; }
      .metric-value { font-size: 22px; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <div>
        <h1>MORI Security Dashboard</h1>
        <p>사용자에게 필요한 보안 현황과 조치 우선순위를 빠르게 보여주는 대시보드입니다. 상세한 수집 데이터는 운영자 화면에서 더 깊게 확인하고, 어떤 정보를 사용자 화면에 노출할지 운영자가 제어할 수 있습니다.</p>
        <div class=\"links\">
          <a href=\"__DOCS_PORTAL_URL__\" target=\"_blank\" rel=\"noreferrer\">운영 문서 / 포털</a>
          <a href=\"/docs\" target=\"_blank\" rel=\"noreferrer\">📋 API 문서 (Swagger)</a>
        </div>
      </div>
      <div class=\"top-actions\">
        <button id=\"refresh_dashboard\" type=\"button\">Refresh Dashboard</button>
        <a href=\"/auth/logout\" style=\"color:#ef4444;font-size:13px;\">로그아웃</a>
      </div>
    </section>

    <nav class=\"tabs-nav\">
      <button class=\"active\" data-tab=\"dashboard\" onclick=\"switchTab('dashboard')\">📊 대시보드</button>
      <button data-tab=\"triage\" onclick=\"switchTab('triage')\">🚨 Alert Triage</button>
      <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\">📋 인시던트</button>
      <button data-tab=\"assets\" onclick=\"switchTab('assets')\">📡 자산 현황</button>
      <button data-tab=\"guides\" onclick=\"switchTab('guides')\">📖 가이드 &amp; 기준</button>
    </nav>

    <!-- ── Tab: Dashboard ──────────────────────────────────────────────── -->
    <div class=\"tab-panel active\" id=\"tab_dashboard\">
      <section class=\"metrics\" id=\"overview_cards\"></section>
      <div class=\"layout\">
        <div class=\"stack\">
          <section class=\"card\" id=\"source_coverage_section\">
            <h2>Source Coverage</h2>
            <div class=\"subtext\">운영자가 노출을 허용한 경우에만 source 상태를 표시합니다.</div>
            <div class=\"coverage\" id=\"source_coverage\"></div>
          </section>

          <section class=\"card\" id=\"latest_status_section\">
            <h2>Latest Host Status</h2>
            <div class=\"subtext\">조치가 필요한 offline / unknown 호스트를 우선 확인합니다.</div>
            <div class=\"table-wrap\" id=\"latest_status\"></div>
          </section>

          <section class=\"card\" id=\"risk_summary_section\">
            <h2>Risk Summary</h2>
            <div class=\"subtext\">alert, 취약점, 상태를 기준으로 우선 대응 대상을 확인합니다.</div>
            <div class=\"table-wrap\" id=\"risk_summary\"></div>
          </section>

          <section class=\"card\" id=\"recent_activity_section\">
            <h2>Recent Activity</h2>
            <div class=\"subtext\">운영자가 허용한 범위에서 최근 이벤트와 관측값을 보여줍니다.</div>
            <div class=\"list\" id=\"recent_activity\"></div>
          </section>

          <!-- NLQ section moved to floating button -->
        </div>
      </div>
      <div class=\"status-line\" id=\"dashboard_status\">dashboard loading...</div>
    </div>

    <!-- ── Tab: Alert Triage ───────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_triage\">
      <section class=\"card\">
        <h2>🚨 Alert Triage</h2>
        <div class=\"subtext\">최근 24h 경보 목록입니다. 상태를 클릭해 Triage 처리하세요.</div>
        <div class=\"table-wrap\" id=\"triage_table\"><span class=\"empty\">로딩 중…</span></div>
        <div style=\"margin-top:10px\"><button id=\"reload_triage\" class=\"secondary\">새로고침</button></div>
      </section>
    </div>

    <!-- ── Tab: Incidents ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_incidents\">
      <section class=\"card\">
        <h2>📋 인시던트 관리</h2>
        <div class=\"subtext\">여러 경보를 하나의 인시던트로 묶고 조사 노트를 남깁니다.</div>
        <!-- 날짜 필터 + CSV 다운로드 -->
        <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px;padding:10px 12px;background:#0f172a;border-radius:8px;border:1px solid #1e293b\">
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#94a3b8;font-size:13px;white-space:nowrap\">시작일</label>
            <input type=\"date\" id=\"inc_date_from\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <div style=\"display:flex;align-items:center;gap:6px\">
            <label style=\"color:#94a3b8;font-size:13px;white-space:nowrap\">종료일</label>
            <input type=\"date\" id=\"inc_date_to\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:5px 8px;font-size:13px\" />
          </div>
          <button id=\"inc_filter_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px\">🔍 조회</button>
          <button id=\"inc_csv_btn\" class=\"secondary\" style=\"padding:5px 14px;font-size:13px;background:#1d3a5f;color:#93c5fd\">⬇️ CSV 다운로드</button>
        </div>
        <div id=\"incidents_list\" class=\"list\" style=\"margin-bottom:14px\"><span class=\"empty\">로딩 중…</span></div>
        <div class=\"row\">
          <label for=\"inc_title\">새 인시던트 제목</label>
          <input id=\"inc_title\" placeholder=\"예: 특정 서버 무단 접근 시도\" />
        </div>
        <div class=\"actions\">
          <button id=\"create_incident\">인시던트 생성</button>
          <button id=\"reload_incidents\" class=\"secondary\">새로고침</button>
        </div>
        <div class=\"status-line\" id=\"incident_status\"></div>
      </section>
    </div>

    <!-- ── Tab: 자산 현황 ─────────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_assets\">
      <!-- Sub-nav -->
      <div style=\"display:flex;gap:0;border-bottom:1px solid #233046;margin-bottom:16px;\">
        <button class=\"active\" id=\"asset_tab_fleet\" onclick=\"switchAssetTab('fleet')\" style=\"background:none;border:none;border-bottom:2px solid #38bdf8;padding:8px 20px;color:#38bdf8;font-size:14px;font-weight:600;cursor:pointer;border-radius:0;margin-bottom:-1px;\">🖥️ PC 자산 (Fleet)</button>
        <button id=\"asset_tab_zabbix\" onclick=\"switchAssetTab('zabbix')\" style=\"background:none;border:none;border-bottom:2px solid transparent;padding:8px 20px;color:#94a3b8;font-size:14px;font-weight:600;cursor:pointer;border-radius:0;margin-bottom:-1px;\">🖧 서버 자산 (Zabbix)</button>
        <button id=\"asset_tab_trivy\" onclick=\"switchAssetTab('trivy')\" style=\"background:none;border:none;border-bottom:2px solid transparent;padding:8px 20px;color:#94a3b8;font-size:14px;font-weight:600;cursor:pointer;border-radius:0;margin-bottom:-1px;\">🔍 취약점 (Trivy)</button>
      </div>

      <!-- Fleet PC Section -->
      <div id=\"assets_fleet_section\">
        <div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;\">
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">전체 PC</div><div class=\"metric-value\" id=\"fleet_total\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">온라인</div><div class=\"metric-value\" style=\"color:#86efac\" id=\"fleet_online\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">오프라인</div><div class=\"metric-value\" style=\"color:#fca5a5\" id=\"fleet_offline\">-</div></section>
        </div>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;\">
            <h2 style=\"margin:0\">🖥️ PC 자산 목록 (Fleet)</h2>
            <button onclick=\"downloadAssetsCSV('fleet')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\">📥 CSV 내보내기</button>
          </div>
          <div class=\"subtext\">Fleet에서 관리되는 PC 엔드포인트 현황입니다.</div>
          <div class=\"table-wrap\" id=\"fleet_table\"><span class=\"empty\">로딩 중…</span></div>
        </section>
      </div>

      <!-- Zabbix Server Section -->
      <div id=\"assets_zabbix_section\" class=\"hidden\">
        <div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;\">
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">전체 서버</div><div class=\"metric-value\" id=\"zabbix_total\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">온라인</div><div class=\"metric-value\" style=\"color:#86efac\" id=\"zabbix_online\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">오프라인</div><div class=\"metric-value\" style=\"color:#fca5a5\" id=\"zabbix_offline\">-</div></section>
        </div>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;\">
            <h2 style=\"margin:0\">🖧 서버 자산 목록 (Zabbix)</h2>
            <button onclick=\"downloadAssetsCSV('zabbix')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\">📥 CSV 내보내기</button>
          </div>
          <div class=\"subtext\">Zabbix에서 모니터링 중인 서버 현황과 최근 메트릭입니다.</div>
          <div class=\"table-wrap\" id=\"zabbix_table\"><span class=\"empty\">로딩 중…</span></div>
        </section>
      </div>

      <!-- Trivy Vulnerability Section -->
      <div id=\"assets_trivy_section\" class=\"hidden\">
        <div style=\"display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;\">
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">영향받는 호스트</div><div class=\"metric-value\" id=\"trivy_affected_hosts\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">전체 취약점</div><div class=\"metric-value\" id=\"trivy_total_vulns\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">Critical</div><div class=\"metric-value\" style=\"color:#fca5a5\" id=\"trivy_critical\">-</div></section>
          <section class=\"card\" style=\"padding:14px;\"><div class=\"metric-label\">High</div><div class=\"metric-value\" style=\"color:#fdba74\" id=\"trivy_high\">-</div></section>
        </div>
        <section class=\"card\">
          <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;\">
            <h2 style=\"margin:0\">🔍 취약점 현황 (Trivy)</h2>
            <button onclick=\"downloadAssetsCSV('trivy')\" class=\"secondary\" style=\"width:auto;padding:6px 14px;font-size:13px;\">📥 CSV 내보내기</button>
          </div>
          <div class=\"subtext\">Trivy가 탐지한 취약점을 호스트별로 집계한 현황입니다. Critical/High 우선 정렬.</div>
          <div class=\"table-wrap\" id=\"trivy_table\"><span class=\"empty\">로딩 중…</span></div>
        </section>
      </div>
      <div class=\"status-line\" id=\"assets_status\"></div>
    </div>

    <!-- ── Tab: 가이드 & 기준 ────────────────────────────────────────── -->
    <div class=\"tab-panel\" id=\"tab_guides\">
      <div id=\"guide_sub_tabs\" style=\"display:flex;gap:0;border-bottom:1px solid #233046;margin-bottom:20px;flex-wrap:wrap;\"></div>
      <section class=\"card\" style=\"padding:0\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;padding:16px 20px 0;\">
          <h2 id=\"guide_content_title\" style=\"margin:0;font-size:16px\"></h2>
          <span id=\"guide_updated_at\" style=\"font-size:12px;color:#64748b\"></span>
        </div>
        <div id=\"guide_content_body\" style=\"padding:16px 20px 20px;color:#cbd5e1;line-height:1.8;white-space:pre-wrap;font-size:14px;font-family:inherit\"></div>
      </section>
    </div>
  </div>

  <dialog id=\"overview_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"overview_modal_title\">Overview Details</h3>
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"overview_modal_copy\">선택한 카드의 상세 목록입니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"overview_modal_body\"></div>
  </dialog>

  <dialog id=\"info_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"info_modal_title\">알림</h3>
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\">확인</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"info_modal_body\" style=\"padding:0 0 8px;\"></div>
    </div>
  </dialog>

  <dialog id=\"nlq_guide_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3>질의 가이드</h3>
        <form method=\"dialog\"><button type=\"submit\" class=\"secondary\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\">아래 예시를 클릭하면 입력창에 바로 채워집니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"nlq_guide_list\" style=\"display:flex;flex-wrap:wrap;gap:8px;padding:16px;\"></div>
  </dialog>

  <dialog id=\"triage_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3>Alert Triage</h3>
        <form method=\"dialog\"><button class=\"secondary\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\">
        <div id=\"triage_modal_alert_info\" style=\"margin-bottom:12px\"></div>
        <div class=\"row\"><label>상태</label>
          <select id=\"triage_modal_status\">
            <option value=\"pending\">🔴 미확인 (Pending)</option>
            <option value=\"reviewing\">🟡 검토중 (Reviewing)</option>
            <option value=\"resolved\">🟢 조치예정/완료 (Resolved)</option>
          </select>
        </div>
        <div class=\"row\"><label>담당자</label><input id=\"triage_modal_analyst\" placeholder=\"예: alice\" /></div>
        <div class=\"row\"><label>메모</label><textarea id=\"triage_modal_note\" style=\"min-height:80px\"></textarea></div>
        <div class=\"actions\">
          <button id=\"triage_modal_save\">저장</button>
          <form method=\"dialog\"><button class=\"secondary\">취소</button></form>
        </div>
        <div class=\"status-line\" id=\"triage_modal_status_line\"></div>
      </div>
    </div>
  </dialog>

  <dialog id=\"incident_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"incident_modal_title\">인시던트 상세</h3>
        <form method=\"dialog\"><button class=\"secondary\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\">
        <div id=\"incident_modal_info\" style=\"margin-bottom:12px;font-size:13px;color:#94a3b8\"></div>
        <div class=\"row\"><label>상태 변경</label>
          <select id=\"incident_modal_status\">
            <option value=\"open\">open</option>
            <option value=\"investigating\">investigating</option>
            <option value=\"resolved\">resolved</option>
            <option value=\"closed\">closed</option>
          </select>
        </div>
        <div class=\"row\"><label>담당자</label><input id=\"incident_modal_status_analyst\" placeholder=\"예: alice\" /></div>
        <button id=\"incident_modal_update_status\" style=\"margin-bottom:12px\">상태 저장</button>
        <hr style=\"border-color:#334155;margin:12px 0\" />
        <div style=\"margin-bottom:8px;font-size:13px;font-weight:600;color:#7dd3fc\">📋 상태 변경 히스토리</div>
        <div id=\"incident_modal_history\" style=\"margin-bottom:12px\"></div>
        <hr style=\"border-color:#334155;margin:12px 0\" />
        <div style=\"margin-bottom:8px;font-size:13px;font-weight:600;color:#a3e635\">📝 조사 노트</div>
        <div id=\"incident_modal_notes\" style=\"margin-bottom:12px\"></div>
        <div class=\"row\"><label>노트 내용</label><textarea id=\"incident_modal_note_text\" style=\"min-height:72px\"></textarea></div>
        <div class=\"row\"><label>작성자</label><input id=\"incident_modal_analyst\" placeholder=\"예: alice\" /></div>
        <button id=\"incident_modal_add_note\">노트 추가</button>
        <div class=\"status-line\" id=\"incident_modal_status_line\"></div>
      </div>
    </div>
  </dialog>

  <!-- 조치 계획 모달 -->
  <div id=\"plan_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:28px 32px;width:500px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"plan_modal_title\" style=\"color:#a3e635;margin:0\">조치 계획</h3>
        <button onclick=\"closePlanModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#94a3b8;font-size:13px\">조치 계획 내용</label>
          <textarea id=\"plan_text\" rows=\"4\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:8px;font-size:13px;resize:vertical;box-sizing:border-box\" placeholder=\"예: 2024년 2분기 내 패키지 업그레이드 예정\"></textarea>
        </div>
        <div style=\"display:flex;gap:12px\">
          <div style=\"flex:1\"><label style=\"color:#94a3b8;font-size:13px\">목표 완료일</label>
            <input type=\"date\" id=\"plan_target_date\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
          </div>
          <div style=\"flex:1\"><label style=\"color:#94a3b8;font-size:13px\">작성자</label>
            <input id=\"plan_updated_by\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 김보안\" />
          </div>
        </div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"plan_modal_save\" style=\"background:#16a34a;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\">저장</button>
          <button onclick=\"closePlanModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- 담당자 편집 모달 (사용자용) -->
  <div id=\"owner_modal\" style=\"display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center;\">
    <div style=\"background:#0f172a;border:1px solid #334155;border-radius:10px;padding:28px 32px;width:440px;max-width:95vw\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:16px\">
        <h3 id=\"owner_modal_title\" style=\"color:#a3e635;margin:0\">담당자/카테고리 수정</h3>
        <button onclick=\"closeOwnerModal()\" style=\"background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer\">✕</button>
      </div>
      <div style=\"display:flex;flex-direction:column;gap:12px\">
        <div><label style=\"color:#94a3b8;font-size:13px\">호스트명</label>
          <input id=\"owner_modal_hostname\" readonly style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#94a3b8;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\">담당자</label>
          <input id=\"owner_modal_owner\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 홍길동\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\">카테고리 (서버 분류)</label>
          <input id=\"owner_modal_category\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 웹 서버\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\">팀</label>
          <input id=\"owner_modal_team\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 인프라팀\" />
        </div>
        <div><label style=\"color:#94a3b8;font-size:13px\">수정자 이름 <span style=\"color:#ef4444\">*</span></label>
          <input id=\"owner_modal_changed_by\" style=\"width:100%;background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:7px;font-size:13px;box-sizing:border-box\" placeholder=\"예: 홍길동 (이력 기록용)\" />
        </div>
        <div id=\"owner_modal_status\" style=\"font-size:13px;color:#94a3b8;\"></div>
        <div style=\"display:flex;gap:10px;justify-content:flex-end;margin-top:4px\">
          <button id=\"owner_modal_save\" style=\"background:#1d4ed8;border:none;color:#fff;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\">저장</button>
          <button onclick=\"closeOwnerModal()\" style=\"background:#1e293b;border:1px solid #334155;color:#94a3b8;padding:8px 20px;border-radius:6px;cursor:pointer;font-size:14px\">취소</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ── 하단 탭 바 (모바일 전용) ────────────────────────────────────────── -->
  <nav class=\"bottom-nav\" id=\"bottom_nav\">
    <button class=\"active\" data-tab=\"dashboard\" onclick=\"switchTab('dashboard')\">
      <span class=\"bn-icon\">📊</span>대시보드
    </button>
    <button data-tab=\"triage\" onclick=\"switchTab('triage')\">
      <span class=\"bn-icon\">🚨</span>Triage
    </button>
    <button data-tab=\"assets\" onclick=\"switchTab('assets')\">
      <span class=\"bn-icon\">📡</span>자산
    </button>
    <button data-tab=\"incidents\" onclick=\"switchTab('incidents')\">
      <span class=\"bn-icon\">📋</span>인시던트
    </button>
    <button data-tab=\"guides\" onclick=\"switchTab('guides')\">
      <span class=\"bn-icon\">📖</span>가이드
    </button>
  </nav>

  <script>
    const defaultPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const cardLabels = __CARD_LABELS_JSON__;
    const sectionLabels = __SECTION_LABELS_JSON__;
    const guideLabels = __GUIDE_LABELS_JSON__;
    let assetColumnPrefs = Object.assign({}, defaultPreferences.asset_columns || { show_importance: true, show_isms_control: true, show_iso27001_control: true });
    const nlqGuideExamples = __NLQ_GUIDE_EXAMPLES__;
    const overviewCardsEl = document.getElementById('overview_cards');
    const sourceCoverageEl = document.getElementById('source_coverage');
    const latestStatusEl = document.getElementById('latest_status');
    const riskSummaryEl = document.getElementById('risk_summary');
    const recentActivityEl = document.getElementById('recent_activity');
    const dashboardStatusEl = document.getElementById('dashboard_status');
    const overviewModalEl = document.getElementById('overview_modal');
    const overviewModalTitleEl = document.getElementById('overview_modal_title');
    const overviewModalCopyEl = document.getElementById('overview_modal_copy');
    const overviewModalBodyEl = document.getElementById('overview_modal_body');
    const nlqGuideModalEl = document.getElementById('nlq_guide_modal');
    const nlqGuideListEl = document.getElementById('nlq_guide_list');
    // Triage
    const triageTableEl = document.getElementById('triage_table');
    const triageModalEl = document.getElementById('triage_modal');
    const triageModalAlertInfoEl = document.getElementById('triage_modal_alert_info');
    const triageModalStatusEl = document.getElementById('triage_modal_status');
    const triageModalAnalystEl = document.getElementById('triage_modal_analyst');
    const triageModalNoteEl = document.getElementById('triage_modal_note');
    const triageModalSaveEl = document.getElementById('triage_modal_save');
    const triageModalStatusLineEl = document.getElementById('triage_modal_status_line');
    // Incidents
    const incidentsListEl = document.getElementById('incidents_list');
    const incTitleEl = document.getElementById('inc_title');
    const incidentStatusEl = document.getElementById('incident_status');
    const incidentModalEl = document.getElementById('incident_modal');
    const incidentModalTitleEl = document.getElementById('incident_modal_title');
    const incidentModalInfoEl = document.getElementById('incident_modal_info');
    const incidentModalStatusEl = document.getElementById('incident_modal_status');
    const incidentModalNotesEl = document.getElementById('incident_modal_notes');
    const incidentModalNoteTextEl = document.getElementById('incident_modal_note_text');
    const incidentModalAnalystEl = document.getElementById('incident_modal_analyst');
    const incidentModalStatusLineEl = document.getElementById('incident_modal_status_line');

    let userPreferences = JSON.parse(JSON.stringify(defaultPreferences));
    let dashboardDetails = {};
    let currentTriageAlertId = null;
    let currentIncidentId = null;
    const TRIAGE_STATUS_COLORS = {
      pending: '#ef4444', reviewing: '#f59e0b', resolved: '#22c55e',
      // legacy (backward compat)
      new: '#ef4444', acknowledged: '#f59e0b', investigating: '#f59e0b',
      closed: '#22c55e', false_positive: '#94a3b8'
    };
    const TRIAGE_STATUS_LABELS = { pending:'🔴 미확인', reviewing:'🟡 검토중', resolved:'🟢 조치예정/완료' };
    const INC_STATUS_COLORS = {open:'#f59e0b', investigating:'#a78bfa', resolved:'#6ee7b7', closed:'#94a3b8'};

    // ── Tab Navigation ─────────────────────────────────────────────────────
    function switchTab(tabName) {
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      // 상단 탭 + 하단 탭 모두 active 동기화
      document.querySelectorAll('.tabs-nav button, .bottom-nav button').forEach(b => b.classList.remove('active'));
      const panel = document.getElementById(`tab_${tabName}`);
      if (panel) panel.classList.add('active');
      document.querySelectorAll(`[data-tab="${tabName}"]`).forEach(b => b.classList.add('active'));
      // 페이지 상단으로 스크롤 (모바일에서 탭 전환 시 편의)
      window.scrollTo({ top: 0, behavior: 'smooth' });
      if (tabName === 'triage') loadTriage();
      if (tabName === 'incidents') loadIncidents();
      if (tabName === 'assets') loadAssets();
      if (tabName === 'guides') {
        buildGuideSubTabs();
        if (currentGuideId) switchGuideTab(currentGuideId);
      }
    }

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function formatTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString('ko-KR', { hour12: false });
    }

    function setSectionVisible(key, visible) {
      const element = document.getElementById(`${key}_section`);
      if (!element) return;
      element.classList.toggle('hidden', !visible);
    }

    function applyUserPreferences() {
      const sections = userPreferences.sections || {};
      Object.keys(sectionLabels).forEach((key) => setSectionVisible(key, sections[key] !== false));
    }

    function openOverviewModal(title, description, bodyHtml) {
      overviewModalTitleEl.textContent = title;
      overviewModalCopyEl.textContent = description;
      overviewModalBodyEl.innerHTML = bodyHtml;
      if (overviewModalEl.open) return;
      if (typeof overviewModalEl.showModal === 'function') {
        overviewModalEl.showModal();
        return;
      }
      overviewModalEl.setAttribute('open', 'open');
    }

    function renderDetailTable(columns, items, emptyText) {
      if (!items.length) return `<div class=\"empty\">${escapeHtml(emptyText)}</div>`;
      return `
        <div class=\"table-wrap\">
          <table>
            <thead><tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr></thead>
            <tbody>
              ${items.map((item) => `<tr>${columns.map((column) => `<td>${column.render(item)}</td>`).join('')}</tr>`).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    function renderHostCell(item) {
      const name = item.source_url
        ? `<a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer"><strong>${escapeHtml(item.hostname)}</strong></a>`
        : `<strong>${escapeHtml(item.hostname)}</strong>`;
      return `${name}<br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span>`;
    }

    function renderStatusDetailTable(items) {
      return renderDetailTable([
        { label: 'Host', render: (item) => renderHostCell(item) },
        { label: 'Status', render: (item) => `<span class=\"badge ${escapeHtml(item.status)}\">${escapeHtml(item.status)}</span>` },
        { label: 'Risk', render: (item) => escapeHtml(item.risk_score) },
        { label: 'Last Seen', render: (item) => escapeHtml(formatTime(item.last_seen_at)) },
      ], items, '표시할 호스트가 없습니다.');
    }

    function renderAlertDetailTable(items) {
      return renderDetailTable([
        { label: 'Time', render: (item) => escapeHtml(formatTime(item.observed_at)) },
        { label: 'Host', render: (item) => `<strong>${escapeHtml(item.hostname || '-')}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id || '-')}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
      ], items, '최근 24시간 high / critical alert가 없습니다.');
    }

    function renderVulnerabilityDetailTable(items) {
      return renderDetailTable([
        { label: 'Detected', render: (item) => escapeHtml(formatTime(item.detected_at)) },
        { label: 'Host', render: (item) => `<strong>${escapeHtml(item.hostname || item.host_id)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span>` },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
      ], items, 'critical 취약점이 없습니다.');
    }

    function renderSourceDetailTable(items) {
      return renderDetailTable([
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Hosts', render: (item) => escapeHtml(item.host_count) },
        { label: 'Status', render: (item) => escapeHtml(item.status) },
        { label: 'Last Sync', render: (item) => escapeHtml(formatTime(item.last_sync_at)) },
      ], items, '표시할 source 상태가 없습니다.');
    }

    function renderIngestedDetailTable(items) {
      return renderDetailTable([
        { label: 'Entity', render: (item) => escapeHtml(item.entity_type) },
        { label: 'Count', render: (item) => escapeHtml(item.count) },
      ], items, '수집된 레코드가 없습니다.');
    }

    function showOverviewDetail(key) {
      const items = Array.isArray(dashboardDetails[key]) ? dashboardDetails[key] : [];
      const renderers = {
        total_hosts: [renderStatusDetailTable, '현재 알려진 전체 호스트 목록입니다.'],
        offline_hosts: [renderStatusDetailTable, '즉시 확인이 필요한 offline 호스트 목록입니다.'],
        alerts_24h: [renderAlertDetailTable, '최근 24시간 high / critical alert 목록입니다.'],
        critical_vulns: [renderVulnerabilityDetailTable, '현재 critical 취약점 목록입니다.'],
        sources_reporting: [renderSourceDetailTable, '호스트를 보고 중인 source 목록입니다.'],
        sources_healthy: [renderSourceDetailTable, '최근 sync가 success인 collector 목록입니다.'],
        ingested_records: [renderIngestedDetailTable, '저장된 엔터티 타입별 레코드 수입니다.'],
      };
      const [renderer, description] = renderers[key] || [renderIngestedDetailTable, '선택한 카드의 상세 데이터입니다.'];
      openOverviewModal(cardLabels[key] || key, description, renderer(items));
    }

    function renderOverview(overview) {
      const cards = [
        ['total_hosts', overview.total_hosts, `${overview.online_hosts} online / ${overview.unknown_hosts} unknown`],
        ['offline_hosts', overview.offline_hosts, '즉시 확인 대상'],
        ['alerts_24h', overview.alerts_24h, 'high + critical'],
        ['critical_vulns', overview.critical_vulns, `high ${overview.high_vulns}`],
        ['sources_reporting', overview.sources_reporting, 'fleet / wazuh / zabbix / trivy / host_log'],
        ['sources_healthy', overview.sources_healthy, '최근 sync success 기준'],
        ['ingested_records', overview.ingested_records, 'alerts + vulns + queries + observations'],
      ].filter(([key]) => (userPreferences.cards || {})[key] !== false);
      if (!cards.length) {
        overviewCardsEl.innerHTML = '<div class=\"empty\">운영자가 공개한 요약 카드가 없습니다.</div>';
        return;
      }
      overviewCardsEl.innerHTML = cards.map(([key, value, sub]) => `
        <section class=\"card metric-card\" role=\"button\" tabindex=\"0\" data-overview-key=\"${escapeHtml(key)}\">
          <div class=\"metric-label\">${escapeHtml(cardLabels[key] || key)}</div>
          <div class=\"metric-value\">${escapeHtml(value)}</div>
          <div class=\"metric-sub\">${escapeHtml(sub)}</div>
        </section>
      `).join('');
      overviewCardsEl.querySelectorAll('[data-overview-key]').forEach((card) => {
        const open = () => showOverviewDetail(card.dataset.overviewKey || '');
        card.addEventListener('click', open);
        card.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            open();
          }
        });
      });
    }

    function renderSourceCoverage(items) {
      if (!items.length) {
        sourceCoverageEl.innerHTML = '<div class=\"empty\">아직 연결된 source alias가 없습니다.</div>';
        return;
      }
      const statusToBadge = { success: 'online', error: 'offline', running: 'unknown', unknown: 'unknown' };
      sourceCoverageEl.innerHTML = items.map((item) => `
        <div class=\"coverage-item\">
          <div class=\"metric-label\">${escapeHtml(item.source.toUpperCase())}</div>
          <strong>${escapeHtml(item.host_count)}</strong>
          <div class=\"metric-sub\">호스트 · <span class=\"badge ${escapeHtml(statusToBadge[item.status] || 'unknown')}\">${escapeHtml(item.status)}</span></div>
          <div class=\"metric-sub\">last sync: ${escapeHtml(formatTime(item.last_sync_at))}</div>
        </div>
      `).join('');
    }

    function renderLatestStatus(items) {
      if (!items.length) {
        latestStatusEl.innerHTML = '<div class=\"empty\">아직 호스트 데이터가 없습니다.</div>';
        return;
      }
      latestStatusEl.innerHTML = `
        <table>
          <thead><tr><th>Host</th><th>Status</th><th>Risk</th><th>Last Seen</th></tr></thead>
          <tbody>${items.map((item) => `
            <tr>
              <td>${renderHostCell(item)}</td>
              <td><span class=\"badge ${escapeHtml(item.status)}\">${escapeHtml(item.status)}</span></td>
              <td>${escapeHtml(item.risk_score)}</td>
              <td>${escapeHtml(formatTime(item.last_seen_at))}</td>
            </tr>`).join('')}</tbody>
        </table>`;
    }

    function renderRiskSummary(items) {
      if (!items.length) {
        riskSummaryEl.innerHTML = '<div class=\"empty\">아직 위험 요약 데이터가 없습니다.</div>';
        return;
      }
      riskSummaryEl.innerHTML = `
        <table>
          <thead><tr><th>Host</th><th>Risk</th><th>Alerts 24h</th><th>Critical</th><th>High</th><th>Vulns</th></tr></thead>
          <tbody>${items.map((item) => `
            <tr>
              <td><strong>${escapeHtml(item.hostname)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span></td>
              <td>${escapeHtml(item.risk_score)}</td>
              <td>${escapeHtml(item.alert_count_24h)}</td>
              <td>${escapeHtml(item.critical_alert_count_24h)}</td>
              <td>${escapeHtml(item.high_alert_count_24h)}</td>
              <td>${escapeHtml(item.vuln_count)} (C:${escapeHtml(item.critical_vuln_count)} / H:${escapeHtml(item.high_vuln_count)})</td>
            </tr>`).join('')}</tbody>
        </table>`;
    }

    function renderRecentActivity(items) {
      if (!items.length) {
        recentActivityEl.innerHTML = '<div class=\"empty\">아직 최근 활동 데이터가 없습니다.</div>';
        return;
      }
      recentActivityEl.innerHTML = items.map((item) => {
        const grafanaLink = item.grafana_url
          ? `<a href=\"${escapeHtml(item.grafana_url)}\" target=\"_blank\" rel=\"noreferrer\" style=\"color:#38bdf8;font-size:12px;margin-left:8px;\">Grafana에서 보기 ↗</a>`
          : '';
        return `
        <div class=\"list-item\">
          <div class=\"top\"><strong>${escapeHtml(item.summary)}</strong><span class=\"meta\">${escapeHtml(formatTime(item.observed_at))}</span></div>
          <div class=\"meta\">${escapeHtml(item.entity_type)} · ${escapeHtml(item.source)} · ${escapeHtml(item.host_id || '-')}${grafanaLink}</div>
        </div>`;
      }).join('');
    }

    function showInfoModal(title, message) {
      const modal = document.getElementById('info_modal');
      document.getElementById('info_modal_title').textContent = title;
      document.getElementById('info_modal_body').textContent = message;
      if (!modal.open) modal.showModal();
    }

    // --- NLQ guide modal ---
    function openNlqGuideModal() {
      nlqGuideListEl.innerHTML = nlqGuideExamples.map((ex, idx) =>
        `<button type=\"button\" class=\"nlq-guide-chip\" data-idx=\"${idx}\" style=\"padding:8px 14px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;font-size:13px;\">${escapeHtml(ex)}</button>`
      ).join('');
      if (typeof nlqGuideModalEl.showModal === 'function') nlqGuideModalEl.showModal();
      else nlqGuideModalEl.setAttribute('open', 'open');
    }
    nlqGuideListEl.addEventListener('click', (e) => {
      const btn = e.target.closest('.nlq-guide-chip');
      if (!btn) return;
      const idx = Number(btn.dataset.idx);
      nlqTextarea.value = nlqGuideExamples[idx] || '';
      lastInterpretedPayload = null;
      nlqInterpretResult.textContent = '';
      if (nlqGuideModalEl.open) nlqGuideModalEl.close();
    });
    document.getElementById('nlq_guide_link').addEventListener('click', (e) => { e.preventDefault(); openNlqGuideModal(); });

    // --- NLQ section ---
    const nlqTextarea = document.getElementById('nlq_textarea');
    const nlqInterpretBtn = document.getElementById('nlq_interpret_btn');
    const nlqRunBtn = document.getElementById('nlq_run_btn');
    const nlqCsvBtn = document.getElementById('nlq_csv_btn');
    const nlqInterpretResult = document.getElementById('nlq_interpret_result');
    const nlqResultArea = document.getElementById('nlq_result_area');
    let lastInterpretedPayload = null;

    nlqInterpretBtn.addEventListener('click', async () => {
      const text = nlqTextarea.value.trim();
      if (!text) { showInfoModal('입력 필요', '질의할 내용을 입력해 주세요.'); return; }
      nlqInterpretResult.textContent = '해석 중...';
      try {
        const res = await fetch('/interpret', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
        const data = await res.json();
        if (!res.ok) { nlqInterpretResult.textContent = `오류: ${data.detail || res.status}`; return; }
        lastInterpretedPayload = { intent: data.intent, scope: data.scope || {time_range:'24h'}, filters: data.filters || {} };
        nlqInterpretResult.textContent = `해석 결과: ${data.intent} (${data.recognized ? '인식됨' : '유사 매칭'})${data.warnings?.length ? ' ⚠ ' + data.warnings.join(', ') : ''}`;
        if (!data.recognized) { openNlqGuideModal(); }
      } catch (err) { nlqInterpretResult.textContent = `오류: ${err.message}`; }
    });

    async function runNlqQuery(format) {
      const text = nlqTextarea.value.trim();
      if (!text) { showInfoModal('입력 필요', '질의할 내용을 입력해 주세요.'); return null; }
      let payload = lastInterpretedPayload;
      if (!payload) {
        // auto-interpret first
        try {
          const res = await fetch('/interpret', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
          const data = await res.json();
          if (!res.ok) { showInfoModal('해석 오류', data.detail || String(res.status)); return null; }
          payload = { intent: data.intent, scope: data.scope || {time_range:'24h'}, filters: data.filters || {} };
          lastInterpretedPayload = payload;
          nlqInterpretResult.textContent = `해석 결과: ${data.intent}`;
        } catch (err) { showInfoModal('해석 오류', err.message); return null; }
      }
      try {
        const url = format === 'csv' ? '/query?format=csv' : '/query';
        const res = await fetch(url, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        if (format === 'csv') {
          if (!res.ok) { const d = await res.json(); showInfoModal('오류', d.detail || String(res.status)); return null; }
          const blob = await res.blob();
          const cd = res.headers.get('content-disposition') || '';
          const match = cd.match(/filename=\"([^\"]+)\"/);
          const filename = match ? match[1] : 'mori-query.csv';
          const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
          return 'csv_downloaded';
        }
        const data = await res.json();
        if (!res.ok) { showInfoModal('질의 오류', data.detail || String(res.status)); return null; }
        return data;
      } catch (err) { showInfoModal('오류', err.message); return null; }
    }

    function renderNlqResult(result) {
      const evidence = result.evidence || [];
      const summary = result.summary || '';
      const count = result.meta?.count ?? evidence.length;
      if (!evidence.length) {
        nlqResultArea.textContent = '';
        showInfoModal('결과 없음', summary || '조건에 맞는 데이터가 없습니다.');
        nlqCsvBtn.style.display = 'none';
        return;
      }
      nlqCsvBtn.style.display = '';
      const srcBadge = (src) => {
        const s = (src || '').toLowerCase();
        const cls = s.includes('wazuh') ? 'wazuh' : s.includes('zabbix') ? 'zabbix' : s.includes('fleet') ? 'fleet' : s.includes('trivy') ? 'trivy' : s.includes('host') ? 'hosts' : '';
        return `<span style=\"display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;background:#1e3a5f;color:#93c5fd;\" class=\"${cls}\">${escapeHtml(src||'-')}</span>`;
      };
      const rows = evidence.map((ev, i) => `
        <tr style=\"border-bottom:1px solid #1a2d45;\">
          <td style=\"padding:7px 10px;color:#64748b\">${i+1}</td>
          <td style=\"padding:7px 10px\">${srcBadge(ev.source)}</td>
          <td style=\"padding:7px 10px;font-size:13px\">${escapeHtml(ev.summary || ev.raw_ref || '-')}</td>
          <td style=\"padding:7px 10px;font-size:11px;color:#64748b;font-family:monospace\">${escapeHtml(ev.record_id || '-')}</td>
        </tr>`).join('');
      nlqResultArea.innerHTML = `
        ${summary ? `<div style=\"color:#7dd3fc;font-size:13px;margin-bottom:10px;padding:8px 12px;background:#0f2035;border-radius:8px;border-left:3px solid #3b82f6\">${escapeHtml(summary)}</div>` : ''}
        <div style=\"overflow:auto\">
          <table style=\"width:100%;border-collapse:collapse;font-size:13px\">
            <thead><tr style=\"background:#0f2035\">
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">#</th>
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">Source</th>
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">Summary</th>
              <th style=\"padding:8px 10px;color:#93c5fd;font-weight:600;text-align:left\">Record ID</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style=\"color:#94a3b8;font-size:13px;margin-top:8px\">총 ${count}건 조회됨</div>`;
    }

    nlqRunBtn.addEventListener('click', async () => {
      nlqResultArea.textContent = '실행 중...';
      const result = await runNlqQuery('json');
      if (!result) { nlqResultArea.textContent = ''; return; }
      renderNlqResult(result);
    });

    nlqCsvBtn.addEventListener('click', async () => {
      await runNlqQuery('csv');
    });

    async function loadPreferences() {
      try {
        const response = await fetch('/dashboard/preferences');
        const data = await response.json();
        if (response.ok && data.user_dashboard) {
          userPreferences = data.user_dashboard;
          if (data.user_dashboard.asset_columns) {
            assetColumnPrefs = Object.assign({}, assetColumnPrefs, data.user_dashboard.asset_columns);
          }
        }
      } catch (error) {
        dashboardStatusEl.textContent = `preferences load failed: ${error.message}`;
      }
      applyUserPreferences();
    }

    async function loadDashboard() {
      dashboardStatusEl.textContent = 'dashboard loading...';
      try {
        const response = await fetch('/dashboard/summary');
        const data = await response.json();
        if (!response.ok) {
          dashboardStatusEl.textContent = `dashboard load failed: HTTP ${response.status}`;
          return;
        }
        dashboardDetails = data.overview_details || {};
        renderOverview(data.overview || {});
        renderSourceCoverage(data.source_coverage || []);
        renderLatestStatus(data.latest_status || []);
        renderRiskSummary(data.risk_summary || []);
        renderRecentActivity(data.recent_activity || []);
        applyUserPreferences();
        dashboardStatusEl.textContent = `dashboard updated at ${formatTime(data.generated_at)}`;
      } catch (error) {
        dashboardStatusEl.textContent = `dashboard load failed: ${error.message}`;
      }
    }

    document.getElementById('refresh_dashboard').addEventListener('click', loadDashboard);

    // ── Triage ──────────────────────────────────────────────────────────────
    async function loadTriage() {
      triageTableEl.innerHTML = '<span class=\"empty\">로딩 중…</span>';
      try {
        const res = await fetch('/alerts');
        if (!res.ok) { triageTableEl.innerHTML = '<span class=\"empty\">경보 로드 실패</span>'; return; }
        const data = await res.json();
        const alerts = data.alerts || [];
        if (!alerts.length) { triageTableEl.innerHTML = '<span class=\"empty\">최근 24h 경보 없음</span>'; return; }
        const rows = alerts.map(a => {
          const triage = a.triage || {};
          const rawStatus = triage.status || 'pending';
          const triageAnalyst = triage.analyst || '';
          const triageNote = triage.note || '';
          const color = TRIAGE_STATUS_COLORS[rawStatus] || '#6b7280';
          const label = TRIAGE_STATUS_LABELS[rawStatus] || rawStatus;
          return `<tr>
            <td>${escapeHtml(formatTime(a.observed_at))}</td>
            <td><span style=\"background:#1e293b;color:#93c5fd;padding:2px 8px;border-radius:4px;font-size:12px\">${escapeHtml(a.source)}</span></td>
            <td><strong>${escapeHtml(a.hostname || a.host_id || '-')}</strong></td>
            <td><span style=\"background:#111827;padding:2px 6px;border-radius:4px;font-size:12px\">${escapeHtml(a.severity)}</span></td>
            <td style=\"max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">${escapeHtml(a.message)}</td>
            <td style=\"color:#94a3b8;font-size:12px\">${escapeHtml(triageAnalyst || '-')}</td>
            <td><button onclick=\"openTriageModal('${escapeHtml(a.alert_id)}','${escapeHtml(rawStatus)}','${escapeHtml(triageAnalyst)}','${escapeHtml(triageNote)}','${escapeHtml(a.message||'').replace(/'/g,\"&#39;\")}')\" style=\"background:${color};color:#fff;border:none;border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px;white-space:nowrap\">${label}</button></td>
          </tr>`;
        }).join('');
        triageTableEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px\">
          <thead><tr style=\"background:#0f2035\">
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">시각</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">소스</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">호스트</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">심각도</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">메시지</th>
            <th style=\"padding:8px;color:#a3e635;text-align:left\">담당자</th>
            <th style=\"padding:8px;color:#93c5fd;text-align:left\">상태</th>
          </tr></thead><tbody>${rows}</tbody></table>`;
      } catch (err) { triageTableEl.innerHTML = `<span class=\"empty\">오류: ${escapeHtml(err.message)}</span>`; }
    }

    function openTriageModal(alertId, status, analyst, note, message) {
      currentTriageAlertId = alertId;
      triageModalAlertInfoEl.innerHTML = `<strong>Alert ID:</strong> ${escapeHtml(alertId)}<br><span style=\"color:#94a3b8\">${escapeHtml(message)}</span>`;
      triageModalStatusEl.value = status || 'pending';
      triageModalAnalystEl.value = analyst || '';
      triageModalNoteEl.value = note || '';
      triageModalStatusLineEl.textContent = '';
      if (typeof triageModalEl.showModal === 'function') triageModalEl.showModal();
      else triageModalEl.setAttribute('open', 'open');
    }

    document.getElementById('triage_modal_save').addEventListener('click', async () => {
      if (!currentTriageAlertId) return;
      const body = { status: triageModalStatusEl.value, analyst: triageModalAnalystEl.value, note: triageModalNoteEl.value };
      triageModalStatusLineEl.textContent = '저장 중...';
      try {
        const res = await fetch(`/alerts/${encodeURIComponent(currentTriageAlertId)}/triage`, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        if (!res.ok) { const d = await res.json(); triageModalStatusLineEl.textContent = `오류: ${d.detail || res.status}`; return; }
        triageModalStatusLineEl.textContent = '저장 완료';
        setTimeout(() => { if (triageModalEl.open) triageModalEl.close(); loadTriage(); }, 800);
      } catch (err) { triageModalStatusLineEl.textContent = `오류: ${err.message}`; }
    });

    // Auto-save triage status when dropdown changes
    triageModalStatusEl.addEventListener('change', async () => {
      if (!currentTriageAlertId) return;
      const body = { status: triageModalStatusEl.value, analyst: triageModalAnalystEl.value, note: triageModalNoteEl.value };
      triageModalStatusLineEl.textContent = '자동 저장 중...';
      try {
        const res = await fetch(`/alerts/${encodeURIComponent(currentTriageAlertId)}/triage`, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
        });
        if (!res.ok) { const d = await res.json(); triageModalStatusLineEl.textContent = `오류: ${d.detail || res.status}`; return; }
        triageModalStatusLineEl.style.color = '#86efac';
        triageModalStatusLineEl.textContent = '✅ 자동 저장됨';
        loadTriage();
      } catch (err) { triageModalStatusLineEl.textContent = `오류: ${err.message}`; }
    });

    document.getElementById('reload_triage').addEventListener('click', loadTriage);

    // ── Incidents ────────────────────────────────────────────────────────────
    function buildIncidentParams() {
      const params = new URLSearchParams();
      const from = document.getElementById('inc_date_from')?.value;
      const to = document.getElementById('inc_date_to')?.value;
      if (from) params.set('date_from', from);
      if (to) params.set('date_to', to);
      return params;
    }

    async function loadIncidents() {
      incidentsListEl.innerHTML = '<span class=\"empty\">로딩 중…</span>';
      try {
        const params = buildIncidentParams();
        const url = '/incidents' + (params.toString() ? '?' + params.toString() : '');
        const res = await fetch(url);
        if (!res.ok) { incidentsListEl.innerHTML = '<span class=\"empty\">인시던트 로드 실패</span>'; return; }
        const data = await res.json();
        const list = data.incidents || [];
        if (!list.length) { incidentsListEl.innerHTML = '<span class=\"empty\">인시던트 없음</span>'; return; }
        const STATUS_COLOR = { open: '#ef4444', investigating: '#f59e0b', resolved: '#22c55e', closed: '#6b7280' };
        incidentsListEl.innerHTML = list.map(inc => {
          const color = STATUS_COLOR[inc.status] || '#6b7280';
          return `<div style=\"background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center\">
            <div>
              <strong>${escapeHtml(inc.title)}</strong>
              <div style=\"color:#94a3b8;font-size:12px;margin-top:4px\">${escapeHtml(formatTime(inc.created_at))} · 노트 ${(inc.notes||[]).length}개</div>
            </div>
            <div style=\"display:flex;gap:8px;align-items:center\">
              <span style=\"background:${color};color:#fff;padding:3px 10px;border-radius:6px;font-size:12px\">${escapeHtml(inc.status)}</span>
              <button onclick=\"openIncidentModal('${escapeHtml(inc.incident_id)}')\" style=\"background:#1e293b;color:#93c5fd;border:1px solid #334155;border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px\">상세</button>
            </div>
          </div>`;
        }).join('');
      } catch (err) { incidentsListEl.innerHTML = `<span class=\"empty\">오류: ${escapeHtml(err.message)}</span>`; }
    }

    async function openIncidentModal(incidentId) {
      currentIncidentId = incidentId;
      document.getElementById('incident_modal_title').textContent = '인시던트 상세';
      document.getElementById('incident_modal_status_line').textContent = '';
      document.getElementById('incident_modal_note_text').value = '';
      document.getElementById('incident_modal_analyst').value = '';
      document.getElementById('incident_modal_status_analyst').value = '';
      try {
        const res = await fetch('/incidents');
        if (!res.ok) return;
        const data = await res.json();
        const inc = (data.incidents || []).find(i => i.incident_id === incidentId);
        if (!inc) return;
        document.getElementById('incident_modal_title').textContent = inc.title;
        const statusUpdatedLine = inc.status_updated_at
          ? `<br>🕐 <strong style="color:#fbbf24">상태 변경 시각:</strong> ${escapeHtml(formatTime(inc.status_updated_at))}`
          : '';
        document.getElementById('incident_modal_info').innerHTML = `<span style="color:#64748b">ID: ${escapeHtml(inc.incident_id)}</span><br>생성: ${escapeHtml(formatTime(inc.created_at))} &nbsp;|&nbsp; 수정: ${escapeHtml(formatTime(inc.updated_at))}${statusUpdatedLine}`;
        document.getElementById('incident_modal_status').value = inc.status;
        // 상태 변경 히스토리
        const history = inc.history || [];
        const statusLabels = { open: '🔵 open', investigating: '🟡 investigating', resolved: '🟢 resolved', closed: '⚫ closed', created: '🆕 생성됨' };
        document.getElementById('incident_modal_history').innerHTML = history.length
          ? [...history].reverse().map(h => {
              const arrow = h.event === 'created'
                ? `<strong>${statusLabels[h.to_status] || h.to_status}</strong>`
                : `${statusLabels[h.from_status] || h.from_status} → <strong>${statusLabels[h.to_status] || h.to_status}</strong>`;
              return `<div style=\"background:#0c1827;border-left:3px solid #334155;padding:7px 12px;margin-bottom:5px;border-radius:4px;font-size:12px\">
                <div style=\"color:#64748b\">${escapeHtml(formatTime(h.changed_at))} &nbsp;·&nbsp; ${escapeHtml(h.analyst || '-')}</div>
                <div style=\"color:#e2e8f0;margin-top:2px\">${arrow}</div>
              </div>`;
            }).join('')
          : '<div style=\"color:#64748b;font-size:13px\">변경 이력 없음</div>';
        // 조사 노트
        const notes = inc.notes || [];
        document.getElementById('incident_modal_notes').innerHTML = notes.length
          ? notes.map(n => `<div style=\"background:#0f172a;border-left:3px solid #334155;padding:8px 12px;margin-bottom:6px;border-radius:4px\"><div style=\"color:#94a3b8;font-size:12px\">${escapeHtml(formatTime(n.created_at))} · ${escapeHtml(n.analyst||'-')}</div><div>${escapeHtml(n.text)}</div></div>`).join('')
          : '<div style=\"color:#64748b;font-size:13px\">조사 노트 없음</div>';
      } catch (_) {}
      if (typeof incidentModalEl.showModal === 'function') incidentModalEl.showModal();
      else incidentModalEl.setAttribute('open', 'open');
    }

    document.getElementById('incident_modal_update_status').addEventListener('click', async () => {
      if (!currentIncidentId) return;
      const status = document.getElementById('incident_modal_status').value;
      const analyst = document.getElementById('incident_modal_status_analyst').value.trim();
      const sl = document.getElementById('incident_modal_status_line');
      sl.textContent = '저장 중...';
      try {
        const res = await fetch(`/incidents/${encodeURIComponent(currentIncidentId)}`, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ status, analyst }),
        });
        sl.textContent = res.ok ? '상태 저장 완료' : `오류: ${res.status}`;
        if (res.ok) { loadIncidents(); openIncidentModal(currentIncidentId); }
      } catch (err) { sl.textContent = `오류: ${err.message}`; }
    });

    document.getElementById('incident_modal_add_note').addEventListener('click', async () => {
      if (!currentIncidentId) return;
      const text = document.getElementById('incident_modal_note_text').value.trim();
      const analyst = document.getElementById('incident_modal_analyst').value.trim();
      const sl = document.getElementById('incident_modal_status_line');
      if (!text) { sl.textContent = '노트 내용을 입력하세요.'; return; }
      sl.textContent = '추가 중...';
      try {
        const res = await fetch(`/incidents/${encodeURIComponent(currentIncidentId)}/notes`, {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ text, analyst }),
        });
        if (res.ok) { sl.textContent = '노트 추가 완료'; openIncidentModal(currentIncidentId); loadIncidents(); }
        else sl.textContent = `오류: ${res.status}`;
      } catch (err) { sl.textContent = `오류: ${err.message}`; }
    });

    document.getElementById('create_incident').addEventListener('click', async () => {
      const title = incTitleEl.value.trim();
      if (!title) { incidentStatusEl.textContent = '제목을 입력하세요.'; return; }
      incidentStatusEl.textContent = '생성 중...';
      try {
        const res = await fetch('/incidents', {
          method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ title }),
        });
        if (res.ok) { incidentStatusEl.textContent = '인시던트 생성 완료'; incTitleEl.value = ''; loadIncidents(); }
        else { const d = await res.json(); incidentStatusEl.textContent = `오류: ${d.detail || res.status}`; }
      } catch (err) { incidentStatusEl.textContent = `오류: ${err.message}`; }
    });

    document.getElementById('reload_incidents').addEventListener('click', loadIncidents);

    // 날짜 필터 조회 버튼
    if (document.getElementById('inc_filter_btn')) {
      document.getElementById('inc_filter_btn').addEventListener('click', loadIncidents);
    }

    // CSV 다운로드
    if (document.getElementById('inc_csv_btn')) {
      document.getElementById('inc_csv_btn').addEventListener('click', () => {
        const params = buildIncidentParams();
        params.set('format', 'csv');
        const url = '/incidents?' + params.toString();
        const a = document.createElement('a');
        a.href = url;
        a.download = 'incidents.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      });
    }

    // ── Asset Collection Board ────────────────────────────────────────────────
    let currentAssetTab = 'fleet';

    function switchAssetTab(tab) {
      currentAssetTab = tab;
      ['fleet', 'zabbix', 'trivy'].forEach(t => {
        const sec = document.getElementById(`assets_${t}_section`);
        const btn = document.getElementById(`asset_tab_${t}`);
        if (sec) sec.classList.toggle('hidden', t !== tab);
        if (btn) {
          btn.style.color = t === tab ? '#38bdf8' : '#94a3b8';
          btn.style.borderBottomColor = t === tab ? '#38bdf8' : 'transparent';
        }
      });
    }

    const FLEET_URL = '__FLEET_UI_URL__';
    const ZABBIX_URL = '__ZABBIX_UI_URL__';

    function renderFleetTable(hosts, containerEl) {
      if (!hosts.length) { containerEl.innerHTML = '<div class=\"empty\">Fleet에서 수집된 PC 자산이 없습니다.</div>'; return; }
      const rows = hosts.map(h => {
        const statusCls = h.status === 'online' ? 'online' : h.status === 'offline' ? 'offline' : 'unknown';
        const fleetLink = FLEET_URL ? `<a href=\"${escapeHtml(FLEET_URL)}/hosts?query=${encodeURIComponent(h.hostname)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#6ee7b7;font-size:12px;\">Fleet ↗</a>` : '';
        const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
        const ownerStr = `<span style=\"color:#a3e635;font-size:12px\">${escapeHtml(ownerLabel)}</span>
          <button onclick=\"openOwnerModal('${escapeHtml(h.hostname)}','${escapeHtml(h.owner||'')}','${escapeHtml(h.team||'')}','${escapeHtml(h.category||'')}')\"
            style=\"margin-left:6px;padding:2px 6px;font-size:11px;border-radius:4px;background:#1e3a5f;color:#93c5fd;border:1px solid #334155;cursor:pointer;\">✏️</button>`;
        return `<tr>
          <td><strong>${escapeHtml(h.hostname)}</strong>${fleetLink ? '<br>' + fleetLink : ''}</td>
          <td><span style=\"background:#0d2137;color:#6ee7b7;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;\">🖥️ PC</span></td>
          <td>${escapeHtml(h.platform)}</td>
          <td>${escapeHtml(h.primary_ip)}</td>
          <td><span class=\"badge ${statusCls}\">${escapeHtml(h.status)}</span></td>
          <td>${escapeHtml(h.risk_score)}</td>
          <td>${escapeHtml(formatTime(h.last_seen_at))}</td>
          <td>${ownerStr}</td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#0f2035;\">
          <th style=\"padding:8px;color:#6ee7b7\">호스트명</th>
          <th style=\"padding:8px;color:#6ee7b7\">유형</th>
          <th style=\"padding:8px;color:#93c5fd\">플랫폼</th>
          <th style=\"padding:8px;color:#93c5fd\">IP</th>
          <th style=\"padding:8px;color:#93c5fd\">상태</th>
          <th style=\"padding:8px;color:#93c5fd\">리스크</th>
          <th style=\"padding:8px;color:#93c5fd\">마지막 확인</th>
          <th style=\"padding:8px;color:#a3e635\">담당자 / 팀</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function renderZabbixTable(hosts, containerEl) {
      if (!hosts.length) { containerEl.innerHTML = '<div class=\"empty\">Zabbix에서 수집된 서버 자산이 없습니다.</div>'; return; }
      const showImp = assetColumnPrefs.show_importance !== false;
      const showIsms = assetColumnPrefs.show_isms_control !== false;
      const showIso = assetColumnPrefs.show_iso27001_control !== false;
      const impColor = { '상': '#fca5a5', '중': '#fde68a', '하': '#86efac' };
      const rows = hosts.map(h => {
        const statusCls = h.status === 'online' ? 'online' : h.status === 'offline' ? 'offline' : 'unknown';
        const zabbixLink = ZABBIX_URL ? `<a href=\"${escapeHtml(ZABBIX_URL)}/zabbix.php?action=host.list&filter_set=1&filter_host=${encodeURIComponent(h.hostname)}\" target=\"_blank\" rel=\"noopener\" style=\"color:#7dd3fc;font-size:12px;\">Zabbix ↗</a>` : '';
        const metricStr = h.latest_metric ? `${escapeHtml(h.latest_metric)}: ${escapeHtml(h.latest_value || '-')}` : '-';
        const impBadge = h.importance ? `<span style=\"background:#1e293b;color:${impColor[h.importance]||'#94a3b8'};padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700\">${escapeHtml(h.importance)}</span>` : '-';
        const ownerLabel = [h.owner, h.team].filter(Boolean).join(' / ') || '-';
        const ownerStr = `<span style=\"color:#a3e635;font-size:12px\">${escapeHtml(ownerLabel)}</span>
          <button onclick=\"openOwnerModal('${escapeHtml(h.hostname)}','${escapeHtml(h.owner||'')}','${escapeHtml(h.team||'')}','${escapeHtml(h.category||'')}')\"
            style=\"margin-left:6px;padding:2px 6px;font-size:11px;border-radius:4px;background:#1e3a5f;color:#93c5fd;border:1px solid #334155;cursor:pointer;\">✏️</button>`;
        return `<tr>
          <td><strong>${escapeHtml(h.hostname)}</strong>${zabbixLink ? '<br>' + zabbixLink : ''}</td>
          <td style=\"font-size:12px\">${escapeHtml(h.category || '-')}</td>
          ${showImp ? `<td>${impBadge}</td>` : ''}
          ${showIsms ? `<td style=\"font-size:11px;color:#7dd3fc\">${escapeHtml(h.isms_control || '-')}</td>` : ''}
          ${showIso ? `<td style=\"font-size:11px;color:#a78bfa\">${escapeHtml(h.iso27001_control || '-')}</td>` : ''}
          <td>${escapeHtml(h.primary_ip)}</td>
          <td><span class=\"badge ${statusCls}\">${escapeHtml(h.status)}</span></td>
          <td style=\"font-size:12px;color:#94a3b8\">${metricStr}</td>
          <td>${ownerStr}</td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#0f2035;\">
          <th style=\"padding:8px;color:#7dd3fc\">호스트명</th>
          <th style=\"padding:8px;color:#7dd3fc\">분류</th>
          ${showImp ? '<th style=\"padding:8px;color:#fde68a\">중요도</th>' : ''}
          ${showIsms ? '<th style=\"padding:8px;color:#7dd3fc\">ISMS-P 통제</th>' : ''}
          ${showIso ? '<th style=\"padding:8px;color:#a78bfa\">ISO 27001</th>' : ''}
          <th style=\"padding:8px;color:#93c5fd\">IP</th>
          <th style=\"padding:8px;color:#93c5fd\">상태</th>
          <th style=\"padding:8px;color:#94a3b8\">최근 메트릭</th>
          <th style=\"padding:8px;color:#a3e635\">담당자 / 팀</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }

    function renderTrivyTable(rows, containerEl) {
      if (!rows.length) { containerEl.innerHTML = '<div class=\"empty\">Trivy 취약점 데이터가 없습니다.</div>'; return; }
      const sevColor = { critical:'#fca5a5', high:'#fdba74', medium:'#fde68a', low:'#86efac', info:'#94a3b8' };
      const tableRows = rows.map(r => {
        const planText = r.action_plan ? escapeHtml(r.action_plan).substring(0, 40) + (r.action_plan.length > 40 ? '…' : '') : '';
        const planCell = r.action_plan
          ? `<span style=\"color:#a3e635;font-size:12px\" title=\"${escapeHtml(r.action_plan)}\">${planText}</span>${r.action_target_date ? '<br><span style=\"color:#64748b;font-size:11px\">~' + escapeHtml(r.action_target_date) + '</span>' : ''}`
          : `<button onclick=\"openPlanModal('${escapeHtml(r.host_id)}','${escapeHtml(r.hostname)}')\" style=\"font-size:11px;padding:2px 7px;background:#1e3a5f;border:1px solid #334155;border-radius:4px;color:#7dd3fc;cursor:pointer\">+ 계획 추가</button>`;
        return `<tr>
          <td><strong>${escapeHtml(r.hostname)}</strong><br><span style=\"color:#64748b;font-size:11px\">${escapeHtml(r.host_id)}</span></td>
          <td style=\"color:${sevColor.critical};font-weight:700;text-align:center\">${r.critical}</td>
          <td style=\"color:${sevColor.high};font-weight:700;text-align:center\">${r.high}</td>
          <td style=\"color:${sevColor.medium};text-align:center\">${r.medium}</td>
          <td style=\"color:${sevColor.low};text-align:center\">${r.low}</td>
          <td style=\"text-align:center\">${r.total}</td>
          <td style=\"font-size:12px;color:#94a3b8\">${escapeHtml(r.latest_cve || '-')}</td>
          <td style=\"font-size:12px;color:#64748b\">${escapeHtml(formatTime(r.latest_detected_at))}</td>
          <td style=\"min-width:140px\">${planCell}</td>
        </tr>`;
      }).join('');
      containerEl.innerHTML = `<table style=\"width:100%;border-collapse:collapse;font-size:13px;\">
        <thead><tr style=\"background:#0f2035;\">
          <th style=\"padding:8px;color:#fdba74\">호스트</th>
          <th style=\"padding:8px;color:#fca5a5\">Critical</th>
          <th style=\"padding:8px;color:#fdba74\">High</th>
          <th style=\"padding:8px;color:#fde68a\">Medium</th>
          <th style=\"padding:8px;color:#86efac\">Low</th>
          <th style=\"padding:8px;color:#93c5fd\">합계</th>
          <th style=\"padding:8px;color:#94a3b8\">최근 CVE</th>
          <th style=\"padding:8px;color:#64748b\">탐지일</th>
          <th style=\"padding:8px;color:#a3e635\">조치 계획</th>
        </tr></thead>
        <tbody>${tableRows}</tbody>
      </table>`;
    }

    // 조치계획 모달
    let _planHostId = null, _planHostname = null;
    function openPlanModal(hostId, hostname) {
      _planHostId = hostId; _planHostname = hostname;
      document.getElementById('plan_modal_title').textContent = hostname + ' 조치 계획';
      document.getElementById('plan_text').value = '';
      document.getElementById('plan_target_date').value = '';
      document.getElementById('plan_updated_by').value = '';
      fetch(`/assets/plans/${encodeURIComponent(hostId)}`).then(r=>r.json()).then(d=>{
        document.getElementById('plan_text').value = d.text || '';
        document.getElementById('plan_target_date').value = d.target_date || '';
        document.getElementById('plan_updated_by').value = d.updated_by || '';
      }).catch(()=>{});
      document.getElementById('plan_modal').style.display = 'flex';
    }
    function closePlanModal() { document.getElementById('plan_modal').style.display = 'none'; }

    /* ── 담당자/카테고리 편집 모달 ──────────────────────────────────────── */
    function openOwnerModal(hostname, owner, team, category) {
      document.getElementById('owner_modal_hostname').value = hostname;
      document.getElementById('owner_modal_owner').value = owner || '';
      document.getElementById('owner_modal_team').value = team || '';
      document.getElementById('owner_modal_category').value = category || '';
      document.getElementById('owner_modal_changed_by').value = '';
      document.getElementById('owner_modal_status').textContent = '';
      document.getElementById('owner_modal_status').style.color = '#94a3b8';
      document.getElementById('owner_modal_title').textContent = `담당자/카테고리 수정 — ${hostname}`;
      document.getElementById('owner_modal').style.display = 'flex';
    }
    function closeOwnerModal() { document.getElementById('owner_modal').style.display = 'none'; }

    document.addEventListener('DOMContentLoaded', () => {
      const ownerSaveBtn = document.getElementById('owner_modal_save');
      if (ownerSaveBtn) ownerSaveBtn.addEventListener('click', async () => {
        const hostname = document.getElementById('owner_modal_hostname').value;
        const owner = document.getElementById('owner_modal_owner').value.trim();
        const team = document.getElementById('owner_modal_team').value.trim();
        const category = document.getElementById('owner_modal_category').value.trim();
        const changed_by = document.getElementById('owner_modal_changed_by').value.trim();
        const statusEl = document.getElementById('owner_modal_status');
        if (!changed_by) { statusEl.style.color='#fca5a5'; statusEl.textContent='수정자 이름을 입력하세요.'; return; }
        statusEl.textContent = '저장 중...';
        try {
          const res = await fetch('/assets/owners', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ hostname, owner, team, category, changed_by })
          });
          if (!res.ok) throw new Error(await res.text());
          statusEl.style.color = '#86efac';
          statusEl.textContent = '✅ 저장되었습니다.';
          setTimeout(() => { closeOwnerModal(); loadAssets(); }, 800);
        } catch(e) {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `오류: ${e.message}`;
        }
      });
    });

    document.addEventListener('DOMContentLoaded', () => {
      const saveBtn = document.getElementById('plan_modal_save');
      if (saveBtn) saveBtn.addEventListener('click', async () => {
        if (!_planHostId) return;
        await fetch(`/assets/plans/${encodeURIComponent(_planHostId)}`, {
          method: 'PUT', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({
            text: document.getElementById('plan_text').value,
            target_date: document.getElementById('plan_target_date').value,
            updated_by: document.getElementById('plan_updated_by').value || '운영자',
          })
        });
        closePlanModal();
        loadAssets();
      });
    });

    async function loadAssets() {
      const statusEl = document.getElementById('assets_status');
      statusEl.textContent = '자산 데이터 로딩 중...';
      try {
        const res = await fetch('/assets');
        if (!res.ok) { statusEl.textContent = '자산 데이터 로드 실패'; return; }
        const data = await res.json();
        // Fleet
        document.getElementById('fleet_total').textContent = data.fleet?.total ?? '-';
        document.getElementById('fleet_online').textContent = data.fleet?.online ?? '-';
        document.getElementById('fleet_offline').textContent = data.fleet?.offline ?? '-';
        renderFleetTable(data.fleet?.hosts || [], document.getElementById('fleet_table'));
        // Zabbix
        document.getElementById('zabbix_total').textContent = data.zabbix?.total ?? '-';
        document.getElementById('zabbix_online').textContent = data.zabbix?.online ?? '-';
        document.getElementById('zabbix_offline').textContent = data.zabbix?.offline ?? '-';
        renderZabbixTable(data.zabbix?.hosts || [], document.getElementById('zabbix_table'));
        // Trivy
        document.getElementById('trivy_affected_hosts').textContent = data.trivy?.affected_hosts ?? '-';
        document.getElementById('trivy_total_vulns').textContent = data.trivy?.total_vulns ?? '-';
        document.getElementById('trivy_critical').textContent = data.trivy?.critical ?? '-';
        document.getElementById('trivy_high').textContent = data.trivy?.high ?? '-';
        renderTrivyTable(data.trivy?.rows || [], document.getElementById('trivy_table'));
        statusEl.textContent = `자산 현황 업데이트: ${formatTime(data.generated_at)}`;
      } catch (err) { statusEl.textContent = `오류: ${err.message}`; }
    }

    function downloadAssetsCSV(source) {
      const a = document.createElement('a');
      a.href = `/assets?format=csv&source=${encodeURIComponent(source)}`;
      a.download = '';
      a.click();
    }

    // ── Guide Tab ─────────────────────────────────────────────────────────
    let currentGuideId = null;
    const guideSubBtns = {};
    const guideSubTabsEl = document.getElementById('guide_sub_tabs');
    const guidePrefs = defaultPreferences.guides || {};

    function buildGuideSubTabs() {
      if (!guideSubTabsEl) return;
      guideSubTabsEl.innerHTML = '';
      Object.keys(guideLabels).forEach((id, idx) => {
        if (guidePrefs[id] === false) return; // hidden by admin
        const btn = document.createElement('button');
        btn.id = 'guide_tab_' + id;
        btn.textContent = guideLabels[id];
        btn.style.cssText = 'background:none;border:none;border-bottom:2px solid transparent;padding:8px 18px;color:#94a3b8;font-size:13px;font-weight:600;cursor:pointer;border-radius:0;margin-bottom:-1px;';
        btn.addEventListener('click', () => switchGuideTab(id));
        guideSubTabsEl.appendChild(btn);
        guideSubBtns[id] = btn;
        if (currentGuideId === null) currentGuideId = id; // first visible
      });
    }

    function switchGuideTab(guideId) {
      currentGuideId = guideId;
      Object.entries(guideSubBtns).forEach(([id, btn]) => {
        if (!btn) return;
        const active = id === guideId;
        btn.style.borderBottomColor = active ? '#38bdf8' : 'transparent';
        btn.style.color = active ? '#38bdf8' : '#94a3b8';
      });
      loadGuide(guideId);
    }

    function renderMarkdownLite(text) {
      // 매우 간단한 마크다운 렌더러: 헤더/볼드/코드블록/체크박스 지원
      return escapeHtml(text)
        .replace(/^### (.+)$/gm, '<h3 style="color:#a3e635;margin:16px 0 6px;font-size:14px">$1</h3>')
        .replace(/^## (.+)$/gm, '<h2 style="color:#38bdf8;margin:20px 0 8px;font-size:16px">$1</h2>')
        .replace(/^#### (.+)$/gm, '<h4 style="color:#94a3b8;margin:12px 0 4px;font-size:13px">$1</h4>')
        .replace(/\\*\\*(.+?)\\*\\*/g, '<strong style="color:#f1f5f9">$1</strong>')
        .replace(/`([^`]+)`/g, '<code style="background:#1e293b;padding:1px 6px;border-radius:4px;color:#a3e635;font-size:12px">$1</code>')
        .replace(/^```[\\s\\S]*?```/gm, m => `<pre style="background:#0f2035;border:1px solid #334155;border-radius:6px;padding:12px 14px;overflow-x:auto;font-size:12px;color:#86efac;margin:8px 0">${m.slice(m.indexOf('\\n')+1, m.lastIndexOf('\\n'))}</pre>`)
        .replace(/^- \\[ \\] (.+)$/gm, '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0"><span style="color:#fde68a;margin-top:1px">☐</span><span>$1</span></div>')
        .replace(/^- \\[x\\] (.+)$/gm, '<div style="display:flex;gap:8px;align-items:flex-start;padding:2px 0"><span style="color:#86efac;margin-top:1px">☑</span><span style="color:#64748b;text-decoration:line-through">$1</span></div>')
        .replace(/^- (.+)$/gm, '<div style="padding:2px 0 2px 12px;color:#cbd5e1">• $1</div>')
        .replace(/^---$/gm, '<hr style="border:none;border-top:1px solid #334155;margin:16px 0">')
        .replace(/\\n/g, '\\n');
    }

    async function loadGuide(guideId) {
      const titleEl = document.getElementById('guide_content_title');
      const bodyEl = document.getElementById('guide_content_body');
      const updatedEl = document.getElementById('guide_updated_at');
      if (!titleEl || !bodyEl) return;
      bodyEl.innerHTML = '<span style="color:#64748b">로딩 중…</span>';
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`);
        if (!res.ok) throw new Error(res.status);
        const g = await res.json();
        titleEl.textContent = g.title || guideId;
        updatedEl.textContent = g.updated_at ? `수정: ${g.updated_at.slice(0,10)}` : '(기본 내용)';
        bodyEl.innerHTML = renderMarkdownLite(g.content || '');
      } catch(e) {
        bodyEl.innerHTML = `<span style="color:#fca5a5">오류: ${escapeHtml(e.message)}</span>`;
      }
    }

    // ── Role-based tab visibility ─────────────────────────────────────────────
    const ROLE_LABELS = { admin: '어드민', security: '보안담당자', monitor: '서버모니터', user: '사용자' };
    async function applyRoleBasedTabs() {
      try {
        const res = await fetch('/auth/me');
        if (!res.ok) return;
        const me = await res.json();
        const allowed = me.allowed_tabs || [];
        ['triage', 'incidents', 'assets', 'guides'].forEach(tab => {
          const navBtn = document.querySelector(`.tabs-nav [data-tab="${tab}"]`);
          const bnBtn = document.querySelector(`.bottom-nav [data-tab="${tab}"]`);
          const visible = allowed.includes(tab);
          if (navBtn) navBtn.style.display = visible ? '' : 'none';
          if (bnBtn) bnBtn.style.display = visible ? '' : 'none';
        });
        const roleLabel = ROLE_LABELS[me.role] || me.role;
        const heroP = document.querySelector('.hero p');
        if (heroP && me.username) {
          heroP.innerHTML = `환영합니다, <strong style="color:#38bdf8">${escapeHtml(me.username)}</strong> <span style="background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:6px;font-size:12px">${escapeHtml(roleLabel)}</span>`;
        }
      } catch(e) { /* 비로그인 상태에서도 대시보드는 동작 */ }
    }

    // ── NLQ FAB ──────────────────────────────────────────────────────────────
    const nlqFabDialog = document.getElementById('nlq_fab_dialog');
    document.getElementById('nlq_fab_btn')?.addEventListener('click', () => {
      if (typeof nlqFabDialog.showModal === 'function') nlqFabDialog.showModal();
      else nlqFabDialog.setAttribute('open', 'open');
    });
    document.getElementById('nlq_fab_close')?.addEventListener('click', () => {
      if (nlqFabDialog.open) nlqFabDialog.close();
    });

    async function initialize() {
      await loadPreferences();
      await applyRoleBasedTabs();
      await loadDashboard();
    }

    initialize();
  </script>

  <!-- ── NLQ Floating Action Button ───────────────────────────────────── -->
  <button class=\"nlq-fab\" id=\"nlq_fab_btn\" title=\"자연어 질의 (NLQ)\">💬 NLQ 질의</button>

  <dialog id=\"nlq_fab_dialog\" class=\"nlq-dialog\">
    <div class=\"nlq-dialog-body\">
      <div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:12px\">
        <h3 style=\"margin:0;font-size:18px\">💬 자연어 질의 (NLQ)</h3>
        <button id=\"nlq_fab_close\" class=\"secondary\" style=\"padding:4px 12px\">닫기</button>
      </div>
      <div style=\"color:#94a3b8;font-size:13px;margin-bottom:10px\">자연스럽게 질문하거나 예시 형식으로 입력하면 해석합니다. <a href=\"#\" id=\"nlq_guide_link\" style=\"color:#7dd3fc;\">가이드 ↗</a></div>
      <textarea id=\"nlq_textarea\" rows=\"3\" style=\"width:100%;box-sizing:border-box;background:#0b1220;color:#e5e7eb;border:1px solid #334155;border-radius:8px;padding:10px;font-size:14px;resize:vertical;\" placeholder=\"예: 오프라인 호스트 보여줘 / 최근 24시간 wazuh high alert 요약\"></textarea>
      <div id=\"nlq_interpret_result\" style=\"margin:8px 0;color:#7dd3fc;font-size:13px;\"></div>
      <div style=\"display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;\">
        <button type=\"button\" id=\"nlq_interpret_btn\" class=\"secondary\">Interpret</button>
        <button type=\"button\" id=\"nlq_run_btn\">Run Query</button>
        <button type=\"button\" id=\"nlq_csv_btn\" class=\"secondary\" style=\"display:none;\">Download CSV</button>
      </div>
      <div id=\"nlq_result_area\" style=\"margin-top:12px;\"></div>
    </div>
  </dialog>
</body>
</html>"""
    return (
        html.replace("__DOCS_PORTAL_URL__", docs_url)
        .replace("__USER_DASHBOARD_PREFS_JSON__", default_preferences_json)
        .replace("__CARD_LABELS_JSON__", card_labels_json)
        .replace("__SECTION_LABELS_JSON__", section_labels_json)
        .replace("__NLQ_GUIDE_EXAMPLES__", nlq_guide_examples_json)
        .replace("__FLEET_UI_URL__", fleet_ui_url)
        .replace("__ZABBIX_UI_URL__", zabbix_ui_url)
        .replace("__GUIDE_LABELS_JSON__", guide_labels_json)
    )


def render_query_console_html(docs_url: str = DOCS_PORTAL_URL) -> str:
    payload_json = json.dumps(DEFAULT_UI_PAYLOAD, indent=2, ensure_ascii=False)
    default_payload_json = json.dumps(DEFAULT_UI_PAYLOAD, ensure_ascii=False)
    guide_examples_json = json.dumps(list(QUERY_GUIDE_EXAMPLES), ensure_ascii=False)
    default_preferences_json = json.dumps(DEFAULT_USER_DASHBOARD_PREFERENCES, ensure_ascii=False)
    card_labels_json = json.dumps(USER_DASHBOARD_CARD_LABELS, ensure_ascii=False)
    section_labels_json = json.dumps(USER_DASHBOARD_SECTION_LABELS, ensure_ascii=False)
    asset_column_labels_json = json.dumps(USER_DASHBOARD_ASSET_COLUMN_LABELS, ensure_ascii=False)
    guide_labels_json = json.dumps(USER_DASHBOARD_GUIDE_LABELS, ensure_ascii=False)
    html = """<!doctype html>
<html lang=\"ko\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>MORI Security Dashboard</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b1220; color: #e5e7eb; }
    .wrap { max-width: 1440px; margin: 0 auto; padding: 28px 20px 48px; }
    .hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; margin-bottom: 18px; }
    .hero h1 { margin: 0 0 8px; font-size: 32px; }
    .hero p { margin: 0; color: #94a3b8; max-width: 860px; line-height: 1.5; }
    .links { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 14px; }
    .links a { color: #cfe3ff; text-decoration: none; border: 1px solid #334155; padding: 8px 12px; border-radius: 999px; background: #0f172a; }
    .top-actions { display: flex; gap: 10px; flex-wrap: wrap; }
    .layout { display: grid; grid-template-columns: minmax(0, 2fr) minmax(340px, 420px); gap: 16px; align-items: start; }
    .stack { display: grid; gap: 16px; }
    .metrics { display: grid; gap: 12px; grid-template-columns: repeat(6, minmax(0, 1fr)); }
    .card { background: linear-gradient(180deg, #101827 0%, #0f172a 100%); border: 1px solid #233046; border-radius: 16px; padding: 18px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.18); }
    .metric-card { cursor: pointer; transition: transform 0.15s ease, border-color 0.15s ease; }
    .metric-card:hover { transform: translateY(-1px); border-color: #38bdf8; }
    .metric-card:focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px; }
    .metric-label { color: #94a3b8; font-size: 13px; margin-bottom: 8px; }
    .metric-value { font-size: 28px; font-weight: 800; }
    .metric-sub { margin-top: 6px; color: #7dd3fc; font-size: 13px; }
    .card h2 { margin: 0 0 12px; font-size: 18px; }
    .subtext { color: #94a3b8; font-size: 13px; margin-bottom: 12px; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #1f2937; vertical-align: top; }
    th { color: #94a3b8; font-weight: 600; }
    .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }
    .badge.online { background: rgba(34, 197, 94, 0.12); color: #86efac; }
    .badge.offline { background: rgba(248, 113, 113, 0.12); color: #fca5a5; }
    .badge.unknown { background: rgba(250, 204, 21, 0.12); color: #fde68a; }
    .coverage { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .coverage-item { background: #0b1220; border: 1px solid #223148; border-radius: 14px; padding: 14px; }
    .coverage-item strong { display: block; font-size: 22px; margin-top: 8px; }
    .list { display: grid; gap: 10px; }
    .list-item { border: 1px solid #1f2937; border-radius: 12px; padding: 12px; background: #0b1220; }
    .list-item .top { display: flex; gap: 12px; justify-content: space-between; margin-bottom: 6px; }
    .list-item .meta { color: #94a3b8; font-size: 12px; }
    .empty { color: #94a3b8; font-size: 14px; padding: 6px 0; }
    .row { display: grid; gap: 8px; margin-bottom: 12px; }
    label { font-size: 13px; color: #cbd5e1; }
    input, select, textarea, button { width: 100%; box-sizing: border-box; border-radius: 12px; border: 1px solid #334155; background: #0b1220; color: #e5e7eb; padding: 10px 12px; }
    textarea { resize: vertical; min-height: 120px; font-family: ui-monospace, SFMono-Regular, monospace; }
    /* 버튼 계층: primary(저장/실행) / secondary(보조) / ghost(중립) / danger(삭제) */
    button { border: 1px solid #1e3a5f; background: #1e3a5f; color: #93c5fd; font-weight: 600; cursor: pointer; font-size: 13px; }
    button:hover { background: #1e4a7a; border-color: #2563eb; color: #bfdbfe; }
    button.primary { background: #1d4ed8; border-color: #2563eb; color: #fff; }
    button.primary:hover { background: #2563eb; }
    button.secondary { background: #1e293b; border: 1px solid #334155; color: #94a3b8; }
    button.secondary:hover { background: #263345; color: #cbd5e1; }
    button.ghost { background: transparent; border: 1px solid #334155; color: #64748b; }
    button.ghost:hover { background: #0f172a; color: #94a3b8; }
    button.danger { background: #450a0a; border: 1px solid #7f1d1d; color: #fca5a5; }
    button.danger:hover { background: #7f1d1d; }
    .actions { display: grid; gap: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .actions a, .top-actions a { display: inline-flex; align-items: center; justify-content: center; border-radius: 12px; border: 1px solid #334155; background: #172033; color: #94a3b8; padding: 10px 12px; text-decoration: none; font-weight: 600; font-size: 13px; }
    .actions a:hover, .top-actions a:hover { background: #1e293b; color: #e5e7eb; }
    .quick-actions { display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .status-line { color: #94a3b8; font-size: 13px; margin-top: 8px; }
    .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
    .query-result-area { min-height: 80px; background: #0b1220; border: 1px solid #334155; border-radius: 12px; padding: 12px; overflow: auto; font-size: 13px; }
    .result-placeholder { color: #64748b; font-style: italic; }
    .result-error { color: #f87171; font-family: ui-monospace, SFMono-Regular, monospace; white-space: pre-wrap; font-size: 12px; }
    .result-summary { color: #7dd3fc; font-size: 13px; margin-bottom: 10px; padding: 8px 12px; background: #0f2035; border-radius: 8px; border-left: 3px solid #3b82f6; }
    .result-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 4px; }
    .result-table th { background: #0f2035; color: #93c5fd; font-weight: 600; text-align: left; padding: 8px 10px; border-bottom: 1px solid #1e3a5f; }
    .result-table td { padding: 7px 10px; border-bottom: 1px solid #1a2d45; color: #e5e7eb; vertical-align: top; word-break: break-all; }
    .result-table tr:last-child td { border-bottom: none; }
    .result-table tr:hover td { background: #0d1d30; }
    .result-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; background: #1e3a5f; color: #93c5fd; }
    .result-badge.wazuh { background: #2d1f5e; color: #c4b5fd; }
    .result-badge.zabbix { background: #1e3a5f; color: #93c5fd; }
    .result-badge.fleet { background: #1a3324; color: #6ee7b7; }
    .result-badge.trivy { background: #3b1f0e; color: #fbbf24; }
    .result-badge.hosts { background: #0f2035; color: #7dd3fc; }
    .top-actions button, .guide-chips button, .guide-list button { width: auto; }
    .guide-chips, .guide-list { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .chip { padding: 8px 12px; border-radius: 999px; }
    .toggle-grid { display: grid; gap: 8px; }
    .toggle-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border: 1px solid #223148; border-radius: 12px; background: #0b1220; }
    .toggle-item input { width: auto; margin: 0; }
    .guide-banner { margin-top: 12px; border-radius: 12px; padding: 12px; border: 1px solid #334155; background: #111827; }
    .guide-banner strong { display: block; margin-bottom: 6px; }
    .guide-banner.need-guide { border-color: #f59e0b; background: rgba(245, 158, 11, 0.12); }
    .guide-banner.warning { border-color: #38bdf8; background: rgba(56, 189, 248, 0.1); }
    dialog { border: 1px solid #334155; border-radius: 18px; padding: 0; background: #0f172a; color: #e5e7eb; width: min(760px, calc(100vw - 32px)); }
    dialog::backdrop { background: rgba(2, 6, 23, 0.74); }
    .guide-dialog { padding: 20px; }
    .guide-dialog-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
    .guide-dialog-head h3 { margin: 0; font-size: 20px; }
    .guide-dialog-copy { color: #94a3b8; font-size: 14px; line-height: 1.5; }
    .dialog-body { padding: 0 20px 20px; max-height: 60vh; overflow: auto; }
    /* Admin tabs */
    .atab-panel { display: none; margin-top: 16px; }
    .atab-panel.active { display: block; }
    #admin_tabs_nav { margin: 16px 0 0; }
    /* Tab nav buttons must never stretch to 100% width */
    .tabs-nav button { width: auto; display: inline-flex; align-items: center; white-space: nowrap; }
    /* Bottom nav (mobile only) */
    .admin-bottom-nav { display: none; }
    @media (max-width: 1240px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .layout { grid-template-columns: 1fr; }
    }
    @media (max-width: 768px) {
      html, body { overflow-x: hidden; }
      .wrap { padding: 16px 12px 80px; max-width: 100%; box-sizing: border-box; }
      .hero { flex-direction: column; gap: 10px; margin-bottom: 12px; }
      .hero h1 { font-size: 22px; }
      .hero p { font-size: 13px; }
      .links, .top-actions { flex-wrap: wrap; gap: 8px; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage, .quick-actions, .actions { grid-template-columns: 1fr; }
      .card { padding: 14px 12px; border-radius: 12px; }
      .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
      table { min-width: 480px; }
      /* 상단 탭 숨기고 하단 탭 표시 */
      .tabs-nav { display: none !important; }
      .admin-bottom-nav {
        display: flex;
        position: fixed;
        bottom: 0; left: 0; right: 0;
        z-index: 1000;
        background: #0f172a;
        border-top: 1px solid #233046;
        padding: 0;
        box-shadow: 0 -4px 20px rgba(0,0,0,.4);
      }
      .admin-bottom-nav button {
        flex: 1;
        width: auto;
        background: none;
        border: none;
        border-top: 2px solid transparent;
        padding: 8px 4px 10px;
        color: #64748b;
        font-size: 10px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 3px;
        border-radius: 0;
        transition: color 0.15s;
      }
      .admin-bottom-nav button .bn-icon { font-size: 20px; line-height: 1; }
      .admin-bottom-nav button.active { color: #38bdf8; border-top-color: #38bdf8; }
    }
    @media (max-width: 480px) {
      .metrics { grid-template-columns: 1fr 1fr; }
      .metric-value { font-size: 22px; }
    }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <div>
        <h1>MORI Admin Console</h1>
        <p>사용자용 대시보드에 노출할 정보 범위를 운영자가 통제하고, 더 상세한 수집 데이터와 자연어/구조화 질의를 함께 다루는 운영 콘솔입니다.</p>
        <div class=\"links\">
          <a href=\"__DOCS_PORTAL_URL__\" target=\"_blank\" rel=\"noreferrer\">운영 문서 / 포털</a>
          <a href=\"/health\" target=\"_blank\" rel=\"noreferrer\">Health JSON</a>
          <a href=\"/dashboard/summary\" target=\"_blank\" rel=\"noreferrer\">Dashboard JSON</a>
          <a href=\"/catalog\" target=\"_blank\" rel=\"noreferrer\">Query Catalog JSON</a>
        </div>
      </div>
      <div class=\"top-actions\">
        <a href=\"/ui\">Open User Dashboard</a>
        <button id=\"query_guide\" class=\"ghost\">Query Guide</button>
        <button id=\"refresh_dashboard\" class=\"ghost\">Refresh Dashboard</button>
        <a href=\"/auth/logout\" style=\"color:#ef4444;font-size:13px;margin-left:4px\">로그아웃</a>
      </div>
    </section>

    <!-- ── Admin Tab Nav ────────────────────────────────────────────────── -->
    <nav class=\"tabs-nav\" id=\"admin_tabs_nav\">
      <button class=\"active\" data-atab=\"monitoring\" onclick=\"switchAdminTab('monitoring')\">📊 모니터링</button>
      <button data-atab=\"assets\" onclick=\"switchAdminTab('assets')\">👤 자산 관리</button>
      <button data-atab=\"query\" onclick=\"switchAdminTab('query')\">🔍 쿼리</button>
      <button data-atab=\"settings\" onclick=\"switchAdminTab('settings')\">⚙️ 설정</button>
      <button data-atab=\"users\" onclick=\"switchAdminTab('users')\">🙋 가입 요청</button>
      <button data-atab=\"auditlog\" onclick=\"switchAdminTab('auditlog')\">📝 변경 이력</button>
      <button data-atab=\"roleperm\" onclick=\"switchAdminTab('roleperm')\">🔐 권한 관리</button>
    </nav>

    <!-- ── Tab: 모니터링 ─────────────────────────────────────────────────── -->
    <div class=\"atab-panel active\" id=\"atab_monitoring\">
      <section class=\"metrics\" id=\"overview_cards\"></section>
      <div class=\"stack\">
        <section class=\"card\">
          <h2>Source Coverage</h2>
          <div class=\"subtext\">Fleet / Wazuh / Zabbix / Trivy / host logs 기준으로 현재 MORI에 연결된 호스트 수입니다.</div>
          <div class=\"coverage\" id=\"source_coverage\"></div>
          <div class=\"status-line\" id=\"dashboard_status\">dashboard loading...</div>
        </section>
        <section class=\"card\">
          <h2>Latest Host Status</h2>
          <div class=\"subtext\">offline / unknown 호스트를 우선 배치합니다.</div>
          <div class=\"table-wrap\" id=\"latest_status\"></div>
        </section>
        <section class=\"card\">
          <h2>Risk Summary</h2>
          <div class=\"subtext\">24시간 alert와 누적 취약점 기준 상위 호스트입니다.</div>
          <div class=\"table-wrap\" id=\"risk_summary\"></div>
        </section>
        <section class=\"card\">
          <h2>Recent Activity</h2>
          <div class=\"subtext\">최근 alert / observation / fleet query 결과를 시간순으로 합쳐 보여줍니다.</div>
          <div class=\"list\" id=\"recent_activity\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 자산 관리 ────────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_assets\">
      <section class=\"card\">
        <h2>👤 자산 담당자 관리</h2>
        <div class=\"subtext\">서버·PC 자산의 담당자와 팀을 등록합니다. 호스트명과 정확히 일치해야 합니다.</div>
        <div id=\"owners_list\" class=\"list\" style=\"margin-bottom:16px;max-height:320px;overflow-y:auto\"><span class=\"empty\">로딩 중…</span></div>
        <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">
          <div class=\"row\"><label>호스트명</label><input id=\"own_hostname\" placeholder=\"예: db-prod-01\" /></div>
          <div class=\"row\"><label>담당자</label><input id=\"own_owner\" placeholder=\"예: 홍길동\" /></div>
          <div class=\"row\"><label>이메일</label><input id=\"own_email\" placeholder=\"예: hong@company.com\" /></div>
          <div class=\"row\"><label>팀</label><input id=\"own_team\" placeholder=\"예: 인프라팀\" /></div>
        </div>
        <div class=\"actions\">
          <button id=\"add_owner\">등록 / 수정</button>
          <button id=\"reload_owners\" class=\"secondary\">목록 새로고침</button>
        </div>
        <div class=\"status-line\" id=\"owner_status\"></div>
      </section>
    </div>

    <!-- ── Tab: 쿼리 ─────────────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_query\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2>⚡ Quick Actions</h2>
          <div class=\"subtext\">자주 쓰는 질의를 클릭하면 아래 폼에 바로 채워집니다.</div>
          <div class=\"quick-actions\" id=\"quick_queries\"></div>
        </section>
        <section class=\"card\">
          <h2>🗣️ Natural Language Query</h2>
          <div class=\"subtext\">자연스럽게 질문하면 의도를 해석해 실행합니다. <a href=\"#\" id=\"query_guide_link\" style=\"color:#7dd3fc;\">질의 가이드 보기 ↗</a></div>
          <div class=\"row\">
            <label for=\"nlp_text\">질문</label>
            <textarea id=\"nlp_text\">오프라인 호스트 보여줘</textarea>
          </div>
          <div class=\"guide-chips\" id=\"guide_examples\"></div>
          <div class=\"actions\">
            <button id=\"interpret\" class=\"secondary\">Interpret Text</button>
            <button id=\"run\">Run Query</button>
            <button id=\"download_csv\" class=\"ghost\">Download CSV</button>
          </div>
          <div id=\"interpretation_hint\"></div>
          <div class=\"status-line\" id=\"query_status\">catalog loading...</div>
        </section>
        <section class=\"card\">
          <h2>🔧 Structured Query Builder</h2>
          <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">
            <div class=\"row\"><label for=\"intent\">Intent</label><select id=\"intent\"></select></div>
            <div class=\"row\"><label for=\"time_range\">time_range</label><input id=\"time_range\" value=\"24h\" /></div>
            <div class=\"row\"><label for=\"host_id\">host_id</label><input id=\"host_id\" placeholder=\"예: host-1\" /></div>
            <div class=\"row\"><label for=\"hostname\">hostname</label><input id=\"hostname\" placeholder=\"예: mbp-01\" /></div>
            <div class=\"row\"><label for=\"severity\">severity</label><input id=\"severity\" placeholder=\"예: high,critical\" /></div>
            <div class=\"row\"><label for=\"source\">source</label><input id=\"source\" placeholder=\"예: wazuh\" /></div>
          </div>
          <div class=\"row\"><label for=\"filters\">filters (JSON)</label><textarea id=\"filters\">{}</textarea></div>
          <div class=\"actions\">
            <button id=\"reset\" class=\"secondary\">Reset</button>
            <button id=\"copy_payload\" class=\"ghost\">Copy Payload</button>
          </div>
        </section>
        <section class=\"card\">
          <h2>📨 Request / Response</h2>
          <div class=\"row\"><label for=\"payload\">Request Payload</label><textarea id=\"payload\">__PAYLOAD_JSON__</textarea></div>
          <div class=\"row\"><label>Response</label><div id=\"result\" class=\"query-result-area\"><span class=\"result-placeholder\">아직 실행 전입니다.</span></div></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 설정 ─────────────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_settings\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2>🖥️ 사용자 대시보드 설정</h2>
          <div class=\"subtext\">`/ui` 에서 사용자에게 보이는 카드와 섹션을 제어합니다. 재시작 시 초기값으로 돌아갑니다.</div>
          <div class=\"row\"><label for=\"docs_portal_url\">문서 / 포털 URL</label><input id=\"docs_portal_url\" value=\"__DOCS_PORTAL_URL__\" /></div>
          <div class=\"row\"><label>사용자 요약 카드</label><div class=\"toggle-grid\" id=\"user_dashboard_cards\"></div></div>
          <div class=\"row\"><label>사용자 섹션</label><div class=\"toggle-grid\" id=\"user_dashboard_sections\"></div></div>
          <div class=\"row\"><label>자빅스 자산 테이블 컬럼 표시</label><div class=\"toggle-grid\" id=\"user_dashboard_asset_columns\"></div></div>
          <div class=\"row\"><label>가이드 탭 노출 설정</label><div class=\"toggle-grid\" id=\"user_dashboard_guides\"></div></div>
          <div class=\"actions\">
            <button id=\"save_dashboard_preferences\" class=\"primary\">저장</button>
            <a href=\"/ui\">사용자 화면 열기 ↗</a>
          </div>
          <div class=\"status-line\" id=\"dashboard_preferences_status\">user dashboard settings loading...</div>
        </section>
        <section class=\"card\">
          <h2>🔔 Slack Webhook 관리</h2>
          <div class=\"subtext\">Critical 경보 발생 시 자동으로 알림을 전송할 Slack Incoming Webhook을 등록합니다.</div>
          <div id=\"webhooks_list\" class=\"list\" style=\"margin-bottom:12px\"><span class=\"empty\">로딩 중…</span></div>
          <div style=\"display:grid;grid-template-columns:1fr 1fr;gap:12px;\">
            <div class=\"row\"><label for=\"wh_name\">채널 이름 (식별용)</label><input id=\"wh_name\" placeholder=\"예: #soc-alerts\" /></div>
            <div class=\"row\"><label for=\"wh_url\">Webhook URL</label><input id=\"wh_url\" placeholder=\"https://hooks.slack.com/services/...\" /></div>
          </div>
          <div class=\"actions\">
            <button id=\"add_webhook\">추가</button>
            <button id=\"reload_webhooks\" class=\"secondary\">새로고침</button>
          </div>
          <div class=\"status-line\" id=\"webhook_status\"></div>
        </section>
        <section class=\"card\">
          <h2>📖 가이드 &amp; 메뉴얼 편집</h2>
          <div class=\"subtext\">사용자 UI에 표시되는 가이드 내용을 수정합니다. 마크다운 형식을 지원합니다.</div>
          <div class=\"row\"><label for=\"guide_edit_select\">가이드 선택</label>
            <select id=\"guide_edit_select\">
              <option value=\"zabbix_setup\">🖧 Zabbix 에이전트 설정</option>
              <option value=\"fleet_install\">🖥️ Fleet 에이전트 설치</option>
              <option value=\"isms_criteria\">📋 ISMS-P 심사 기준</option>
              <option value=\"iso27001_criteria\">🌐 ISO 27001 심사 기준</option>
              <option value=\"ldap_setup\">🔐 LDAP 통합 설정</option>
              <option value=\"incident_response\">🚨 인시던트 대응 절차</option>
              <option value=\"security_policy\">📜 보안 정책 가이드</option>
            </select>
          </div>
          <div class=\"row\"><label for=\"guide_edit_title\">제목</label><input id=\"guide_edit_title\" placeholder=\"가이드 제목\" /></div>
          <div class=\"row\"><label for=\"guide_edit_content\">내용 (마크다운)</label><textarea id=\"guide_edit_content\" style=\"min-height:280px;font-family:monospace;font-size:12px\"></textarea></div>
          <div class=\"actions\">
            <button id=\"guide_edit_load\" class=\"secondary\">불러오기</button>
            <button id=\"guide_edit_save\">저장</button>
          </div>
          <div class=\"status-line\" id=\"guide_edit_status\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 가입 요청 관리 ──────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_users\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2>🙋 가입 요청 관리</h2>
          <div class=\"subtext\">사용자가 제출한 가입 요청 목록입니다. 승인하면 운영자가 별도로 계정을 생성해야 합니다.</div>
          <div class=\"actions\" style=\"margin-bottom:12px\">
            <button id=\"reload_signup_requests\" class=\"secondary\">새로고침</button>
          </div>
          <div id=\"signup_requests_list\" class=\"list\"><span class=\"empty\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"signup_requests_status\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 변경 이력 ────────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_auditlog\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2>📝 자산 변경 이력</h2>
          <div class=\"subtext\">사용자가 수정한 담당자·카테고리 변경 이력입니다. 최신 순으로 표시됩니다.</div>
          <div style=\"display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px\">
            <input id=\"audit_filter_hostname\" placeholder=\"호스트명으로 검색\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:6px 10px;font-size:13px;width:180px\" />
            <select id=\"audit_filter_field\" style=\"background:#1e293b;border:1px solid #334155;color:#f1f5f9;border-radius:6px;padding:6px 10px;font-size:13px\">
              <option value=\"\">전체 항목</option>
              <option value=\"owner\">담당자</option>
              <option value=\"category\">카테고리</option>
            </select>
            <button id=\"audit_search_btn\" class=\"secondary\" style=\"padding:6px 14px\">🔍 검색</button>
            <button id=\"reload_audit_log\" class=\"secondary\" style=\"padding:6px 14px\">새로고침</button>
          </div>
          <div id=\"audit_log_list\" class=\"list\"><span class=\"empty\">로딩 중…</span></div>
          <div class=\"status-line\" id=\"audit_log_status\"></div>
        </section>
      </div>
    </div>

    <!-- ── Tab: 권한 관리 ───────────────────────────────────────────────── -->
    <div class=\"atab-panel\" id=\"atab_roleperm\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2>🔐 역할별 탭 권한 관리</h2>
          <div class=\"subtext\">각 계정 역할에서 보이는 탭을 설정합니다. 저장 후 다음 로그인부터 적용됩니다.</div>
          <div id=\"roleperm_list\" style=\"display:grid;gap:16px;margin-bottom:16px\"><span class=\"empty\">로딩 중…</span></div>
          <div class=\"actions\">
            <button id=\"save_roleperm\">저장</button>
            <button id=\"reload_roleperm\" class=\"secondary\">새로고침</button>
          </div>
          <div class=\"status-line\" id=\"roleperm_status\"></div>
        </section>
      </div>
    </div>
  </div>

  <!-- ── 어드민 하단 탭 바 (모바일 전용) ────────────────────────────────── -->
  <nav class=\"admin-bottom-nav\" id=\"admin_bottom_nav\">
    <button class=\"active\" data-atab=\"monitoring\" onclick=\"switchAdminTab('monitoring')\">
      <span class=\"bn-icon\">📊</span>모니터링
    </button>
    <button data-atab=\"assets\" onclick=\"switchAdminTab('assets')\">
      <span class=\"bn-icon\">👤</span>자산
    </button>
    <button data-atab=\"query\" onclick=\"switchAdminTab('query')\">
      <span class=\"bn-icon\">🔍</span>쿼리
    </button>
    <button data-atab=\"settings\" onclick=\"switchAdminTab('settings')\">
      <span class=\"bn-icon\">⚙️</span>설정
    </button>
    <button data-atab=\"users\" onclick=\"switchAdminTab('users')\">
      <span class=\"bn-icon\">🙋</span>가입
    </button>
    <button data-atab=\"auditlog\" onclick=\"switchAdminTab('auditlog')\">
      <span class=\"bn-icon\">📝</span>이력
    </button>
    <button data-atab=\"roleperm\" onclick=\"switchAdminTab('roleperm')\">
      <span class=\"bn-icon\">🔐</span>권한
    </button>
  </nav>

  <dialog id=\"query_guide_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3>Natural Language Query Guide</h3>
        <form method=\"dialog\"><button class=\"secondary\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"query_guide_message\">질문 의도를 정확히 해석하지 못하면 아래 예시를 눌러 다시 시작할 수 있습니다.</div>
      <div class=\"guide-list\" id=\"query_guide_list\"></div>
    </div>
  </dialog>

  <dialog id=\"overview_modal\">
    <div class=\"guide-dialog\">
      <div class=\"guide-dialog-head\">
        <h3 id=\"overview_modal_title\">Overview Details</h3>
        <form method=\"dialog\"><button class=\"secondary\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\" id=\"overview_modal_copy\">선택한 카드의 상세 목록입니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"overview_modal_body\"></div>
  </dialog>



  <script>
    const defaultPayload = __DEFAULT_PAYLOAD_JSON__;
    const guideExamples = __GUIDE_EXAMPLES__;
    const overviewCardsEl = document.getElementById('overview_cards');
    const sourceCoverageEl = document.getElementById('source_coverage');
    const latestStatusEl = document.getElementById('latest_status');
    const riskSummaryEl = document.getElementById('risk_summary');
    const recentActivityEl = document.getElementById('recent_activity');
    const quickQueriesEl = document.getElementById('quick_queries');
    const dashboardStatusEl = document.getElementById('dashboard_status');
    const queryStatusEl = document.getElementById('query_status');
    const intentEl = document.getElementById('intent');
    const nlpTextEl = document.getElementById('nlp_text');
    const timeRangeEl = document.getElementById('time_range');
    const hostIdEl = document.getElementById('host_id');
    const hostnameEl = document.getElementById('hostname');
    const severityEl = document.getElementById('severity');
    const sourceEl = document.getElementById('source');
    const filtersEl = document.getElementById('filters');
    const payloadEl = document.getElementById('payload');
    const resultEl = document.getElementById('result');
    const interpretationHintEl = document.getElementById('interpretation_hint');
    const guideExamplesEl = document.getElementById('guide_examples');
    const guideModalEl = document.getElementById('query_guide_modal');
    const guideMessageEl = document.getElementById('query_guide_message');
    const guideListEl = document.getElementById('query_guide_list');
    const overviewModalEl = document.getElementById('overview_modal');
    const overviewModalTitleEl = document.getElementById('overview_modal_title');
    const overviewModalCopyEl = document.getElementById('overview_modal_copy');
    const overviewModalBodyEl = document.getElementById('overview_modal_body');
    const docsPortalUrlEl = document.getElementById('docs_portal_url');
    const userDashboardCardsEl = document.getElementById('user_dashboard_cards');
    const userDashboardSectionsEl = document.getElementById('user_dashboard_sections');
    const userDashboardAssetColumnsEl = document.getElementById('user_dashboard_asset_columns');
    const userDashboardGuidesEl = document.getElementById('user_dashboard_guides');
    const dashboardPreferencesStatusEl = document.getElementById('dashboard_preferences_status');

    // Webhooks
    const webhooksListEl = document.getElementById('webhooks_list');
    const whNameEl = document.getElementById('wh_name');
    const whUrlEl = document.getElementById('wh_url');
    const webhookStatusEl = document.getElementById('webhook_status');


    const defaultUserDashboardPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const userDashboardCardLabels = __CARD_LABELS_JSON__;
    const userDashboardSectionLabels = __SECTION_LABELS_JSON__;
    const userDashboardAssetColumnLabels = __ASSET_COLUMN_LABELS_JSON__;
    const userDashboardGuideLabels = __GUIDE_LABELS_JSON__;
    let dashboardDetails = {};
    let userDashboardPreferences = JSON.parse(JSON.stringify(defaultUserDashboardPreferences));
    let queryMode = 'natural';

    function escapeHtml(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }

    function formatTime(value) {
      if (!value) return '-';
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return value;
      return date.toLocaleString('ko-KR', { hour12: false });
    }

    function renderPreferenceGroup(container, labels, values, prefix) {
      container.innerHTML = Object.entries(labels).map(([key, label]) => `
        <label class=\"toggle-item\" for=\"${prefix}_${escapeHtml(key)}\">
          <span>${escapeHtml(label)}</span>
          <input type=\"checkbox\" id=\"${prefix}_${escapeHtml(key)}\" data-pref-key=\"${escapeHtml(key)}\" ${values[key] !== false ? 'checked' : ''} />
        </label>
      `).join('');
    }

    function renderDashboardPreferences() {
      renderPreferenceGroup(userDashboardCardsEl, userDashboardCardLabels, userDashboardPreferences.cards || {}, 'user_card');
      renderPreferenceGroup(userDashboardSectionsEl, userDashboardSectionLabels, userDashboardPreferences.sections || {}, 'user_section');
      renderPreferenceGroup(userDashboardAssetColumnsEl, userDashboardAssetColumnLabels, userDashboardPreferences.asset_columns || {}, 'user_asset_col');
      renderPreferenceGroup(userDashboardGuidesEl, userDashboardGuideLabels, userDashboardPreferences.guides || {}, 'user_guide');
    }

    function readPreferenceGroup(container) {
      return Object.fromEntries(Array.from(container.querySelectorAll('[data-pref-key]')).map((input) => [input.dataset.prefKey, input.checked]));
    }

    async function loadDashboardPreferences() {
      dashboardPreferencesStatusEl.textContent = 'user dashboard settings loading...';
      try {
        const response = await fetch('/dashboard/preferences');
        const data = await response.json();
        if (!response.ok) {
          dashboardPreferencesStatusEl.textContent = `settings load failed: HTTP ${response.status}`;
          return;
        }
        docsPortalUrlEl.value = data.docs_url || '__DOCS_PORTAL_URL__';
        userDashboardPreferences = data.user_dashboard || JSON.parse(JSON.stringify(defaultUserDashboardPreferences));
        renderDashboardPreferences();
        dashboardPreferencesStatusEl.textContent = 'user dashboard settings loaded';
      } catch (error) {
        dashboardPreferencesStatusEl.textContent = `settings load failed: ${error.message}`;
      }
    }

    async function saveDashboardPreferences() {
      dashboardPreferencesStatusEl.textContent = 'saving user dashboard settings...';
      const payload = {
        docs_url: docsPortalUrlEl.value.trim() || '__DOCS_PORTAL_URL__',
        user_dashboard: {
          cards: readPreferenceGroup(userDashboardCardsEl),
          sections: readPreferenceGroup(userDashboardSectionsEl),
          asset_columns: readPreferenceGroup(userDashboardAssetColumnsEl),
          guides: readPreferenceGroup(userDashboardGuidesEl),
        },
      };
      try {
        const response = await fetch('/dashboard/preferences', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) {
          dashboardPreferencesStatusEl.textContent = `settings save failed: HTTP ${response.status}`;
          setResultError(JSON.stringify(data, null, 2));
          return;
        }
        docsPortalUrlEl.value = data.docs_url || payload.docs_url;
        userDashboardPreferences = data.user_dashboard || payload.user_dashboard;
        renderDashboardPreferences();
        dashboardPreferencesStatusEl.textContent = 'user dashboard settings saved';
      } catch (error) {
        dashboardPreferencesStatusEl.textContent = `settings save failed: ${error.message}`;
      }
    }

    function compactScope() {
      const scope = {
        time_range: timeRangeEl.value.trim() || '24h',
        host_id: hostIdEl.value.trim(),
        hostname: hostnameEl.value.trim(),
        severity: severityEl.value.trim(),
        source: sourceEl.value.trim(),
      };
      return Object.fromEntries(Object.entries(scope).filter(([, value]) => value));
    }

    function setQueryMode(mode) {
      queryMode = mode;
    }

    function populateFormFromPayload(payload, options = {}) {
      intentEl.value = payload.intent || defaultPayload.intent;
      const scope = payload.scope || {};
      timeRangeEl.value = scope.time_range || '24h';
      hostIdEl.value = scope.host_id || '';
      hostnameEl.value = scope.hostname || '';
      severityEl.value = scope.severity || '';
      sourceEl.value = scope.source || '';
      filtersEl.value = JSON.stringify(payload.filters || {}, null, 2);
      setQueryMode(options.mode || 'structured');
      syncPayload();
    }

    function syncPayload() {
      let filters = {};
      try {
        filters = filtersEl.value.trim() ? JSON.parse(filtersEl.value) : {};
      } catch (error) {
        queryStatusEl.textContent = `filters JSON 오류: ${error.message}`;
        return null;
      }
      const payload = { intent: intentEl.value, scope: compactScope(), filters };
      payloadEl.value = JSON.stringify(payload, null, 2);
      queryStatusEl.textContent = 'payload ready';
      return payload;
    }

    function normalizeGuideExamples(examples) {
      return Array.isArray(examples) && examples.length ? examples : guideExamples;
    }

    function renderGuideButtons(container, examples) {
      const items = normalizeGuideExamples(examples);
      container.innerHTML = items.map((example, index) => `
        <button class=\"ghost chip\" type=\"button\" data-guide-index=\"${index}\">${escapeHtml(example)}</button>
      `).join('');
      container.querySelectorAll('[data-guide-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const example = items[Number(button.dataset.guideIndex)] || '';
          nlpTextEl.value = example;
          setQueryMode('natural');
          queryStatusEl.textContent = `guide loaded: ${example}`;
          if (guideModalEl.open) {
            guideModalEl.close();
          }
        });
      });
    }

    function renderInterpretationHint(data) {
      const warnings = Array.isArray(data?.warnings) ? data.warnings : [];
      if (!warnings.length && data?.recognized !== false) {
        interpretationHintEl.innerHTML = '';
        return;
      }
      const tone = data?.recognized === false ? 'need-guide' : 'warning';
      const title = data?.recognized === false ? '이 질문은 다시 써주는 편이 좋습니다.' : '추가 힌트가 있습니다.';
      interpretationHintEl.innerHTML = `
        <div class=\"guide-banner ${escapeHtml(tone)}\">
          <strong>${escapeHtml(title)}</strong>
          ${warnings.map((warning) => `<div>${escapeHtml(warning)}</div>`).join('')}
        </div>
      `;
    }

    function openGuideModal(message, examples) {
      guideMessageEl.textContent = message || '질문 의도를 정확히 해석하지 못하면 아래 예시를 눌러 다시 시작할 수 있습니다.';
      renderGuideButtons(guideListEl, examples);
      if (guideModalEl.open) {
        return;
      }
      if (typeof guideModalEl.showModal === 'function') {
        guideModalEl.showModal();
        return;
      }
      guideModalEl.setAttribute('open', 'open');
    }

    function openOverviewModal(title, description, bodyHtml) {
      overviewModalTitleEl.textContent = title;
      overviewModalCopyEl.textContent = description;
      overviewModalBodyEl.innerHTML = bodyHtml;
      if (overviewModalEl.open) {
        return;
      }
      if (typeof overviewModalEl.showModal === 'function') {
        overviewModalEl.showModal();
        return;
      }
      overviewModalEl.setAttribute('open', 'open');
    }

    function renderDetailTable(columns, items, emptyText) {
      if (!items.length) {
        return `<div class="empty">${escapeHtml(emptyText)}</div>`;
      }
      return `
        <div class="table-wrap">
          <table>
            <thead>
              <tr>${columns.map((column) => `<th>${escapeHtml(column.label)}</th>`).join('')}</tr>
            </thead>
            <tbody>
              ${items.map((item) => `
                <tr>
                  ${columns.map((column) => `<td>${column.render(item)}</td>`).join('')}
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    function renderHostCell(item) {
      const name = item.source_url
        ? `<a href="${escapeHtml(item.source_url)}" target="_blank" rel="noopener noreferrer"><strong>${escapeHtml(item.hostname)}</strong></a>`
        : `<strong>${escapeHtml(item.hostname)}</strong>`;
      return `${name}<br /><span class="subtext">${escapeHtml(item.host_id)}</span>`;
    }

    function renderStatusDetailTable(items) {
      return renderDetailTable([
        { label: 'Host', render: (item) => renderHostCell(item) },
        { label: 'Status', render: (item) => `<span class="badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>` },
        { label: 'Risk', render: (item) => escapeHtml(item.risk_score) },
        { label: 'Last Seen', render: (item) => escapeHtml(formatTime(item.last_seen_at)) },
        { label: 'Last Alert', render: (item) => escapeHtml(formatTime(item.last_alert_at)) },
      ], items, '표시할 호스트가 없습니다.');
    }

    const UI_TRIAGE_COLORS = {new:'#f59e0b', acknowledged:'#38bdf8', investigating:'#a78bfa', closed:'#6ee7b7', false_positive:'#94a3b8'};
    let uiTriageData = {};
    async function loadUiTriageData() {
      try { const r = await fetch('/alerts'); const d = await r.json(); (d.alerts||[]).forEach(a => { uiTriageData[a.alert_id] = a.triage || {status:'pending'}; }); } catch(_) {}
    }

    function renderAlertDetailTable(items) {
      return renderDetailTable([
        { label: 'Time', render: (item) => escapeHtml(formatTime(item.observed_at)) },
        {
          label: 'Host',
          render: (item) => `<strong>${escapeHtml(item.hostname || '-')}</strong><br /><span class="subtext">${escapeHtml(item.host_id || '-')}</span>`,
        },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Severity', render: (item) => escapeHtml(item.severity) },
        { label: 'Message', render: (item) => escapeHtml(item.message) },
        {
          label: 'Triage',
          render: (item) => {
            const tr = uiTriageData[item.alert_id] || {status:'new'};
            const st = tr.status || 'new';
            const color = UI_TRIAGE_COLORS[st] || '#94a3b8';
            return `<span style="background:${color}22;color:${color};padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700">${escapeHtml(st)}</span>`;
          }
        },
      ], items, '최근 24시간 high / critical alert가 없습니다.');
    }

    function renderVulnerabilityDetailTable(items) {
      return renderDetailTable([
        { label: 'Detected', render: (item) => escapeHtml(formatTime(item.detected_at)) },
        {
          label: 'Host',
          render: (item) => `<strong>${escapeHtml(item.hostname || item.host_id)}</strong><br /><span class="subtext">${escapeHtml(item.host_id)}</span>`,
        },
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'CVE', render: (item) => escapeHtml(item.cve || '-') },
        { label: 'Package', render: (item) => escapeHtml(item.package_name || '-') },
      ], items, 'critical 취약점이 없습니다.');
    }

    function renderSourceDetailTable(items) {
      return renderDetailTable([
        { label: 'Source', render: (item) => escapeHtml(item.source) },
        { label: 'Hosts', render: (item) => escapeHtml(item.host_count) },
        { label: 'Status', render: (item) => escapeHtml(item.status) },
        { label: 'Last Sync', render: (item) => escapeHtml(formatTime(item.last_sync_at)) },
        { label: 'Message', render: (item) => escapeHtml(item.message || '-') },
      ], items, '표시할 source 상태가 없습니다.');
    }

    function renderIngestedDetailTable(items) {
      return renderDetailTable([
        { label: 'Entity', render: (item) => escapeHtml(item.entity_type) },
        { label: 'Count', render: (item) => escapeHtml(item.count) },
      ], items, '수집된 레코드가 없습니다.');
    }

    async function showOverviewDetail(key, label) {
      const items = Array.isArray(dashboardDetails[key]) ? dashboardDetails[key] : [];
      const renderers = {
        total_hosts: [renderStatusDetailTable, '현재 알려진 전체 호스트 목록입니다.'],
        offline_hosts: [renderStatusDetailTable, '즉시 확인이 필요한 offline 호스트 목록입니다.'],
        alerts_24h: [renderAlertDetailTable, '최근 24시간 high / critical alert 목록입니다.'],
        critical_vulns: [renderVulnerabilityDetailTable, '현재 critical 취약점 목록입니다.'],
        sources_reporting: [renderSourceDetailTable, '호스트를 보고 중인 source 목록입니다.'],
        sources_healthy: [renderSourceDetailTable, '최근 sync가 success인 collector 목록입니다.'],
        ingested_records: [renderIngestedDetailTable, '저장된 엔터티 타입별 레코드 수입니다.'],
      };
      if (key === 'alerts_24h') await loadUiTriageData();
      const [renderer, description] = renderers[key] || [renderIngestedDetailTable, '선택한 카드의 상세 데이터입니다.'];
      openOverviewModal(label, description, renderer(items));
    }

    function renderOverview(overview) {
      const cards = [
        ['total_hosts', 'Total Hosts', overview.total_hosts, `${overview.online_hosts} online / ${overview.unknown_hosts} unknown`],
        ['offline_hosts', 'Offline Hosts', overview.offline_hosts, '즉시 확인 대상'],
        ['alerts_24h', 'High Alerts 24h', overview.alerts_24h, 'high + critical'],
        ['critical_vulns', 'Critical Vulns', overview.critical_vulns, `high ${overview.high_vulns}`],
        ['sources_reporting', 'Sources Reporting', overview.sources_reporting, 'fleet / wazuh / zabbix / trivy / host_log'],
        ['sources_healthy', 'Healthy Collectors', overview.sources_healthy, '최근 sync success 기준'],
        ['ingested_records', 'Ingested Records', overview.ingested_records, 'alerts + vulns + queries + observations'],
      ];
      overviewCardsEl.innerHTML = cards.map(([key, label, value, sub]) => `
        <section class=\"card metric-card\" role=\"button\" tabindex=\"0\" data-overview-key=\"${escapeHtml(key)}\" data-overview-label=\"${escapeHtml(label)}\">
          <div class=\"metric-label\">${escapeHtml(label)}</div>
          <div class=\"metric-value\">${escapeHtml(value)}</div>
          <div class=\"metric-sub\">${escapeHtml(sub)}</div>
        </section>
      `).join('');
      overviewCardsEl.querySelectorAll('[data-overview-key]').forEach((card) => {
        const open = () => showOverviewDetail(card.dataset.overviewKey, card.dataset.overviewLabel || 'Overview');
        card.addEventListener('click', open);
        card.addEventListener('keydown', (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            open();
          }
        });
      });
    }

    function renderSourceCoverage(items) {
      if (!items.length) {
        sourceCoverageEl.innerHTML = '<div class=\"empty\">아직 연결된 source alias가 없습니다.</div>';
        return;
      }
      const statusToBadge = { success: 'online', error: 'offline', running: 'unknown', unknown: 'unknown' };
      sourceCoverageEl.innerHTML = items.map((item) => `
        <div class=\"coverage-item\">
          <div class=\"metric-label\">${escapeHtml(item.source.toUpperCase())}</div>
          <strong>${escapeHtml(item.host_count)}</strong>
          <div class=\"metric-sub\">호스트 · <span class=\"badge ${escapeHtml(statusToBadge[item.status] || 'unknown')}\">${escapeHtml(item.status)}</span></div>
          <div class=\"metric-sub\">last sync: ${escapeHtml(formatTime(item.last_sync_at))}</div>
          <div class=\"metric-sub\">records ${escapeHtml(item.records_collected)} / entities ${escapeHtml(item.entities_saved)}</div>
          <div class=\"status-line\">${escapeHtml(item.message || '아직 sync 기록 없음')}</div>
        </div>
      `).join('');
    }

    function renderLatestStatus(items) {
      if (!items.length) {
        latestStatusEl.innerHTML = '<div class=\"empty\">아직 호스트 데이터가 없습니다.</div>';
        return;
      }
      latestStatusEl.innerHTML = `
        <table>
          <thead>
            <tr><th>Host</th><th>Status</th><th>Risk</th><th>Last Seen</th><th>Last Alert</th></tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td>${renderHostCell(item)}</td>
                <td><span class=\"badge ${escapeHtml(item.status)}\">${escapeHtml(item.status)}</span></td>
                <td>${escapeHtml(item.risk_score)}</td>
                <td>${escapeHtml(formatTime(item.last_seen_at))}</td>
                <td>${escapeHtml(formatTime(item.last_alert_at))}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRiskSummary(items) {
      if (!items.length) {
        riskSummaryEl.innerHTML = '<div class=\"empty\">아직 위험 요약 데이터가 없습니다.</div>';
        return;
      }
      riskSummaryEl.innerHTML = `
        <table>
          <thead>
            <tr><th>Host</th><th>Risk</th><th>Alerts 24h</th><th>Critical</th><th>High</th><th>Vulns</th></tr>
          </thead>
          <tbody>
            ${items.map((item) => `
              <tr>
                <td><strong>${escapeHtml(item.hostname)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span></td>
                <td>${escapeHtml(item.risk_score)}</td>
                <td>${escapeHtml(item.alert_count_24h)}</td>
                <td>${escapeHtml(item.critical_alert_count_24h)}</td>
                <td>${escapeHtml(item.high_alert_count_24h)}</td>
                <td>${escapeHtml(item.vuln_count)} (C:${escapeHtml(item.critical_vuln_count)} / H:${escapeHtml(item.high_vuln_count)})</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    }

    function renderRecentActivity(items) {
      if (!items.length) {
        recentActivityEl.innerHTML = '<div class=\"empty\">아직 최근 활동 데이터가 없습니다.</div>';
        return;
      }
      recentActivityEl.innerHTML = items.map((item) => `
        <div class=\"list-item\">
          <div class=\"top\">
            <strong>${escapeHtml(item.summary)}</strong>
            <span class=\"meta\">${escapeHtml(formatTime(item.observed_at))}</span>
          </div>
          <div class=\"meta\">${escapeHtml(item.entity_type)} · ${escapeHtml(item.source)} · ${escapeHtml(item.host_id || '-')}</div>
        </div>
      `).join('');
    }

    function renderQuickQueries(items) {
      if (!items.length) {
        quickQueriesEl.innerHTML = '<div class=\"empty\">추천 질의가 없습니다.</div>';
        return;
      }
      quickQueriesEl.innerHTML = items.map((item, index) => `
        <button class=\"ghost\" type=\"button\" data-quick-index=\"${index}\">${escapeHtml(item.label)}</button>
      `).join('');
      quickQueriesEl.querySelectorAll('[data-quick-index]').forEach((button) => {
        button.addEventListener('click', () => {
          const item = items[Number(button.dataset.quickIndex)];
          nlpTextEl.value = item.text || '';
          populateFormFromPayload(item.payload || defaultPayload, { mode: 'natural' });
          queryStatusEl.textContent = `quick query loaded: ${item.label}`;
        });
      });
    }

    async function loadCatalog() {
      try {
        const response = await fetch('/catalog');
        const data = await response.json();
        const queries = data.queries || [];
        intentEl.innerHTML = queries.map((query) => `<option value=\"${query.intent}\">${escapeHtml(query.name)} (${escapeHtml(query.intent)})</option>`).join('');
        populateFormFromPayload(defaultPayload, { mode: 'natural' });
        queryStatusEl.textContent = `catalog loaded: ${queries.length} queries`;
      } catch (error) {
        queryStatusEl.textContent = `catalog load failed: ${error.message}`;
      }
    }

    async function loadDashboard() {
      dashboardStatusEl.textContent = 'dashboard loading...';
      try {
        const response = await fetch('/dashboard/summary');
        const data = await response.json();
        if (!response.ok) {
          dashboardStatusEl.textContent = `dashboard load failed: HTTP ${response.status}`;
          return;
        }
        dashboardDetails = data.overview_details || {};
        renderOverview(data.overview || {});
        renderSourceCoverage(data.source_coverage || []);
        renderLatestStatus(data.latest_status || []);
        renderRiskSummary(data.risk_summary || []);
        renderRecentActivity(data.recent_activity || []);
        renderQuickQueries(data.recommended_queries || []);
        dashboardStatusEl.textContent = `dashboard updated at ${formatTime(data.generated_at)}`;
      } catch (error) {
        dashboardStatusEl.textContent = `dashboard load failed: ${error.message}`;
      }
    }

    async function interpretNaturalText(options = {}) {
      const text = nlpTextEl.value.trim();
      if (!text) {
        queryStatusEl.textContent = '자연어 질문을 입력하세요.';
        renderInterpretationHint({ warnings: ['질문을 먼저 입력해 주세요.'], recognized: false });
        return null;
      }
      queryStatusEl.textContent = options.statusText || 'interpreting text...';
      try {
        const response = await fetch('/interpret', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text }),
        });
        const data = await response.json();
        if (!response.ok) {
          queryStatusEl.textContent = `interpret failed: HTTP ${response.status}`;
          return null;
        }
        renderInterpretationHint(data);
        const examples = normalizeGuideExamples(data.guide_examples);
        renderGuideButtons(guideExamplesEl, examples);
        if (data.recognized === false) {
          if (options.openGuideOnUnrecognized !== false) {
            openGuideModal((data.warnings || [])[0], examples);
          }
          queryStatusEl.textContent = 'interpret needs guide examples';
          return { recognized: false, data };
        }
        const payload = { intent: data.intent, scope: data.scope || {}, filters: data.filters || {} };
        populateFormFromPayload(payload, { mode: 'natural' });
        queryStatusEl.textContent = (data.warnings || []).length ? 'interpret completed with hints' : 'interpret completed';
        return { recognized: true, data, payload };
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `interpret failed: ${error.message}`;
        return null;
      }
    }

    async function resolvePayloadForRun() {
      if (queryMode === 'natural' && nlpTextEl.value.trim()) {
        const interpreted = await interpretNaturalText({ statusText: 'interpreting text before query...' });
        if (!interpreted || interpreted.recognized === false) {
          return null;
        }
        return interpreted.payload;
      }
      return syncPayload();
    }

    function extractFilename(response) {
      const disposition = response.headers.get('content-disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/i);
      return match ? match[1] : 'mori-query.csv';
    }

    function queryResultCount(data) {
      if (typeof data?.meta?.count === 'number') {
        return data.meta.count;
      }
      return Array.isArray(data?.evidence) ? data.evidence.length : 0;
    }

    function hasQueryResults(data) {
      return queryResultCount(data) > 0;
    }

    function showNoResultsAlert(data) {
      const message = typeof data?.summary === 'string' && data.summary.trim()
        ? data.summary.trim()
        : '조회 결과가 없습니다.';
      window.alert(message);
    }

    function downloadTextFile(text, filename, mimeType = 'text/csv;charset=utf-8') {
      const blob = new Blob([text], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    }

    function setResultText(msg) {
      resultEl.innerHTML = `<span class=\"result-placeholder\">${escapeHtml(String(msg))}</span>`;
    }

    function setResultError(msg) {
      resultEl.innerHTML = `<div class=\"result-error\">${escapeHtml(String(msg))}</div>`;
    }

    function renderQueryResult(data) {
      const evidence = Array.isArray(data?.evidence) ? data.evidence : [];
      const summary = typeof data?.summary === 'string' ? data.summary : '';
      const count = typeof data?.meta?.count === 'number' ? data.meta.count : evidence.length;

      let html = '';
      if (summary) {
        html += `<div class=\"result-summary\">${escapeHtml(summary)}</div>`;
      }
      if (!evidence.length) {
        html += `<span class=\"result-placeholder\">조회 결과가 없습니다.</span>`;
        resultEl.innerHTML = html;
        return;
      }

      const badgeClass = (src) => {
        const s = (src || '').toLowerCase();
        if (s.includes('wazuh')) return 'wazuh';
        if (s.includes('zabbix')) return 'zabbix';
        if (s.includes('fleet')) return 'fleet';
        if (s.includes('trivy')) return 'trivy';
        if (s.includes('host')) return 'hosts';
        return '';
      };

      html += `
        <table class=\"result-table\">
          <thead><tr>
            <th>#</th><th>Source</th><th>Summary</th><th>Record ID</th>
          </tr></thead>
          <tbody>
            ${evidence.map((ev, i) => `
              <tr>
                <td>${i + 1}</td>
                <td><span class=\"result-badge ${escapeHtml(badgeClass(ev.source))}\">${escapeHtml(ev.source || '-')}</span></td>
                <td>${escapeHtml(ev.summary || ev.raw_ref || '-')}</td>
                <td><span class=\"mono\" style=\"font-size:11px;color:#64748b;\">${escapeHtml(ev.record_id || '-')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div class=\"status-line\" style=\"margin-top:8px;\">총 ${escapeHtml(String(count))}건 조회됨</div>`;
      resultEl.innerHTML = html;
    }

    async function runQuery() {
      const payload = await resolvePayloadForRun();
      if (!payload) return;
      queryStatusEl.textContent = 'query running...';
      try {
        const response = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            const data = await response.json();
            setResultError(JSON.stringify(data, null, 2));
          } else {
            setResultError(await response.text());
          }
          queryStatusEl.textContent = `query failed: HTTP ${response.status}`;
          return;
        }
        const data = await response.json();
        if (!hasQueryResults(data)) {
          setResultText('조회 결과가 없습니다.');
          queryStatusEl.textContent = 'query returned no results';
          showNoResultsAlert(data);
          return;
        }
        renderQueryResult(data);
        queryStatusEl.textContent = 'query completed';
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `query failed: ${error.message}`;
      }
    }

    async function downloadCsv() {
      const payload = await resolvePayloadForRun();
      if (!payload) return;
      queryStatusEl.textContent = 'checking query results before csv download...';
      try {
        const previewResponse = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const previewData = await previewResponse.json();
        if (!previewResponse.ok) {
          setResultError(JSON.stringify(previewData, null, 2));
          queryStatusEl.textContent = `query failed: HTTP ${previewResponse.status}`;
          return;
        }
        if (!hasQueryResults(previewData)) {
          setResultText('조회 결과가 없습니다.');
          queryStatusEl.textContent = 'csv download skipped: no results';
          showNoResultsAlert(previewData);
          return;
        }

        const response = await fetch('/query?format=csv', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('application/json')) {
            const data = await response.json();
            setResultError(JSON.stringify(data, null, 2));
          } else {
            setResultError(await response.text());
          }
          queryStatusEl.textContent = `csv download failed: HTTP ${response.status}`;
          return;
        }
        const csvText = await response.text();
        const filename = extractFilename(response);
        downloadTextFile(csvText, filename, response.headers.get('content-type') || 'text/csv;charset=utf-8');
        renderQueryResult(previewData);
        queryStatusEl.textContent = `csv download started: ${filename}`;
      } catch (error) {
        setResultError(error.stack || String(error));
        queryStatusEl.textContent = `csv download failed: ${error.message}`;
      }
    }

    async function interpretText() {
      await interpretNaturalText();
    }

    function resetForm() {
      nlpTextEl.value = '오프라인 호스트 보여줘';
      populateFormFromPayload(defaultPayload, { mode: 'natural' });
      setResultText('아직 실행 전입니다.');
      interpretationHintEl.innerHTML = '';
      queryStatusEl.textContent = 'form reset';
    }

    async function copyPayload() {
      try {
        await navigator.clipboard.writeText(payloadEl.value);
        queryStatusEl.textContent = 'payload copied';
      } catch (error) {
        queryStatusEl.textContent = `copy failed: ${error.message}`;
      }
    }

    nlpTextEl.addEventListener('input', () => setQueryMode('natural'));
    [intentEl, timeRangeEl, hostIdEl, hostnameEl, severityEl, sourceEl].forEach((element) => {
      const handleStructuredInput = () => {
        setQueryMode('structured');
        syncPayload();
      };
      element.addEventListener('input', handleStructuredInput);
      element.addEventListener('change', handleStructuredInput);
    });
    filtersEl.addEventListener('input', () => {
      setQueryMode('structured');
      syncPayload();
    });
    document.getElementById('interpret').addEventListener('click', interpretText);
    document.getElementById('run').addEventListener('click', runQuery);
    document.getElementById('download_csv').addEventListener('click', downloadCsv);
    document.getElementById('reset').addEventListener('click', resetForm);
    document.getElementById('copy_payload').addEventListener('click', copyPayload);
    document.getElementById('query_guide').addEventListener('click', () => openGuideModal('', guideExamples));
    document.getElementById('refresh_dashboard').addEventListener('click', loadDashboard);
    document.getElementById('save_dashboard_preferences').addEventListener('click', saveDashboardPreferences);
    filtersEl.value = JSON.stringify(defaultPayload.filters, null, 2);
    renderGuideButtons(guideExamplesEl, guideExamples);

    // ── Asset Owners ───────────────────────────────────────────────────────
    const ownersListEl = document.getElementById('owners_list');
    const ownerStatusEl = document.getElementById('owner_status');
    const ownHostnameEl = document.getElementById('own_hostname');
    const ownOwnerEl = document.getElementById('own_owner');
    const ownEmailEl = document.getElementById('own_email');
    const ownTeamEl = document.getElementById('own_team');

    async function loadOwners() {
      ownersListEl.innerHTML = '<span class=\"empty\">로딩 중…</span>';
      try {
        const res = await fetch('/assets/owners');
        const data = await res.json();
        const list = data.owners || [];
        if (!list.length) { ownersListEl.innerHTML = '<span class=\"empty\">등록된 담당자 없음</span>'; return; }
        ownersListEl.innerHTML = list.map(o => `
          <div style=\"display:flex;justify-content:space-between;align-items:center;padding:6px 8px;border-bottom:1px solid #1e293b;font-size:13px\">
            <div>
              <strong style=\"color:#e2e8f0\">${escapeHtml(o.hostname)}</strong>
              <span style=\"color:#a3e635;margin-left:8px\">${escapeHtml(o.owner||'-')}</span>
              ${o.team ? `<span style=\"color:#64748b;margin-left:6px\">(${escapeHtml(o.team)})</span>` : ''}
              ${o.email ? `<span style=\"color:#64748b;font-size:11px;margin-left:6px\">${escapeHtml(o.email)}</span>` : ''}
            </div>
            <button onclick=\"deleteOwner('${escapeHtml(o.hostname)}')\" style=\"background:#7f1d1d;border:none;color:#fca5a5;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px\">삭제</button>
          </div>`).join('');
      } catch(e) { ownersListEl.innerHTML = `<span class=\"empty\">오류: ${escapeHtml(e.message)}</span>`; }
    }

    async function deleteOwner(hostname) {
      try {
        await fetch(`/assets/owners/${encodeURIComponent(hostname)}`, {method:'DELETE'});
        await loadOwners();
      } catch(e) { ownerStatusEl.textContent = `삭제 실패: ${e.message}`; }
    }

    document.getElementById('add_owner').addEventListener('click', async () => {
      const hostname = ownHostnameEl.value.trim();
      if (!hostname) { ownerStatusEl.textContent = '호스트명을 입력하세요.'; return; }
      ownerStatusEl.textContent = '저장 중…';
      try {
        const res = await fetch('/assets/owners', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({hostname, owner: ownOwnerEl.value.trim(), email: ownEmailEl.value.trim(), team: ownTeamEl.value.trim()})
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        ownHostnameEl.value = ''; ownOwnerEl.value = ''; ownEmailEl.value = ''; ownTeamEl.value = '';
        ownerStatusEl.textContent = '저장 완료 ✓';
        await loadOwners();
      } catch(e) { ownerStatusEl.textContent = `오류: ${e.message}`; }
    });
    document.getElementById('reload_owners').addEventListener('click', loadOwners);

    // ── Webhooks ───────────────────────────────────────────────────────────
    async function loadWebhooks() {
      webhooksListEl.innerHTML = '<span class=\"empty\">로딩 중…</span>';
      try {
        const res = await fetch('/webhooks');
        const data = await res.json();
        const whs = data.webhooks || [];
        if (!whs.length) { webhooksListEl.innerHTML = '<span class=\"empty\">등록된 webhook 없음</span>'; return; }
        webhooksListEl.innerHTML = whs.map(w => `
          <div class=\"list-item\">
            <div class=\"top\"><strong>${escapeHtml(w.name)}</strong><span class=\"meta\">${escapeHtml(w.created_at||'')}</span></div>
            <div class=\"meta mono\" style=\"word-break:break-all\">${escapeHtml(w.url)}</div>
            <div style=\"margin-top:8px;display:flex;gap:8px\">
              <button class=\"secondary\" style=\"width:auto;padding:4px 12px;font-size:12px\" onclick=\"testWebhook('${escapeHtml(w.id)}', this)\">테스트</button>
              <button class=\"ghost\" style=\"width:auto;padding:4px 12px;font-size:12px;border-color:#ef4444;color:#fca5a5\" onclick=\"deleteWebhook('${escapeHtml(w.id)}', this)\">삭제</button>
            </div>
          </div>
        `).join('');
      } catch(e) { webhooksListEl.innerHTML = `<span class=\"empty\">오류: ${escapeHtml(e.message)}</span>`; }
    }
    async function testWebhook(id, btn) {
      btn.textContent = '전송 중…'; btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}/test`, {method:'POST'});
        btn.textContent = res.ok ? '✓ 성공' : '✗ 실패';
      } catch(e) { btn.textContent = '✗ 오류'; }
      setTimeout(() => { btn.textContent = '테스트'; btn.disabled = false; }, 2000);
    }
    async function deleteWebhook(id, btn) {
      if (!confirm('이 webhook을 삭제하시겠습니까?')) return;
      btn.textContent = '삭제 중…'; btn.disabled = true;
      try {
        const res = await fetch(`/webhooks/${id}`, {method:'DELETE'});
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        await loadWebhooks();
      } catch(e) { webhookStatusEl.textContent = `삭제 실패: ${e.message}`; btn.disabled = false; btn.textContent = '삭제'; }
    }
    document.getElementById('add_webhook').addEventListener('click', async () => {
      const url = whUrlEl.value.trim();
      if (!url) { webhookStatusEl.textContent = 'URL을 입력하세요.'; return; }
      webhookStatusEl.textContent = '추가 중…';
      try {
        const res = await fetch('/webhooks', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name: whNameEl.value.trim() || 'Slack Webhook', url})});
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        whNameEl.value = ''; whUrlEl.value = '';
        webhookStatusEl.textContent = '추가 완료 ✓';
        await loadWebhooks();
      } catch(e) { webhookStatusEl.textContent = `오류: ${e.message}`; }
    });
    document.getElementById('reload_webhooks').addEventListener('click', loadWebhooks);

    // ── Guide Editor ───────────────────────────────────────────────────────
    const guideEditSelectEl = document.getElementById('guide_edit_select');
    const guideEditTitleEl = document.getElementById('guide_edit_title');
    const guideEditContentEl = document.getElementById('guide_edit_content');
    const guideEditStatusEl = document.getElementById('guide_edit_status');

    async function loadGuideForEdit(guideId) {
      guideEditStatusEl.textContent = '불러오는 중…';
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`);
        if (!res.ok) throw new Error(res.status);
        const g = await res.json();
        guideEditTitleEl.value = g.title || '';
        guideEditContentEl.value = g.content || '';
        guideEditStatusEl.textContent = g.updated_at ? `마지막 저장: ${g.updated_at.slice(0,19).replace('T',' ')}` : '(기본 내용)';
      } catch(e) { guideEditStatusEl.textContent = `불러오기 실패: ${e.message}`; }
    }

    document.getElementById('guide_edit_load').addEventListener('click', () => {
      loadGuideForEdit(guideEditSelectEl.value);
    });
    guideEditSelectEl.addEventListener('change', () => {
      loadGuideForEdit(guideEditSelectEl.value);
    });
    document.getElementById('guide_edit_save').addEventListener('click', async () => {
      const guideId = guideEditSelectEl.value;
      const title = guideEditTitleEl.value.trim();
      const content = guideEditContentEl.value;
      if (!title) { guideEditStatusEl.textContent = '제목을 입력하세요.'; return; }
      guideEditStatusEl.textContent = '저장 중…';
      try {
        const res = await fetch(`/guides/${encodeURIComponent(guideId)}`, {
          method: 'PUT', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({title, content}),
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        guideEditStatusEl.textContent = '저장 완료 ✓';
      } catch(e) { guideEditStatusEl.textContent = `오류: ${e.message}`; }
    });

    /* ── Admin Tab switching ──────────────────────────────── */
    function switchAdminTab(tab) {
      document.querySelectorAll('.atab-panel').forEach(el => el.classList.remove('active'));
      // 상단 탭 + 하단 탭 모두 active 동기화
      document.querySelectorAll('#admin_tabs_nav button, #admin_bottom_nav button').forEach(btn => btn.classList.remove('active'));
      const panel = document.getElementById('atab_' + tab);
      if (panel) panel.classList.add('active');
      document.querySelectorAll('[data-atab="' + tab + '"]').forEach(btn => btn.classList.add('active'));
      window.scrollTo({ top: 0, behavior: 'smooth' });
      if (tab === 'auditlog') loadAuditLog();
    }

    // ── Signup Requests ────────────────────────────────────────────────────
    const signupListEl = document.getElementById('signup_requests_list');
    const signupStatusEl = document.getElementById('signup_requests_status');

    async function loadSignupRequests() {
      if (!signupListEl) return;
      signupListEl.innerHTML = '<span class="empty">로딩 중…</span>';
      try {
        const res = await fetch('/auth/signup-requests');
        const data = await res.json();
        const reqs = data.requests || [];
        if (reqs.length === 0) {
          signupListEl.innerHTML = '<span class="empty">가입 요청이 없습니다.</span>';
          return;
        }
        const statusBadge = s => ({pending:'🟡 대기중', approved:'🟢 승인됨', rejected:'🔴 거절됨'}[s] || s);
        signupListEl.innerHTML = reqs.map(r => `
          <div class="owner-row" style="border:1px solid #1e3a5f;border-radius:10px;padding:12px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
              <div>
                <strong>${r.name}</strong> <span style="color:#94a3b8;font-size:12px;">${r.email}</span>
                ${r.department ? `<span style="color:#64748b;font-size:12px;margin-left:6px;">[${r.department}]</span>` : ''}
                <div style="font-size:12px;color:#94a3b8;margin-top:4px;">${r.reason || '(사유 없음)'}</div>
                <div style="font-size:11px;color:#475569;margin-top:4px;">요청일: ${r.created_at || '-'}${r.reviewed_at ? ' / 처리일: ' + r.reviewed_at : ''}</div>
              </div>
              <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
                <span>${statusBadge(r.status)}</span>
                ${r.status === 'pending' ? `
                  <button class="secondary" style="font-size:12px;padding:4px 10px" onclick="handleSignupRequest('${r.id}','approved')">승인</button>
                  <button class="danger" style="font-size:12px;padding:4px 10px" onclick="handleSignupRequest('${r.id}','rejected')">거절</button>
                ` : ''}
              </div>
            </div>
          </div>`).join('');
      } catch(e) {
        signupListEl.innerHTML = `<span class="empty">오류: ${e.message}</span>`;
      }
    }

    async function handleSignupRequest(id, status) {
      if (!signupStatusEl) return;
      signupStatusEl.textContent = '처리 중…';
      try {
        const res = await fetch(`/auth/signup-requests/${id}`, {
          method: 'PATCH',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({status})
        });
        if (!res.ok) throw new Error((await res.json()).detail || res.status);
        signupStatusEl.textContent = status === 'approved' ? '✅ 승인 완료' : '❌ 거절 완료';
        await loadSignupRequests();
      } catch(e) {
        signupStatusEl.textContent = `오류: ${e.message}`;
      }
    }

    if (document.getElementById('reload_signup_requests')) {
      document.getElementById('reload_signup_requests').addEventListener('click', loadSignupRequests);
    }

    // ── Asset Audit Log ────────────────────────────────────────────────────
    const auditLogListEl = document.getElementById('audit_log_list');
    const auditLogStatusEl = document.getElementById('audit_log_status');

    async function loadAuditLog() {
      if (!auditLogListEl) return;
      auditLogListEl.innerHTML = '<span class="empty">로딩 중…</span>';
      const hostname = (document.getElementById('audit_filter_hostname')?.value || '').trim();
      const field = document.getElementById('audit_filter_field')?.value || '';
      let url = '/admin/audit-log';
      const params = new URLSearchParams();
      if (hostname) params.set('hostname', hostname);
      if (field) params.set('field', field);
      if (params.toString()) url += '?' + params.toString();
      try {
        const res = await fetch(url);
        if (!res.ok) { auditLogListEl.innerHTML = '<span class="empty">로드 실패</span>'; return; }
        const data = await res.json();
        const logs = data.audit_log || [];
        if (!logs.length) { auditLogListEl.innerHTML = '<span class="empty">변경 이력 없음</span>'; return; }
        const FIELD_LABEL = { owner: '담당자', category: '카테고리' };
        auditLogListEl.innerHTML = `<table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="background:#0f2035;">
            <th style="padding:8px;color:#7dd3fc;text-align:left">시각</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">호스트</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">항목</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">이전 값</th>
            <th style="padding:8px;color:#a3e635;text-align:left">변경 값</th>
            <th style="padding:8px;color:#7dd3fc;text-align:left">변경자</th>
          </tr></thead>
          <tbody>
          ${logs.map(l => `<tr style="border-bottom:1px solid #1e293b;">
            <td style="padding:7px 8px;color:#64748b;white-space:nowrap">${escapeHtml(formatTime(l.changed_at))}</td>
            <td style="padding:7px 8px;color:#e2e8f0;font-weight:600">${escapeHtml(l.hostname)}</td>
            <td style="padding:7px 8px;color:#fbbf24">${escapeHtml(FIELD_LABEL[l.field] || l.field)}</td>
            <td style="padding:7px 8px;color:#94a3b8">${escapeHtml(l.old_value || '-')}</td>
            <td style="padding:7px 8px;color:#a3e635">${escapeHtml(l.new_value || '-')}</td>
            <td style="padding:7px 8px;color:#93c5fd">${escapeHtml(l.changed_by)}</td>
          </tr>`).join('')}
          </tbody></table>`;
        if (auditLogStatusEl) auditLogStatusEl.textContent = `총 ${data.total}건`;
      } catch(e) {
        auditLogListEl.innerHTML = `<span class="empty">오류: ${escapeHtml(e.message)}</span>`;
      }
    }

    if (document.getElementById('reload_audit_log')) {
      document.getElementById('reload_audit_log').addEventListener('click', loadAuditLog);
    }
    if (document.getElementById('audit_search_btn')) {
      document.getElementById('audit_search_btn').addEventListener('click', loadAuditLog);
    }

    // ── Role Permissions ─────────────────────────────────────────────────────
    const ROLE_PERM_TABS = [
      { id: 'dashboard', label: '📊 대시보드' },
      { id: 'triage', label: '🚨 Alert Triage' },
      { id: 'incidents', label: '📋 인시던트' },
      { id: 'assets', label: '📡 자산 현황' },
      { id: 'guides', label: '📖 가이드' },
    ];
    const ROLE_PERM_ROLES = [
      { key: 'security', label: '보안담당자 (security)' },
      { key: 'monitor', label: '서버모니터 (moniter)' },
      { key: 'user', label: '일반사용자 (user)' },
    ];

    async function loadRolePermissions() {
      const listEl = document.getElementById('roleperm_list');
      const statusEl = document.getElementById('roleperm_status');
      if (!listEl) return;
      listEl.innerHTML = '<span class=\"empty\">로딩 중…</span>';
      try {
        const res = await fetch('/admin/role-permissions');
        if (!res.ok) throw new Error(res.status);
        const data = await res.json();
        const perms = data.permissions || {};
        listEl.innerHTML = ROLE_PERM_ROLES.map(role => {
          const allowed = perms[role.key] || [];
          const checks = ROLE_PERM_TABS.map(tab => {
            const checked = allowed.includes(tab.id) ? 'checked' : '';
            return `<label style=\"display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid #223148;border-radius:8px;background:#0b1220;cursor:pointer\">
              <input type=\"checkbox\" data-role=\"${role.key}\" data-tab=\"${tab.id}\" ${checked} style=\"width:auto;margin:0\" />
              <span style=\"font-size:13px\">${tab.label}</span>
            </label>`;
          }).join('');
          return `<div style=\"background:#0f172a;border:1px solid #233046;border-radius:12px;padding:14px\">
            <div style=\"font-weight:700;color:#38bdf8;margin-bottom:10px\">${escapeHtml(role.label)}</div>
            <div style=\"display:flex;flex-wrap:wrap;gap:8px\">${checks}</div>
          </div>`;
        }).join('');
      } catch(e) {
        listEl.innerHTML = `<span class=\"empty\">로드 실패: ${escapeHtml(e.message)}</span>`;
      }
    }

    if (document.getElementById('reload_roleperm')) {
      document.getElementById('reload_roleperm').addEventListener('click', loadRolePermissions);
    }
    if (document.getElementById('save_roleperm')) {
      document.getElementById('save_roleperm').addEventListener('click', async () => {
        const statusEl = document.getElementById('roleperm_status');
        const checkboxes = document.querySelectorAll('#roleperm_list input[type=checkbox]');
        const payload = {};
        checkboxes.forEach(cb => {
          const role = cb.dataset.role;
          const tab = cb.dataset.tab;
          if (!payload[role]) payload[role] = [];
          if (cb.checked) payload[role].push(tab);
        });
        statusEl.textContent = '저장 중...';
        try {
          const res = await fetch('/admin/role-permissions', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
          });
          if (!res.ok) throw new Error(await res.text());
          statusEl.style.color = '#86efac';
          statusEl.textContent = '✅ 권한이 저장되었습니다. 해당 역할 사용자 재로그인 후 적용됩니다.';
        } catch(e) {
          statusEl.style.color = '#fca5a5';
          statusEl.textContent = `오류: ${e.message}`;
        }
      });
    }

    async function initialize() {
      await loadDashboardPreferences();
      await loadCatalog();
      await loadDashboard();
      await loadOwners();
      await loadWebhooks();
      await loadGuideForEdit(guideEditSelectEl.value);
      await loadSignupRequests();
      await loadRolePermissions();
    }

    initialize();
  </script>
</body>
</html>"""
    return (
        html.replace("__PAYLOAD_JSON__", payload_json)
        .replace("__DEFAULT_PAYLOAD_JSON__", default_payload_json)
        .replace("__GUIDE_EXAMPLES__", guide_examples_json)
        .replace("__DOCS_PORTAL_URL__", docs_url)
        .replace("__USER_DASHBOARD_PREFS_JSON__", default_preferences_json)
        .replace("__CARD_LABELS_JSON__", card_labels_json)
        .replace("__SECTION_LABELS_JSON__", section_labels_json)
        .replace("__ASSET_COLUMN_LABELS_JSON__", asset_column_labels_json)
        .replace("__GUIDE_LABELS_JSON__", guide_labels_json)
    )


def _source_coverage(store: InMemoryQueryStore) -> list[dict[str, Any]]:
    ordered_sources = ["fleet", "wazuh", "zabbix", "trivy", "host_log"]
    sources = {source: set() for source in ordered_sources}
    for alias in store.host_aliases:
        sources.setdefault(alias.source, set()).add(alias.host_id)
    sync_map = {item.source: item for item in store.source_syncs}
    for source in sync_map:
        sources.setdefault(source, set())
    rows: list[dict[str, Any]] = []
    for source, host_ids in sources.items():
        sync = sync_map.get(source)
        rows.append(
            {
                "source": source,
                "host_count": len(host_ids),
                "status": sync.status if sync else "unknown",
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


def _alert_detail_rows(alerts: list[Any], hostnames: Mapping[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "alert_id": alert.alert_id,
            "host_id": alert.host_id,
            "hostname": hostnames.get(alert.host_id or "", alert.host_id or "-"),
            "source": alert.source,
            "severity": alert.severity,
            "message": alert.message,
            "observed_at": _isoformat(alert.observed_at),
        }
        for alert in sorted(alerts, key=lambda item: item.observed_at, reverse=True)
    ]


def _critical_vuln_detail_rows(store: InMemoryQueryStore, hostnames: Mapping[str, str]) -> list[dict[str, Any]]:
    critical_vulns = [vuln for vuln in store.vulnerabilities if vuln.severity == "critical"]
    return [
        {
            "vuln_id": vuln.vuln_id,
            "host_id": vuln.host_id,
            "hostname": hostnames.get(vuln.host_id, vuln.host_id),
            "source": vuln.source,
            "cve": vuln.cve,
            "package_name": vuln.package_name,
            "detected_at": _isoformat(vuln.detected_at),
        }
        for vuln in sorted(critical_vulns, key=lambda item: item.detected_at, reverse=True)
    ]


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