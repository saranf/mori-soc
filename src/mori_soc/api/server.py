from __future__ import annotations

import json
import os
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
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    FastAPI = None
    HTTPException = None
    HTMLResponse = None
    RedirectResponse = None
    StreamingResponse = None


DEFAULT_UI_PAYLOAD = {
    "intent": "offline_hosts",
    "scope": {"time_range": "24h"},
    "filters": {},
}

DOCS_PORTAL_URL = os.getenv("MORI_DOCS_PORTAL_URL", "http://mori.rmstudio.co.kr:37854/")
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
}


def create_query_service(store: InMemoryQueryStore | None = None) -> QueryService:
    return QueryService(store or InMemoryQueryStore())


def create_query_service_from_env() -> QueryService:
    backend = os.getenv("MORI_QUERY_BACKEND", "memory").strip().lower()
    if backend == "memory":
        return create_query_service()
    if backend == "postgres":
        database_url = os.getenv("MORI_DATABASE_URL")
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


def _default_dashboard_preferences() -> dict[str, Any]:
    return {
        "docs_url": DOCS_PORTAL_URL,
        "user_dashboard": {
            "cards": dict(DEFAULT_USER_DASHBOARD_PREFERENCES["cards"]),
            "sections": dict(DEFAULT_USER_DASHBOARD_PREFERENCES["sections"]),
        },
    }


def _dashboard_preferences_response(preferences: Mapping[str, Any]) -> dict[str, Any]:
    docs_url = preferences.get("docs_url") if isinstance(preferences.get("docs_url"), str) else DOCS_PORTAL_URL
    user_dashboard = preferences.get("user_dashboard") if isinstance(preferences.get("user_dashboard"), Mapping) else {}
    cards = user_dashboard.get("cards") if isinstance(user_dashboard.get("cards"), Mapping) else {}
    sections = user_dashboard.get("sections") if isinstance(user_dashboard.get("sections"), Mapping) else {}
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
        },
        "card_labels": dict(USER_DASHBOARD_CARD_LABELS),
        "section_labels": dict(USER_DASHBOARD_SECTION_LABELS),
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
        },
    }


def create_app(service: QueryService | None = None, service_factory=None) -> Any:
    if FastAPI is None or HTTPException is None:
        raise RuntimeError(
            "FastAPI is not installed. Install fastapi and uvicorn to run MVC 1 HTTP server."
        )

    app = FastAPI(title="MORI SOC Query API", version="0.1.0")
    dashboard_preferences = _default_dashboard_preferences()

    def get_query_service() -> QueryService:
        if service is not None:
            return service
        if service_factory is not None:
            return service_factory()
        return create_query_service()

    @app.get("/", include_in_schema=False)
    def index() -> Any:
        return RedirectResponse(url="/ui", status_code=307)

    @app.get("/ui", include_in_schema=False, response_class=HTMLResponse)
    def ui() -> str:
        return render_user_dashboard_html(dashboard_preferences["docs_url"])

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

    return app


def create_app_from_env() -> Any:
    return create_app(service_factory=create_query_service_from_env)


def _query_csv_filename(intent: str) -> str:
    safe_intent = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in intent).strip("-")
    if not safe_intent:
        safe_intent = "query"
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"mori-query-{safe_intent}-{timestamp}.csv"


def render_user_dashboard_html(docs_url: str = DOCS_PORTAL_URL) -> str:
    default_preferences_json = json.dumps(DEFAULT_USER_DASHBOARD_PREFERENCES, ensure_ascii=False)
    card_labels_json = json.dumps(USER_DASHBOARD_CARD_LABELS, ensure_ascii=False)
    section_labels_json = json.dumps(USER_DASHBOARD_SECTION_LABELS, ensure_ascii=False)
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
    @media (max-width: 960px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 720px) {
      .hero { flex-direction: column; }
      .metrics, .coverage { grid-template-columns: 1fr; }
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
        </div>
      </div>
      <div class=\"top-actions\">
        <button id=\"refresh_dashboard\" type=\"button\">Refresh Dashboard</button>
      </div>
    </section>

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

        <section class=\"card\" id=\"nlq_section\">
          <h2>자연어 질의 (NLQ)</h2>
          <div class=\"subtext\">자연스럽게 질문하거나 아래 예시 형식으로 입력하면 더 정확하게 해석합니다. <a href=\"#\" id=\"nlq_guide_link\" style=\"color:#7dd3fc;\">질의 가이드 보기 ↗</a></div>
          <textarea id=\"nlq_textarea\" rows=\"3\" style=\"width:100%;box-sizing:border-box;background:#0b1220;color:#e5e7eb;border:1px solid #334155;border-radius:8px;padding:10px;font-size:14px;resize:vertical;\" placeholder=\"예: 오프라인 호스트 보여줘 / 최근 24시간 wazuh high alert 요약\"></textarea>
          <div id=\"nlq_interpret_result\" style=\"margin:8px 0;color:#7dd3fc;font-size:13px;\"></div>
          <div style=\"display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;\">
            <button type=\"button\" id=\"nlq_interpret_btn\" style=\"padding:8px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\">Interpret</button>
            <button type=\"button\" id=\"nlq_run_btn\" style=\"padding:8px 16px;background:#1d4ed8;color:#fff;border:none;border-radius:999px;cursor:pointer;\">Run Query</button>
            <button type=\"button\" id=\"nlq_csv_btn\" style=\"display:none;padding:8px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\">Download CSV</button>
          </div>
          <div id=\"nlq_result_area\" style=\"margin-top:12px;\"></div>
        </section>
      </div>
    </div>

    <div class=\"status-line\" id=\"dashboard_status\">dashboard loading...</div>
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
        <form method=\"dialog\"><button type=\"submit\" style=\"padding:6px 16px;background:#0f172a;color:#cfe3ff;border:1px solid #334155;border-radius:999px;cursor:pointer;\">닫기</button></form>
      </div>
      <div class=\"guide-dialog-copy\">아래 예시를 클릭하면 입력창에 바로 채워집니다.</div>
    </div>
    <div class=\"dialog-body\" id=\"nlq_guide_list\" style=\"display:flex;flex-wrap:wrap;gap:8px;padding:16px;\"></div>
  </dialog>

  <script>
    const defaultPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const cardLabels = __CARD_LABELS_JSON__;
    const sectionLabels = __SECTION_LABELS_JSON__;
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
    let userPreferences = JSON.parse(JSON.stringify(defaultPreferences));
    let dashboardDetails = {};

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

    nlqRunBtn.addEventListener('click', async () => {
      nlqResultArea.textContent = '실행 중...';
      const result = await runNlqQuery('json');
      if (!result) { nlqResultArea.textContent = ''; return; }
      const evidence = result.evidence || [];
      if (!evidence.length) {
        nlqResultArea.textContent = '';
        showInfoModal('결과 없음', '조건에 맞는 데이터가 없습니다.');
        nlqCsvBtn.style.display = 'none';
        return;
      }
      nlqCsvBtn.style.display = '';
      nlqResultArea.innerHTML = `<pre style=\"background:#0b1220;border:1px solid #233046;border-radius:8px;padding:12px;overflow:auto;font-size:12px;color:#e5e7eb;max-height:320px;\">${escapeHtml(JSON.stringify(result, null, 2))}</pre>`;
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

    async function initialize() {
      await loadPreferences();
      await loadDashboard();
    }

    initialize();
  </script>
</body>
</html>"""
    return (
        html.replace("__DOCS_PORTAL_URL__", docs_url)
        .replace("__USER_DASHBOARD_PREFS_JSON__", default_preferences_json)
        .replace("__CARD_LABELS_JSON__", card_labels_json)
        .replace("__SECTION_LABELS_JSON__", section_labels_json)
        .replace("__NLQ_GUIDE_EXAMPLES__", nlq_guide_examples_json)
    )


def render_query_console_html(docs_url: str = DOCS_PORTAL_URL) -> str:
    payload_json = json.dumps(DEFAULT_UI_PAYLOAD, indent=2, ensure_ascii=False)
    default_payload_json = json.dumps(DEFAULT_UI_PAYLOAD, ensure_ascii=False)
    guide_examples_json = json.dumps(list(QUERY_GUIDE_EXAMPLES), ensure_ascii=False)
    default_preferences_json = json.dumps(DEFAULT_USER_DASHBOARD_PREFERENCES, ensure_ascii=False)
    card_labels_json = json.dumps(USER_DASHBOARD_CARD_LABELS, ensure_ascii=False)
    section_labels_json = json.dumps(USER_DASHBOARD_SECTION_LABELS, ensure_ascii=False)
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
    button { border: none; background: #2563eb; font-weight: 700; cursor: pointer; }
    button.secondary { background: #334155; }
    button.ghost { background: #172033; border: 1px solid #334155; }
    .actions { display: grid; gap: 10px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .actions a, .top-actions a { display: inline-flex; align-items: center; justify-content: center; border-radius: 12px; border: 1px solid #334155; background: #172033; color: #e5e7eb; padding: 10px 12px; text-decoration: none; font-weight: 700; }
    .quick-actions { display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .status-line { color: #94a3b8; font-size: 13px; margin-top: 8px; }
    .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
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
    @media (max-width: 1240px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .layout { grid-template-columns: 1fr; }
    }
    @media (max-width: 720px) {
      .hero { flex-direction: column; }
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .coverage, .quick-actions, .actions { grid-template-columns: 1fr; }
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
      </div>
    </section>

    <section class=\"metrics\" id=\"overview_cards\"></section>

    <div class=\"layout\">
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

      <aside class=\"stack\">
        <section class=\"card\">
          <h2>User Dashboard Controls</h2>
          <div class=\"subtext\">`18000/ui` 에서 사용자에게 보이는 카드와 섹션을 제어합니다. 현재 설정은 애플리케이션 메모리에 저장되므로 프로세스 재시작 시 초기값으로 돌아갑니다.</div>
          <div class=\"row\">
            <label for=\"docs_portal_url\">문서 / 포털 URL</label>
            <input id=\"docs_portal_url\" value=\"__DOCS_PORTAL_URL__\" />
          </div>
          <div class=\"row\">
            <label>User Overview Cards</label>
            <div class=\"toggle-grid\" id=\"user_dashboard_cards\"></div>
          </div>
          <div class=\"row\">
            <label>User Sections</label>
            <div class=\"toggle-grid\" id=\"user_dashboard_sections\"></div>
          </div>
          <div class=\"actions\">
            <button id=\"save_dashboard_preferences\">Save User View</button>
            <a href=\"/ui\">Open User View</a>
          </div>
          <div class=\"status-line\" id=\"dashboard_preferences_status\">user dashboard settings loading...</div>
        </section>

        <section class=\"card\">
          <h2>Quick Actions</h2>
          <div class=\"subtext\">자주 쓰는 질의를 클릭하면 아래 폼에 바로 채워집니다.</div>
          <div class=\"quick-actions\" id=\"quick_queries\"></div>
        </section>

        <section class=\"card\">
          <h2>Natural Language Query</h2>
          <div class=\"subtext\">자연스럽게 질문해도 되며, Run Query는 마지막으로 수정한 입력 영역(자연어/구조화)을 우선 사용합니다. CSV는 원할 때만 별도로 다운로드합니다.</div>
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
          <h2>Structured Query Builder</h2>
          <div class=\"row\">
            <label for=\"intent\">Intent</label>
            <select id=\"intent\"></select>
          </div>
          <div class=\"row\">
            <label for=\"time_range\">time_range</label>
            <input id=\"time_range\" value=\"24h\" />
          </div>
          <div class=\"row\">
            <label for=\"host_id\">host_id</label>
            <input id=\"host_id\" placeholder=\"예: host-1\" />
          </div>
          <div class=\"row\">
            <label for=\"hostname\">hostname</label>
            <input id=\"hostname\" placeholder=\"예: mbp-01\" />
          </div>
          <div class=\"row\">
            <label for=\"severity\">severity</label>
            <input id=\"severity\" placeholder=\"예: high,critical\" />
          </div>
          <div class=\"row\">
            <label for=\"source\">source</label>
            <input id=\"source\" placeholder=\"예: wazuh\" />
          </div>
          <div class=\"row\">
            <label for=\"filters\">filters (JSON)</label>
            <textarea id=\"filters\">{}</textarea>
          </div>
          <div class=\"actions\">
            <button id=\"reset\" class=\"secondary\">Reset</button>
            <button id=\"copy_payload\" class=\"ghost\">Copy Payload</button>
          </div>
        </section>

        <section class=\"card\">
          <h2>Request / Response</h2>
          <div class=\"row\">
            <label for=\"payload\">Request Payload</label>
            <textarea id=\"payload\">__PAYLOAD_JSON__</textarea>
          </div>
          <div class=\"row\">
            <label for=\"result\">Response</label>
            <textarea id=\"result\" class=\"mono\" readonly>아직 실행 전입니다.</textarea>
          </div>
        </section>
      </aside>
    </div>
  </div>

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
    const dashboardPreferencesStatusEl = document.getElementById('dashboard_preferences_status');
    const defaultUserDashboardPreferences = __USER_DASHBOARD_PREFS_JSON__;
    const userDashboardCardLabels = __CARD_LABELS_JSON__;
    const userDashboardSectionLabels = __SECTION_LABELS_JSON__;
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
          resultEl.value = JSON.stringify(data, null, 2);
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

    function showOverviewDetail(key, label) {
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
        resultEl.value = JSON.stringify(data, null, 2);
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
        resultEl.value = error.stack || String(error);
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
            resultEl.value = JSON.stringify(data, null, 2);
          } else {
            resultEl.value = await response.text();
          }
          queryStatusEl.textContent = `query failed: HTTP ${response.status}`;
          return;
        }
        const data = await response.json();
        if (!hasQueryResults(data)) {
          resultEl.value = '조회 결과가 없습니다.';
          queryStatusEl.textContent = 'query returned no results';
          showNoResultsAlert(data);
          return;
        }
        resultEl.value = JSON.stringify(data, null, 2);
        queryStatusEl.textContent = 'query completed';
      } catch (error) {
        resultEl.value = error.stack || String(error);
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
          resultEl.value = JSON.stringify(previewData, null, 2);
          queryStatusEl.textContent = `query failed: HTTP ${previewResponse.status}`;
          return;
        }
        if (!hasQueryResults(previewData)) {
          resultEl.value = '조회 결과가 없습니다.';
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
            resultEl.value = JSON.stringify(data, null, 2);
          } else {
            resultEl.value = await response.text();
          }
          queryStatusEl.textContent = `csv download failed: HTTP ${response.status}`;
          return;
        }
        const csvText = await response.text();
        const filename = extractFilename(response);
        downloadTextFile(csvText, filename, response.headers.get('content-type') || 'text/csv;charset=utf-8');
        resultEl.value = JSON.stringify(previewData, null, 2);
        queryStatusEl.textContent = `csv download started: ${filename}`;
      } catch (error) {
        resultEl.value = error.stack || String(error);
        queryStatusEl.textContent = `csv download failed: ${error.message}`;
      }
    }

    async function interpretText() {
      await interpretNaturalText();
    }

    function resetForm() {
      nlpTextEl.value = '오프라인 호스트 보여줘';
      populateFormFromPayload(defaultPayload, { mode: 'natural' });
      resultEl.value = '아직 실행 전입니다.';
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

    async function initialize() {
      await loadDashboardPreferences();
      await loadCatalog();
      await loadDashboard();
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