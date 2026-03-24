from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.services.intent_parser import QUERY_GUIDE_EXAMPLES, NaturalLanguageQueryParser
from mori_soc.services.query_catalog import PHASE1_QUERY_CATALOG
from mori_soc.services.query_service import InMemoryQueryStore, QueryService
from mori_soc.services.views import host_risk_summary_view, latest_host_status_view

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, RedirectResponse
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    FastAPI = None
    HTTPException = None
    HTMLResponse = None
    RedirectResponse = None


DEFAULT_UI_PAYLOAD = {
    "intent": "offline_hosts",
    "scope": {"time_range": "24h"},
    "filters": {},
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

    alerts_24h = [
        alert for alert in store.alerts if alert.observed_at >= since_24h and alert.severity in {"high", "critical"}
    ]
    overview = {
        "total_hosts": len(store.hosts),
        "online_hosts": Counter(host.status for host in store.hosts).get("online", 0),
        "offline_hosts": Counter(host.status for host in store.hosts).get("offline", 0),
        "unknown_hosts": Counter(host.status for host in store.hosts).get("unknown", 0),
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
        "source_coverage": source_coverage,
        "latest_status": [
            {
                "host_id": row.host_id,
                "hostname": row.hostname,
                "status": row.status,
                "risk_score": row.risk_score,
                "last_seen_at": _isoformat(row.last_seen_at),
                "last_alert_at": _isoformat(row.last_alert_at),
                "last_observation_at": _isoformat(row.last_observation_at),
            }
            for row in status_rows[:8]
        ],
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


def create_app(service: QueryService | None = None, service_factory=None) -> Any:
    if FastAPI is None or HTTPException is None:
        raise RuntimeError(
            "FastAPI is not installed. Install fastapi and uvicorn to run MVC 1 HTTP server."
        )

    app = FastAPI(title="MORI SOC Query API", version="0.1.0")

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
        return render_query_console_html()

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

    @app.post("/query")
    def query(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            request = build_query_request(payload)
            response = get_query_service().execute(request)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"query execution failed: {exc}") from exc
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


def render_query_console_html() -> str:
    payload_json = json.dumps(DEFAULT_UI_PAYLOAD, indent=2, ensure_ascii=False)
    default_payload_json = json.dumps(DEFAULT_UI_PAYLOAD, ensure_ascii=False)
    guide_examples_json = json.dumps(list(QUERY_GUIDE_EXAMPLES), ensure_ascii=False)
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
    .quick-actions { display: grid; gap: 8px; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .status-line { color: #94a3b8; font-size: 13px; margin-top: 8px; }
    .mono { font-family: ui-monospace, SFMono-Regular, monospace; }
    .top-actions button, .guide-chips button, .guide-list button { width: auto; }
    .guide-chips, .guide-list { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
    .chip { padding: 8px 12px; border-radius: 999px; }
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
        <h1>MORI Security Dashboard</h1>
        <p>Fleet · Wazuh · Zabbix 데이터를 공통 모델로 묶어 상태/위험/최근 활동을 한눈에 보고, 같은 화면에서 자연어 질의까지 바로 실행하는 운영 대시보드입니다.</p>
        <div class=\"links\">
          <a href=\"/docs\" target=\"_blank\" rel=\"noreferrer\">Swagger Docs</a>
          <a href=\"/catalog\" target=\"_blank\" rel=\"noreferrer\">Query Catalog JSON</a>
          <a href=\"/health\" target=\"_blank\" rel=\"noreferrer\">Health JSON</a>
          <a href=\"/dashboard/summary\" target=\"_blank\" rel=\"noreferrer\">Dashboard JSON</a>
        </div>
      </div>
      <div class=\"top-actions\">
        <button id=\"query_guide\" class=\"ghost\">Query Guide</button>
        <button id=\"refresh_dashboard\" class=\"ghost\">Refresh Dashboard</button>
      </div>
    </section>

    <section class=\"metrics\" id=\"overview_cards\"></section>

    <div class=\"layout\">
      <div class=\"stack\">
        <section class=\"card\">
          <h2>Source Coverage</h2>
          <div class=\"subtext\">Fleet / Wazuh / Zabbix / host logs 기준으로 현재 MORI에 연결된 호스트 수입니다.</div>
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
          <h2>Quick Actions</h2>
          <div class=\"subtext\">자주 쓰는 질의를 클릭하면 아래 폼에 바로 채워집니다.</div>
          <div class=\"quick-actions\" id=\"quick_queries\"></div>
        </section>

        <section class=\"card\">
          <h2>Natural Language Query</h2>
          <div class=\"subtext\">자연스럽게 질문해도 되지만, 애매하면 아래 예시 형식으로 다시 물어보면 더 정확하게 해석합니다.</div>
          <div class=\"row\">
            <label for=\"nlp_text\">질문</label>
            <textarea id=\"nlp_text\">오프라인 호스트 보여줘</textarea>
          </div>
          <div class=\"guide-chips\" id=\"guide_examples\"></div>
          <div class=\"actions\">
            <button id=\"interpret\" class=\"secondary\">Interpret Text</button>
            <button id=\"run\">Run Query</button>
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

    function populateFormFromPayload(payload) {
      intentEl.value = payload.intent || defaultPayload.intent;
      const scope = payload.scope || {};
      timeRangeEl.value = scope.time_range || '24h';
      hostIdEl.value = scope.host_id || '';
      hostnameEl.value = scope.hostname || '';
      severityEl.value = scope.severity || '';
      sourceEl.value = scope.source || '';
      filtersEl.value = JSON.stringify(payload.filters || {}, null, 2);
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
      if (typeof guideModalEl.showModal === 'function') {
        guideModalEl.showModal();
        return;
      }
      guideModalEl.setAttribute('open', 'open');
    }

    function renderOverview(overview) {
      const cards = [
        ['Total Hosts', overview.total_hosts, `${overview.online_hosts} online / ${overview.unknown_hosts} unknown`],
        ['Offline Hosts', overview.offline_hosts, '즉시 확인 대상'],
        ['High Alerts 24h', overview.alerts_24h, 'high + critical'],
        ['Critical Vulns', overview.critical_vulns, `high ${overview.high_vulns}`],
        ['Sources Reporting', overview.sources_reporting, 'fleet / wazuh / zabbix / host_log'],
        ['Healthy Collectors', overview.sources_healthy, '최근 sync success 기준'],
        ['Ingested Records', overview.ingested_records, 'alerts + vulns + queries + observations'],
      ];
      overviewCardsEl.innerHTML = cards.map(([label, value, sub]) => `
        <section class=\"card\">
          <div class=\"metric-label\">${escapeHtml(label)}</div>
          <div class=\"metric-value\">${escapeHtml(value)}</div>
          <div class=\"metric-sub\">${escapeHtml(sub)}</div>
        </section>
      `).join('');
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
                <td><strong>${escapeHtml(item.hostname)}</strong><br /><span class=\"subtext\">${escapeHtml(item.host_id)}</span></td>
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
          populateFormFromPayload(item.payload || defaultPayload);
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
        populateFormFromPayload(defaultPayload);
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

    async function runQuery() {
      const payload = syncPayload();
      if (!payload) return;
      queryStatusEl.textContent = 'query running...';
      try {
        const response = await fetch('/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        resultEl.value = JSON.stringify(data, null, 2);
        queryStatusEl.textContent = response.ok ? 'query completed' : `query failed: HTTP ${response.status}`;
      } catch (error) {
        resultEl.value = error.stack || String(error);
        queryStatusEl.textContent = `query failed: ${error.message}`;
      }
    }

    async function interpretText() {
      const text = nlpTextEl.value.trim();
      if (!text) {
        queryStatusEl.textContent = '자연어 질문을 입력하세요.';
        renderInterpretationHint({ warnings: ['질문을 먼저 입력해 주세요.'], recognized: false });
        return;
      }
      queryStatusEl.textContent = 'interpreting text...';
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
          return;
        }
        renderInterpretationHint(data);
        const examples = normalizeGuideExamples(data.guide_examples);
        renderGuideButtons(guideExamplesEl, examples);
        if (data.recognized === false) {
          openGuideModal((data.warnings || [])[0], examples);
          queryStatusEl.textContent = 'interpret needs guide examples';
          return;
        }
        populateFormFromPayload({ intent: data.intent, scope: data.scope || {}, filters: data.filters || {} });
        queryStatusEl.textContent = (data.warnings || []).length ? 'interpret completed with hints' : 'interpret completed';
      } catch (error) {
        resultEl.value = error.stack || String(error);
        queryStatusEl.textContent = `interpret failed: ${error.message}`;
      }
    }

    function resetForm() {
      nlpTextEl.value = '오프라인 호스트 보여줘';
      populateFormFromPayload(defaultPayload);
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

    [intentEl, timeRangeEl, hostIdEl, hostnameEl, severityEl, sourceEl].forEach((element) => element.addEventListener('input', syncPayload));
    filtersEl.addEventListener('input', syncPayload);
    document.getElementById('interpret').addEventListener('click', interpretText);
    document.getElementById('run').addEventListener('click', runQuery);
    document.getElementById('reset').addEventListener('click', resetForm);
    document.getElementById('copy_payload').addEventListener('click', copyPayload);
    document.getElementById('query_guide').addEventListener('click', () => openGuideModal('', guideExamples));
    document.getElementById('refresh_dashboard').addEventListener('click', loadDashboard);
    filtersEl.value = JSON.stringify(defaultPayload.filters, null, 2);
    renderGuideButtons(guideExamplesEl, guideExamples);

    async function initialize() {
      await loadCatalog();
      await loadDashboard();
    }

    initialize();
  </script>
</body>
</html>"""
    return html.replace("__PAYLOAD_JSON__", payload_json).replace("__DEFAULT_PAYLOAD_JSON__", default_payload_json).replace("__GUIDE_EXAMPLES__", guide_examples_json)


def _source_coverage(store: InMemoryQueryStore) -> list[dict[str, Any]]:
    sources = {"fleet": set(), "wazuh": set(), "zabbix": set(), "host_log": set()}
    for alias in store.host_aliases:
        sources.setdefault(alias.source, set()).add(alias.host_id)
    sync_map = {item.source: item for item in store.source_syncs}
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
]