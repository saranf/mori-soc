from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.services.intent_parser import NaturalLanguageQueryParser
from mori_soc.services.query_catalog import PHASE1_QUERY_CATALOG
from mori_soc.services.query_service import InMemoryQueryStore, QueryService

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
    return f"""<!doctype html>
<html lang=\"ko\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>MORI Query Console</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0b1220; color: #e5e7eb; }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 48px; }}
    .grid {{ display: grid; gap: 16px; grid-template-columns: 320px 1fr; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 14px; padding: 18px; }}
    .row {{ display: grid; gap: 10px; margin-bottom: 12px; }}
    label {{ font-size: 14px; color: #cbd5e1; }}
    input, select, textarea, button {{ width: 100%; box-sizing: border-box; border-radius: 10px; border: 1px solid #475569; background: #0f172a; color: #e5e7eb; padding: 10px 12px; }}
    textarea {{ min-height: 220px; resize: vertical; font-family: ui-monospace, SFMono-Regular, monospace; }}
    button {{ background: #2563eb; border: none; font-weight: 700; cursor: pointer; }}
    button.secondary {{ background: #334155; }}
    .actions {{ display: grid; gap: 10px; grid-template-columns: 1fr 1fr; }}
    .links {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }}
    .links a {{ color: #93c5fd; text-decoration: none; }}
    .muted {{ color: #94a3b8; font-size: 14px; }}
    pre {{ margin: 0; white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, SFMono-Regular, monospace; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h1>MORI Query Console</h1>
    <p class=\"muted\">브라우저에서 바로 intent 기반 질의를 테스트하는 최소 UI입니다. 상세 API 문서는 <code>/docs</code>를 사용하세요.</p>
    <div class=\"links\">
      <a href=\"/docs\" target=\"_blank\" rel=\"noreferrer\">Swagger Docs</a>
      <a href=\"/catalog\" target=\"_blank\" rel=\"noreferrer\">Query Catalog JSON</a>
      <a href=\"/health\" target=\"_blank\" rel=\"noreferrer\">Health JSON</a>
    </div>
    <div class=\"grid\">
      <section class=\"card\">
        <div class=\"row\">
          <label for=\"nlp_text\">자연어 질문</label>
          <textarea id=\"nlp_text\">오프라인 호스트 보여줘</textarea>
        </div>
        <div class=\"actions\">
          <button id=\"interpret\" class=\"secondary\">Interpret Text</button>
          <button id=\"run\">Run Query</button>
        </div>
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
          <label for=\"filters\">filters(JSON)</label>
          <textarea id=\"filters\">{{}}</textarea>
        </div>
        <div class=\"actions\"><button id=\"reset\" class=\"secondary\">Reset</button></div>
      </section>
      <section class=\"card\">
        <div class=\"row\">
          <label for=\"payload\">Request Payload</label>
          <textarea id=\"payload\">{payload_json}</textarea>
        </div>
        <div class=\"row\">
          <label for=\"result\">Response</label>
          <textarea id=\"result\" readonly>아직 실행 전입니다.</textarea>
        </div>
        <div class=\"muted\" id=\"status\">catalog loading...</div>
      </section>
    </div>
  </div>
  <script>
    const defaultPayload = {json.dumps(DEFAULT_UI_PAYLOAD, ensure_ascii=False)};
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
    const statusEl = document.getElementById('status');

    function compactScope() {{
      const scope = {{
        time_range: timeRangeEl.value.trim() || '24h',
        host_id: hostIdEl.value.trim(),
        hostname: hostnameEl.value.trim(),
        severity: severityEl.value.trim(),
        source: sourceEl.value.trim(),
      }};
      return Object.fromEntries(Object.entries(scope).filter(([, value]) => value));
    }}

    function syncPayload() {{
      let filters = {{}};
      try {{
        filters = filtersEl.value.trim() ? JSON.parse(filtersEl.value) : {{}};
      }} catch (error) {{
        statusEl.textContent = `filters JSON 오류: ${{error.message}}`;
        return null;
      }}
      const payload = {{ intent: intentEl.value, scope: compactScope(), filters }};
      payloadEl.value = JSON.stringify(payload, null, 2);
      statusEl.textContent = 'payload ready';
      return payload;
    }}

    async function loadCatalog() {{
      try {{
        const response = await fetch('/catalog');
        const data = await response.json();
        const queries = data.queries || [];
        intentEl.innerHTML = queries.map((query) => `<option value=\"${{query.intent}}\">${{query.name}} (${{query.intent}})</option>`).join('');
        if (queries.length) {{
          intentEl.value = defaultPayload.intent;
        }}
        syncPayload();
        statusEl.textContent = `catalog loaded: ${{queries.length}} queries`;
      }} catch (error) {{
        statusEl.textContent = `catalog load failed: ${{error.message}}`;
      }}
    }}

    async function runQuery() {{
      const payload = syncPayload();
      if (!payload) return;
      statusEl.textContent = 'query running...';
      try {{
        const response = await fetch('/query', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(payload),
        }});
        const data = await response.json();
        resultEl.value = JSON.stringify(data, null, 2);
        statusEl.textContent = response.ok ? 'query completed' : `query failed: HTTP ${{response.status}}`;
      }} catch (error) {{
        resultEl.value = error.stack || String(error);
        statusEl.textContent = `query failed: ${{error.message}}`;
      }}
    }}

    function resetForm() {{
      nlpTextEl.value = '오프라인 호스트 보여줘';
      intentEl.value = defaultPayload.intent;
      timeRangeEl.value = defaultPayload.scope.time_range;
      hostIdEl.value = '';
      hostnameEl.value = '';
      severityEl.value = '';
      sourceEl.value = '';
      filtersEl.value = JSON.stringify(defaultPayload.filters, null, 2);
      resultEl.value = '아직 실행 전입니다.';
      syncPayload();
    }}

    async function interpretText() {{
      const text = nlpTextEl.value.trim();
      if (!text) {{
        statusEl.textContent = '자연어 질문을 입력하세요.';
        return;
      }}
      statusEl.textContent = 'interpreting text...';
      try {{
        const response = await fetch('/interpret', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ text }}),
        }});
        const data = await response.json();
        if (!response.ok) {{
          resultEl.value = JSON.stringify(data, null, 2);
          statusEl.textContent = `interpret failed: HTTP ${{response.status}}`;
          return;
        }}
        intentEl.value = data.intent || defaultPayload.intent;
        timeRangeEl.value = (data.scope && data.scope.time_range) || '24h';
        hostIdEl.value = (data.scope && data.scope.host_id) || '';
        hostnameEl.value = (data.scope && data.scope.hostname) || '';
        severityEl.value = (data.scope && data.scope.severity) || '';
        sourceEl.value = (data.scope && data.scope.source) || '';
        filtersEl.value = JSON.stringify(data.filters || {{}}, null, 2);
        payloadEl.value = JSON.stringify({{ intent: data.intent, scope: data.scope || {{}}, filters: data.filters || {{}} }}, null, 2);
        resultEl.value = JSON.stringify(data, null, 2);
        statusEl.textContent = 'interpret completed';
      }} catch (error) {{
        resultEl.value = error.stack || String(error);
        statusEl.textContent = `interpret failed: ${{error.message}}`;
      }}
    }}

    [intentEl, timeRangeEl, hostIdEl, hostnameEl, severityEl, sourceEl].forEach((element) => element.addEventListener('input', syncPayload));
    filtersEl.addEventListener('input', syncPayload);
    document.getElementById('interpret').addEventListener('click', interpretText);
    document.getElementById('run').addEventListener('click', runQuery);
    document.getElementById('reset').addEventListener('click', resetForm);
    filtersEl.value = JSON.stringify(defaultPayload.filters, null, 2);
    loadCatalog();
  </script>
</body>
</html>"""


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("query scope values must be strings")
    value = value.strip()
    return value or None


__all__ = [
    "DEFAULT_UI_PAYLOAD",
    "build_query_request",
    "create_app",
    "create_app_from_env",
    "create_query_service",
    "create_query_service_from_env",
    "interpret_query_text",
    "render_query_console_html",
]