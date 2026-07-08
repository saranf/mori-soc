"""Page / health / catalog routes (Task J-4b13).

Registers the HTML entry pages (``/``, ``/ui``, ``/admin``), the ``/health``
diagnostics endpoint, and the ``/catalog`` query listing on ``ctx.app``. Handler
bodies are verbatim from the original ``create_app`` closures; only the unpacking
preamble (binding the ``get_query_service`` helper + ``insecure_defaults`` from
:class:`RouteContext`) is new. ``admin_dashboard_preferences`` is read through
``ctx`` so the dashboard-prefs handlers' rebind stays visible here.
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from mori_soc.services.query_catalog import PHASE1_QUERY_CATALOG
from mori_soc.api.templates import (
    render_user_dashboard_html,
    render_query_console_html,
    FLEET_UI_URL,
    ZABBIX_UI_URL,
    WAZUH_UI_URL,
    GRAFANA_UI_URL,
)
from mori_soc.api.payloads import _source_coverage
from mori_soc.api.routes.context import RouteContext


def register_pages(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    insecure_defaults = ctx.insecure_defaults

    @app.get("/", include_in_schema=False)
    def index() -> Any:
        return RedirectResponse(url="/ui", status_code=307)

    @app.get("/ui", include_in_schema=False, response_class=HTMLResponse)
    def ui() -> str:
        return render_user_dashboard_html(
            docs_url=ctx.admin_dashboard_preferences["docs_url"],
            fleet_ui_url=FLEET_UI_URL,
            zabbix_ui_url=ZABBIX_UI_URL,
            wazuh_ui_url=WAZUH_UI_URL,
            grafana_ui_url=GRAFANA_UI_URL,
        )

    @app.get("/admin", include_in_schema=False, response_class=HTMLResponse)
    def admin() -> str:
        return render_query_console_html(ctx.admin_dashboard_preferences["docs_url"])

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


__all__ = ["register_pages"]
