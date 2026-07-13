"""Query routes (Task J-4b9).

Registers the dashboard-summary / query / interpret endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; only the
unpacking preamble (binding shared stores + the ``get_query_service`` helper from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from mori_soc.api.payloads import (
    _query_csv_filename,
    build_dashboard_payload,
    build_query_request,
    interpret_query_text,
)
from mori_soc.api.routes.context import RouteContext
from mori_soc.services.query_service import query_response_to_csv


def register_query(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    asset_owners = ctx.asset_owners
    vuln_actions = ctx.vuln_actions

    @app.get("/dashboard/summary")
    def dashboard_summary() -> dict[str, Any]:
        try:
            return build_dashboard_payload(get_query_service(), asset_owners=asset_owners, vuln_actions=vuln_actions)
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"dashboard summary unavailable: {exc}") from exc

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


__all__ = ["register_query"]
