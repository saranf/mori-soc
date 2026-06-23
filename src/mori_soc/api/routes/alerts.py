"""Alert triage routes (Task J-4b2).

Registers ``GET /alerts`` and ``PATCH /alerts/{alert_id}/triage`` on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; only the
unpacking preamble (binding shared state + the ``get_query_service`` /
``get_session_username`` helpers from :class:`RouteContext`) is new.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.payloads import _alert_detail_rows, _isoformat, _notify_all_webhooks
from mori_soc.api.routes.context import RouteContext


def register_alerts(ctx: RouteContext) -> None:
    app = ctx.app
    get_query_service = ctx.get_query_service
    triage_store = ctx.triage_store
    webhooks = ctx.webhooks
    _get_session_username = ctx.get_session_username

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


__all__ = ["register_alerts"]
