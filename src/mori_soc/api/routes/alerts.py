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
    sessions = ctx.sessions
    _get_session_username = ctx.get_session_username
    _persist_triage = ctx.persist_triage
    _zabbix_writeback_comment = ctx.zabbix_writeback_comment
    _zabbix_writeback_suppress = ctx.zabbix_writeback_suppress

    def _find_alert(alert_id: str) -> Any:
        store = get_query_service().store
        return next((a for a in store.alerts if a.alert_id == alert_id), None)

    def _require_writeback_actor(request: Request) -> str:
        """Suppress/unsuppress 는 실운영 억제라 admin·security 전용."""
        if ctx.auth_enabled:
            token = request.cookies.get("mori_session", "")
            sess = sessions.get(token) if sessions else None
            role = sess.get("role") if sess else None
            if role not in {"admin", "security"}:
                raise HTTPException(status_code=403, detail="Zabbix suppress는 admin·security 전용입니다.")
        return _get_session_username(request) or "unknown"

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
        _persist_triage(alert_id)

        # Alert 객체는 Zabbix write-back(모든 상태)과 Slack 알림(reviewing/resolved)이
        # 공유한다 — 둘 중 하나라도 필요하면 한 번만 조회한다.
        need_slack = status in {"reviewing", "resolved"} and bool(webhooks)
        alert_obj = None
        if _zabbix_writeback_comment is not None or need_slack:
            store = get_query_service().store
            alert_obj = next((a for a in store.alerts if a.alert_id == alert_id), None)

        # Zabbix write-back (Level 1 comment / Level 2 ack) — 활성화 시에만, 실패해도 triage 응답 유지.
        # payload의 zabbix_ack(bool)로 상태와 무관하게 ack 강제/해제(프론트 버튼용). 없으면 상태 기반.
        if alert_obj is not None and _zabbix_writeback_comment is not None:
            raw_ack = payload.get("zabbix_ack")
            explicit_ack = bool(raw_ack) if isinstance(raw_ack, bool) else None
            _zabbix_writeback_comment(alert_obj, entry, changed_by, explicit_ack)

        # Slack 알림: reviewing/resolved 전환 시
        if need_slack and alert_obj is not None:
            label = {"reviewing": "검토중", "resolved": "조치예정/완료"}.get(status, status)
            msg = f":mag: [MORI Triage] `{alert_id}` → *{label}*\n*Alert:* {alert_obj.message}\n*담당자:* {entry['analyst'] or 'unknown'}"
            _notify_all_webhooks(webhooks, msg)
        return {"alert_id": alert_id, "triage": entry}

    # ── Zabbix suppress/unsuppress (Level 3) ──────────────────────────────────
    # 명시적 예외 승인/철회 액션 — triage 와 분리, admin·security 전용.
    # MORI_ZABBIX_WRITEBACK_MODE=suppress 로 켜졌을 때만 실제 반영된다.
    def _resolve_suppress_target(alert_id: str, request: Request) -> Any:
        actor = _require_writeback_actor(request)
        if _zabbix_writeback_suppress is None:
            raise HTTPException(status_code=503, detail="Zabbix write-back이 구성되지 않았습니다.")
        alert_obj = _find_alert(alert_id)
        if alert_obj is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return actor, alert_obj

    def _finish_suppress(alert_id: str, result: dict[str, Any]) -> dict[str, Any]:
        if not result.get("enabled"):
            raise HTTPException(status_code=409, detail=result.get("error", "suppress write-back not enabled"))
        if not result.get("ok"):
            raise HTTPException(status_code=502, detail=result.get("error", "Zabbix suppress failed"))
        return {"alert_id": alert_id, **result}

    @app.post("/alerts/{alert_id}/zabbix/suppress", tags=["Alerts"])
    def alert_zabbix_suppress(alert_id: str, request: Request, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Zabbix problem event 억제(예외 승인). minutes 미지정/0 → 무기한. admin·security."""
        actor, alert_obj = _resolve_suppress_target(alert_id, request)
        body = payload or {}
        minutes = body.get("minutes")
        until = 0
        if isinstance(minutes, (int, float)) and not isinstance(minutes, bool) and minutes > 0:
            until = int(datetime.now(tz=timezone.utc).timestamp()) + int(minutes) * 60
        reason = str(body.get("reason", "")).strip()
        result = _zabbix_writeback_suppress(alert_obj, until=until, reason=reason, acting_user=actor)
        return _finish_suppress(alert_id, result)

    @app.post("/alerts/{alert_id}/zabbix/unsuppress", tags=["Alerts"])
    def alert_zabbix_unsuppress(alert_id: str, request: Request, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Zabbix problem event 억제 해제(예외 철회). admin·security."""
        actor, alert_obj = _resolve_suppress_target(alert_id, request)
        reason = str((payload or {}).get("reason", "")).strip()
        result = _zabbix_writeback_suppress(alert_obj, until=0, reason=reason, acting_user=actor, unsuppress=True)
        return _finish_suppress(alert_id, result)


__all__ = ["register_alerts"]
