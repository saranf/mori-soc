"""Audit-log routes (Task J-4b12).

Registers the user-action audit log (read/append) and the asset-change audit log
(read) endpoints on ``ctx.app``. Handler bodies are verbatim from the original
``create_app`` closures; only the unpacking preamble (binding shared stores + the
``log_action`` helper from :class:`RouteContext`) is new.
"""
from __future__ import annotations

from typing import Any

from mori_soc.api.routes.context import RouteContext


def register_audit(ctx: RouteContext) -> None:
    app = ctx.app
    action_audit_log = ctx.action_audit_log
    asset_audit_log = ctx.asset_audit_log
    sessions = ctx.sessions
    _log_action = ctx.log_action

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

    @app.get("/admin/audit-log", tags=["Assets"])
    def audit_log_list(hostname: str = "", field: str = "") -> Any:
        """자산 담당자/카테고리 변경 이력 조회 (어드민 전용)."""
        result = list(reversed(asset_audit_log))  # 최신 순
        if hostname:
            result = [r for r in result if r["hostname"] == hostname]
        if field:
            result = [r for r in result if r["field"] == field]
        return {"audit_log": result, "total": len(result)}


__all__ = ["register_audit"]
