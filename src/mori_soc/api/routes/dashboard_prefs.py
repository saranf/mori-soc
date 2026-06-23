"""Dashboard preferences routes (Task J-4b10).

Registers the per-user / admin dashboard-preference endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures except for
``admin_dashboard_preferences``: it is *rebound* by two handlers and also read by
the ``/ui`` / ``/admin`` page routes that remain in ``server.py``. To keep a
single shared source of truth the ``nonlocal`` local is replaced by the
:class:`RouteContext` attribute ``ctx.admin_dashboard_preferences`` (write-back),
which the page routes also read — behaviour is identical.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.payloads import _dashboard_preferences_response, _merge_dashboard_preferences
from mori_soc.api.routes.context import RouteContext


def register_dashboard_prefs(ctx: RouteContext) -> None:
    app = ctx.app
    _get_session_username = ctx.get_session_username
    user_dashboard_prefs = ctx.user_dashboard_prefs

    @app.get("/dashboard/preferences")
    def dashboard_preferences_get(request: Request) -> dict[str, Any]:
        """현재 사용자의 대시보드 설정 조회 (개인 설정 → 관리자 기본값 순)."""
        username = _get_session_username(request)
        if username and username in user_dashboard_prefs:
            return _dashboard_preferences_response(user_dashboard_prefs[username])
        return _dashboard_preferences_response(ctx.admin_dashboard_preferences)

    @app.post("/dashboard/preferences")
    def dashboard_preferences_update(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
        """현재 사용자의 대시보드 설정 저장 (개인별)."""
        username = _get_session_username(request)
        if username:
            base = user_dashboard_prefs.get(username, dict(ctx.admin_dashboard_preferences))
            try:
                user_dashboard_prefs[username] = _merge_dashboard_preferences(base, payload)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            return _dashboard_preferences_response(user_dashboard_prefs[username])
        # 인증 미사용 환경: 글로벌 설정 업데이트
        try:
            ctx.admin_dashboard_preferences = _merge_dashboard_preferences(ctx.admin_dashboard_preferences, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _dashboard_preferences_response(ctx.admin_dashboard_preferences)

    @app.get("/admin/dashboard/preferences", tags=["Admin"])
    def admin_dashboard_preferences_get() -> dict[str, Any]:
        """관리자 기본 대시보드 설정 조회 (모든 사용자 기본값)."""
        return _dashboard_preferences_response(ctx.admin_dashboard_preferences)

    @app.post("/admin/dashboard/preferences", tags=["Admin"])
    def admin_dashboard_preferences_update(payload: dict[str, Any]) -> dict[str, Any]:
        """관리자 기본 대시보드 설정 변경 (모든 사용자 기본값)."""
        try:
            ctx.admin_dashboard_preferences = _merge_dashboard_preferences(ctx.admin_dashboard_preferences, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _dashboard_preferences_response(ctx.admin_dashboard_preferences)

    @app.get("/admin/dashboard/user-preferences", tags=["Admin"])
    def admin_user_prefs_list() -> dict[str, Any]:
        """모든 사용자의 개인 설정 목록 조회 (관리자용)."""
        return {
            "users": {
                uname: _dashboard_preferences_response(prefs)
                for uname, prefs in user_dashboard_prefs.items()
            }
        }

    @app.delete("/admin/dashboard/user-preferences/{username}", tags=["Admin"])
    def admin_user_prefs_reset(username: str) -> dict[str, Any]:
        """특정 사용자의 개인 설정 초기화 (관리자 기본값으로 복원)."""
        removed = user_dashboard_prefs.pop(username, None)
        return {"username": username, "reset": removed is not None}


__all__ = ["register_dashboard_prefs"]
