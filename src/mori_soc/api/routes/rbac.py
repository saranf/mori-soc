"""RBAC routes (Task J-4b11).

Registers role-permission and per-user tab-permission endpoints on ``ctx.app``.
Handler bodies are verbatim from the original ``create_app`` closures; the only
changes are the unpacking preamble and dropping the unnecessary ``nonlocal
role_permissions`` (the handler mutates the dict in place, so binding the shared
``ctx.role_permissions`` reference is equivalent). ``_DEFAULT_ROLE_PERMISSIONS``
is the module-level :data:`DEFAULT_ROLE_PERMISSIONS` from ``auth.py``.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from mori_soc.api.auth import DEFAULT_ROLE_PERMISSIONS
from mori_soc.api.routes.context import RouteContext


def register_rbac(ctx: RouteContext) -> None:
    app = ctx.app
    role_permissions = ctx.role_permissions
    user_tab_permissions = ctx.user_tab_permissions
    sessions = ctx.sessions
    local_users = ctx.local_users
    _log_action = ctx.log_action

    @app.get("/admin/role-permissions", tags=["Admin"])
    def get_role_permissions_api() -> dict[str, Any]:
        """역할별 탭 권한 조회."""
        return {"permissions": role_permissions}

    @app.post("/admin/role-permissions", tags=["Admin"])
    def update_role_permissions_api(payload: dict[str, Any]) -> dict[str, Any]:
        """역할별 탭 권한 업데이트. {role: [tab_id, ...]}"""
        valid_tabs = {"dashboard", "triage", "incidents", "assets", "compliance", "guides"}
        for role_key, tabs in payload.items():
            if not isinstance(tabs, list):
                raise HTTPException(status_code=400, detail=f"tabs for {role_key} must be a list")
            role_permissions[role_key] = [t for t in tabs if t in valid_tabs]
        return {"permissions": role_permissions}

    @app.get("/admin/user-tab-permissions", tags=["Admin"])
    def get_user_tab_permissions_api() -> dict[str, Any]:
        """유저별 탭 권한 오버라이드 목록 + 전체 유저 목록 조회."""
        # 로컬 유저 + 로그인 이력이 있는 세션 유저
        all_users: dict[str, str] = {}
        for uname, info in local_users.items():
            all_users[uname] = info.get("role", "user")
        for _tok, sess in sessions.items():
            uname = sess.get("username", "")
            if uname and uname not in all_users:
                all_users[uname] = sess.get("role", "user")
        users_list = []
        for uname, role in sorted(all_users.items()):
            role_default = role_permissions.get(role, DEFAULT_ROLE_PERMISSIONS.get(role, ["dashboard", "assets", "guides"]))
            override = user_tab_permissions.get(uname)
            users_list.append({
                "username": uname,
                "role": role,
                "role_default_tabs": role_default,
                "user_tabs": override,  # None이면 역할 기본값 사용 중
                "has_override": override is not None,
            })
        return {"users": users_list}

    @app.post("/admin/user-tab-permissions/{username}", tags=["Admin"])
    def set_user_tab_permissions_api(username: str, payload: dict[str, Any]) -> dict[str, Any]:
        """특정 유저의 탭 권한 개별 설정. {"tabs": ["dashboard","assets",...]}"""
        valid_tabs = {"dashboard", "triage", "incidents", "assets", "compliance", "guides"}
        tabs = payload.get("tabs")
        if not isinstance(tabs, list):
            raise HTTPException(status_code=400, detail="tabs must be a list")
        user_tab_permissions[username] = [t for t in tabs if t in valid_tabs]
        _log_action("admin", "USER_TAB_PERM_SET", f"user={username} tabs={user_tab_permissions[username]}")
        return {"username": username, "tabs": user_tab_permissions[username]}

    @app.delete("/admin/user-tab-permissions/{username}", tags=["Admin"])
    def reset_user_tab_permissions_api(username: str) -> dict[str, Any]:
        """특정 유저의 탭 권한 개별 설정 초기화 (역할 기본값으로 복원)."""
        removed = user_tab_permissions.pop(username, None)
        _log_action("admin", "USER_TAB_PERM_RESET", f"user={username}")
        return {"username": username, "reset": removed is not None}


__all__ = ["register_rbac"]
