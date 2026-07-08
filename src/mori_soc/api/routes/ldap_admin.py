"""Admin LDAP user-management routes.

Lets an **admin** manage the directory directly from the MORI admin console when
LDAP is enabled (`MORI_LDAP_ENABLED=true`): list / add / delete users and reset
passwords. All endpoints are admin-gated and no-op-safe when LDAP is disabled.
MORI role for an LDAP user is kept in ``local_users`` and persisted to
``ui_settings`` under ``ldaprole:<uid>`` so it survives restarts.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from mori_soc.api.auth import (
    ldap_add_user,
    ldap_delete_user,
    ldap_list_users,
    ldap_set_password,
)
from mori_soc.api.routes.context import RouteContext

_LDAP_ROLES = {"admin", "security", "monitor", "auditor", "helpdesk", "user"}
_LDAP_ROLE_PREFIX = "ldaprole:"


def register_ldap_admin(ctx: RouteContext) -> None:
    app = ctx.app
    sessions = ctx.sessions
    local_users = ctx.local_users
    settings = ctx.settings

    def _require_admin(request: Request) -> str:
        """Enforce admin role; return the acting username."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        role = (sess or {}).get("role") if sess else None
        if ctx.auth_enabled and role != "admin":
            raise HTTPException(status_code=403, detail="LDAP 관리는 admin 전용입니다.")
        return (sess or {}).get("username", "") if sess else ""

    def _cfg():
        cfg = ctx.auth_config
        if cfg is None or not getattr(cfg, "ldap_enabled", False):
            raise HTTPException(status_code=409, detail="LDAP이 비활성 상태입니다(MORI_LDAP_ENABLED=true).")
        return cfg

    def _role_of(uid: str) -> str:
        return (local_users.get(uid) or {}).get("role", "user")

    @app.get("/admin/ldap/status", tags=["Admin"])
    def ldap_status(request: Request) -> dict[str, Any]:
        """LDAP 활성 여부·접속 정보 요약(비밀번호 제외). admin 전용."""
        _require_admin(request)
        cfg = ctx.auth_config
        enabled = bool(cfg and getattr(cfg, "ldap_enabled", False))
        return {
            "enabled": enabled,
            "url": getattr(cfg, "ldap_url", "") if cfg else "",
            "base_dn": getattr(cfg, "ldap_base_dn", "") if cfg else "",
            "bind_dn": getattr(cfg, "ldap_bind_dn", "") if cfg else "",
            "user_attr": getattr(cfg, "ldap_user_attr", "uid") if cfg else "uid",
            "roles": sorted(_LDAP_ROLES),
        }

    @app.get("/admin/ldap/users", tags=["Admin"])
    def ldap_users(request: Request) -> dict[str, Any]:
        """디렉터리 사용자 목록 + MORI 역할. admin 전용."""
        _require_admin(request)
        cfg = _cfg()
        users, err = ldap_list_users(cfg)
        if err:
            raise HTTPException(status_code=502, detail=f"LDAP 조회 실패: {err}")
        for u in users:
            u["role"] = _role_of(u.get("uid", ""))
        return {"users": users, "total": len(users)}

    @app.post("/admin/ldap/users", tags=["Admin"])
    def ldap_user_add(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """LDAP 사용자 추가 {uid, cn?, mail?, password, role?}. admin 전용."""
        actor = _require_admin(request)
        cfg = _cfg()
        uid = str(payload.get("uid", "")).strip()
        password = str(payload.get("password", "")).strip()
        role = str(payload.get("role", "user")).strip() or "user"
        if not uid or not password:
            raise HTTPException(status_code=400, detail="uid 와 password 는 필수입니다.")
        if role not in _LDAP_ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of: {', '.join(sorted(_LDAP_ROLES))}")
        ok, err = ldap_add_user(
            cfg, uid=uid, password=password,
            cn=str(payload.get("cn", "")).strip() or uid,
            sn=str(payload.get("cn", "")).strip() or uid,
            mail=str(payload.get("mail", "")).strip(),
        )
        if not ok:
            raise HTTPException(status_code=502, detail=f"LDAP 계정 생성 실패: {err}")
        local_users[uid] = {"password": "", "role": role}
        settings[_LDAP_ROLE_PREFIX + uid] = role
        if ctx.persist_setting:
            ctx.persist_setting(_LDAP_ROLE_PREFIX + uid, actor)
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "LDAP_USER_ADD", f"{uid} (role={role})")
        return {"uid": uid, "role": role, "ok": True}

    @app.post("/admin/ldap/users/{uid}/password", tags=["Admin"])
    def ldap_user_reset_pw(uid: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """LDAP 사용자 비밀번호 재설정 {password}. admin 전용."""
        actor = _require_admin(request)
        cfg = _cfg()
        password = str(payload.get("password", "")).strip()
        if not password:
            raise HTTPException(status_code=400, detail="password 는 필수입니다.")
        ok, err = ldap_set_password(cfg, uid, password)
        if not ok:
            raise HTTPException(status_code=502, detail=f"비밀번호 재설정 실패: {err}")
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "LDAP_USER_RESET_PW", uid)
        return {"uid": uid, "ok": True}

    @app.post("/admin/ldap/users/{uid}/role", tags=["Admin"])
    def ldap_user_set_role(uid: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """LDAP 사용자 MORI 역할 변경 {role}. admin 전용."""
        actor = _require_admin(request)
        _cfg()
        role = str(payload.get("role", "")).strip()
        if role not in _LDAP_ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of: {', '.join(sorted(_LDAP_ROLES))}")
        local_users[uid] = {"password": "", "role": role}
        settings[_LDAP_ROLE_PREFIX + uid] = role
        if ctx.persist_setting:
            ctx.persist_setting(_LDAP_ROLE_PREFIX + uid, actor)
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "LDAP_USER_SET_ROLE", f"{uid} → {role}")
        return {"uid": uid, "role": role, "ok": True}

    @app.delete("/admin/ldap/users/{uid}", tags=["Admin"])
    def ldap_user_delete(uid: str, request: Request) -> dict[str, Any]:
        """LDAP 사용자 삭제. admin 전용."""
        actor = _require_admin(request)
        cfg = _cfg()
        ok, err = ldap_delete_user(cfg, uid)
        if not ok:
            raise HTTPException(status_code=502, detail=f"LDAP 삭제 실패: {err}")
        local_users.pop(uid, None)
        settings[_LDAP_ROLE_PREFIX + uid] = ""  # 부팅 시드에서 빈 값은 건너뜀
        if ctx.persist_setting:
            ctx.persist_setting(_LDAP_ROLE_PREFIX + uid, actor)
        if ctx.log_action:
            ctx.log_action(actor or "unknown", "LDAP_USER_DELETE", uid)
        return {"uid": uid, "ok": True}


__all__ = ["register_ldap_admin"]
