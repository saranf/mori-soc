"""Auth routes (Task J-4b15).

Registers the login / signup HTML pages and the ``/auth/*`` JSON endpoints
(login, logout, signup-request CRUD, ``/auth/me`` and profile read/write) on
``ctx.app``. Handler bodies — and the block-local ``_user_profile`` helper — are
verbatim from the original ``create_app`` closures; only the unpacking preamble
(binding shared stores + the ``verify_credentials`` / ``log_action`` helpers from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from mori_soc.api.auth import DEFAULT_ROLE_PERMISSIONS, ldap_add_user, parse_account_view_roles
from mori_soc.api.templates import render_login_html, render_signup_request_html
from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext

# 가입 승인 시 부여 가능한 역할
_SIGNUP_ROLES = {"admin", "security", "monitor", "auditor", "helpdesk", "user"}
# LDAP 사용자 역할을 재시작 후에도 유지하기 위한 settings 키 접두사
_LDAP_ROLE_PREFIX = "ldaprole:"


def register_auth(ctx: RouteContext) -> None:
    app = ctx.app
    sessions = ctx.sessions
    local_users = ctx.local_users
    signup_requests = ctx.signup_requests
    user_profiles = ctx.user_profiles
    user_tab_permissions = ctx.user_tab_permissions
    role_permissions = ctx.role_permissions
    _verify_credentials = ctx.verify_credentials
    _log_action = ctx.log_action
    _persist_user_profile = ctx.persist_user_profile
    _DEFAULT_ROLE_PERMISSIONS = DEFAULT_ROLE_PERMISSIONS

    @app.get("/login", include_in_schema=False, response_class=HTMLResponse)
    def login_page(next: str = "/ui") -> str:
        return render_login_html(next_url=next)

    @app.post("/auth/login", tags=["Auth"])
    def auth_login(payload: dict[str, Any]) -> dict[str, Any]:
        """로그인: {username, password} → 세션 쿠키 설정."""
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password:
            raise HTTPException(status_code=400, detail="아이디와 비밀번호를 입력하세요.")
        if not _verify_credentials(username, password):
            _log_action(username, "LOGIN_FAIL", "잘못된 비밀번호")
            raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
        token = str(uuid.uuid4())
        _role = local_users.get(username, {}).get("role", "user")
        sessions[token] = {
            "username": username,
            "role": _role,
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        _log_action(username, "LOGIN", f"role={_role}")
        from fastapi.responses import JSONResponse
        resp = JSONResponse({"ok": True, "username": username})
        # HTTPS 배포 시 MORI_COOKIE_SECURE=true 로 Secure 속성 부여(평문 전송 세션 스니핑 방지).
        # 기본 off — HTTP 데모에서 Secure 쿠키는 전송되지 않아 로그인이 끊기므로.
        _secure = os.environ.get("MORI_COOKIE_SECURE", "").strip().lower() in ("1", "true", "yes", "on")
        resp.set_cookie("mori_session", token, httponly=True, samesite="lax",
                        secure=_secure, max_age=86400 * 7)
        return resp

    @app.get("/auth/logout", include_in_schema=False)
    def auth_logout(request: Any = None) -> Any:
        """로그아웃: 세션 쿠키 삭제 후 /login 리디렉션."""
        token = ""
        if hasattr(request, "cookies"):
            token = request.cookies.get("mori_session", "")
        sess = sessions.pop(token, {})
        _log_action(sess.get("username", "unknown"), "LOGOUT", "")
        resp = RedirectResponse(url="/login", status_code=302)
        resp.delete_cookie("mori_session")
        return resp

    @app.get("/signup-request", include_in_schema=False, response_class=HTMLResponse)
    def signup_request_page() -> str:
        return render_signup_request_html()

    @app.post("/auth/signup-request", tags=["Auth"])
    def submit_signup_request(payload: dict[str, Any]) -> dict[str, Any]:
        """가입 요청 제출: {username, name, email, department, reason}.

        승인제(approval): 요청만 접수하고, admin 승인 시 계정이 실제로 생성된다.
        `username` 은 로그인 아이디(승인 시 LDAP uid / 로컬 계정명으로 사용).
        """
        username = str(payload.get("username", "")).strip()
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip()
        if not name or not email:
            raise HTTPException(status_code=400, detail="이름과 이메일은 필수입니다.")
        if username and username in local_users:
            raise HTTPException(status_code=409, detail="이미 사용 중인 아이디입니다.")
        req = {
            "id": str(uuid.uuid4()),
            "username": username or email.split("@")[0],
            "name": name,
            "email": email,
            "department": str(payload.get("department", "")).strip(),
            "reason": str(payload.get("reason", "")).strip(),
            "status": "pending",
            "created_at": _isoformat(datetime.now(tz=timezone.utc)),
            "reviewed_at": None,
        }
        signup_requests.append(req)
        return {"ok": True, "message": "가입 요청이 접수되었습니다. 운영자 승인 후 안내드리겠습니다."}

    @app.get("/auth/signup-requests", tags=["Auth"])
    def list_signup_requests() -> dict[str, Any]:
        """가입 요청 목록 조회 (어드민용)."""
        return {"requests": signup_requests, "total": len(signup_requests)}

    @app.patch("/auth/signup-requests/{req_id}", tags=["Auth"])
    def update_signup_request(req_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """가입 요청 승인/거절 (어드민용). status: approved | rejected.

        승인 시 계정을 **실제로 생성**한다:
        - LDAP 활성(`MORI_LDAP_ENABLED=true`): `ldap_add_user` 로 디렉터리에 계정 생성 →
          같은 LDAP을 보는 다른 서비스(Grafana/Zabbix/Fleet)에서도 로그인 가능. 역할은
          `ui_settings`(`ldaprole:<user>`)에 영속되어 재시작 후에도 유지.
        - LDAP 비활성(기본): 로컬 계정(local_users)으로 생성(이번 세션 유지).
        승인 body: `{status:"approved", role?, password?}` — role 기본 `user`,
        password 미지정 시 랜덤 초기 비밀번호를 생성해 응답으로 1회 반환.
        """
        valid_statuses = {"approved", "rejected", "pending"}
        new_status = str(payload.get("status", "")).strip()
        if new_status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid_statuses))}")

        req = next((r for r in signup_requests if r["id"] == req_id), None)
        if req is None:
            raise HTTPException(status_code=404, detail="가입 요청을 찾을 수 없습니다.")

        actor = ""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token) if sessions else None
        if sess:
            actor = sess.get("username", "") or ""

        result: dict[str, Any] = {}
        if new_status == "approved" and req.get("status") != "approved":
            role = str(payload.get("role", "user")).strip() or "user"
            if role not in _SIGNUP_ROLES:
                raise HTTPException(status_code=400, detail=f"role must be one of: {', '.join(sorted(_SIGNUP_ROLES))}")
            username = str(req.get("username", "")).strip()
            if not username:
                raise HTTPException(status_code=400, detail="가입 요청에 아이디가 없습니다.")
            if username in local_users:
                raise HTTPException(status_code=409, detail="이미 존재하는 계정입니다.")
            password = str(payload.get("password", "")).strip() or uuid.uuid4().hex[:12]
            cfg = ctx.auth_config

            if cfg is not None and getattr(cfg, "ldap_enabled", False):
                ok, err = ldap_add_user(
                    cfg, uid=username, password=password,
                    cn=req.get("name") or username, sn=req.get("name") or username,
                    mail=req.get("email", ""),
                )
                if not ok:
                    raise HTTPException(status_code=502, detail=f"LDAP 계정 생성 실패: {err}")
                # 역할만 로컬에 매핑(비밀번호는 LDAP이 검증) + settings에 영속
                local_users[username] = {"password": "", "role": role}
                ctx.settings[_LDAP_ROLE_PREFIX + username] = role
                if ctx.persist_setting:
                    ctx.persist_setting(_LDAP_ROLE_PREFIX + username, actor)
                result["backend"] = "ldap"
            else:
                local_users[username] = {"password": password, "role": role}
                result["backend"] = "local"

            result["username"] = username
            result["role"] = role
            result["initial_password"] = password  # 1회 노출(운영자가 사용자에게 전달)
            if _log_action:
                _log_action(actor or "unknown", "SIGNUP_APPROVE",
                            f"{username} → role={role} ({result['backend']})")

        req["status"] = new_status
        req["reviewed_at"] = _isoformat(datetime.now(tz=timezone.utc))
        return {**req, **result}

    def _user_profile(uname: str) -> dict[str, Any]:
        """username → 프로필 dict (없으면 빈 기본값)."""
        p = user_profiles.get(uname, {})
        return {
            "display_name": p.get("display_name", ""),
            "department": p.get("department", ""),
            "assigned_servers": list(p.get("assigned_servers", [])),
        }

    @app.get("/auth/me", tags=["Auth"])
    def auth_me(request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자 정보 조회."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        acct_roles = parse_account_view_roles(ctx.settings)
        if not sess:
            return {
                "username": "anonymous",
                "role": "user",
                "allowed_tabs": _DEFAULT_ROLE_PERMISSIONS.get("user", ["dashboard", "assets", "guides"]),
                "account_view_roles": acct_roles,
                **_user_profile("anonymous"),
            }
        role = sess.get("role", "user")
        uname = sess["username"]
        # 유저별 개별 설정이 있으면 우선 적용, 없으면 역할 기본값
        if uname in user_tab_permissions:
            allowed = user_tab_permissions[uname]
        else:
            allowed = role_permissions.get(role, _DEFAULT_ROLE_PERMISSIONS.get(role, ["dashboard", "assets", "guides"]))
        return {
            "username": uname,
            "role": role,
            "allowed_tabs": allowed,
            "account_view_roles": acct_roles,
            **_user_profile(uname),
        }

    @app.get("/auth/profile", tags=["Auth"])
    def get_profile(request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자의 프로필 조회."""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        if not sess:
            raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
        uname = sess["username"]
        return {"username": uname, **_user_profile(uname)}

    @app.post("/auth/profile", tags=["Auth"])
    def update_profile(payload: dict[str, Any], request: Request) -> dict[str, Any]:
        """현재 로그인한 사용자의 프로필 업서트. {display_name, department, assigned_servers[]}"""
        token = request.cookies.get("mori_session", "")
        sess = sessions.get(token)
        if not sess:
            raise HTTPException(status_code=401, detail="로그인이 필요합니다.")
        uname = sess["username"]
        display_name = str(payload.get("display_name", "")).strip()
        department = str(payload.get("department", "")).strip()
        raw_servers = payload.get("assigned_servers", [])
        if isinstance(raw_servers, str):
            raw_servers = [s for s in raw_servers.replace(",", "\n").splitlines()]
        assigned_servers = [str(s).strip() for s in raw_servers if str(s).strip()]
        user_profiles[uname] = {
            "display_name": display_name,
            "department": department,
            "assigned_servers": assigned_servers,
            "updated_at": _isoformat(datetime.now(tz=timezone.utc)),
        }
        _persist_user_profile(uname)
        return {"ok": True, "username": uname, **_user_profile(uname)}


__all__ = ["register_auth"]
