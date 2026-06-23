"""Auth routes (Task J-4b15).

Registers the login / signup HTML pages and the ``/auth/*`` JSON endpoints
(login, logout, signup-request CRUD, ``/auth/me`` and profile read/write) on
``ctx.app``. Handler bodies — and the block-local ``_user_profile`` helper — are
verbatim from the original ``create_app`` closures; only the unpacking preamble
(binding shared stores + the ``verify_credentials`` / ``log_action`` helpers from
:class:`RouteContext`) is new.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from mori_soc.api.auth import DEFAULT_ROLE_PERMISSIONS
from mori_soc.api.templates import render_login_html, render_signup_request_html
from mori_soc.api.payloads import _isoformat
from mori_soc.api.routes.context import RouteContext


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
        resp.set_cookie("mori_session", token, httponly=True, samesite="lax", max_age=86400 * 7)
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
        """가입 요청 제출: {name, email, department, reason}."""
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip()
        if not name or not email:
            raise HTTPException(status_code=400, detail="이름과 이메일은 필수입니다.")
        req = {
            "id": str(uuid.uuid4()),
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
    def update_signup_request(req_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """가입 요청 승인/거절 (어드민용). status: approved | rejected."""
        valid_statuses = {"approved", "rejected", "pending"}
        new_status = str(payload.get("status", "")).strip()
        if new_status not in valid_statuses:
            raise HTTPException(status_code=400, detail=f"status must be one of: {', '.join(sorted(valid_statuses))}")
        for req in signup_requests:
            if req["id"] == req_id:
                req["status"] = new_status
                req["reviewed_at"] = _isoformat(datetime.now(tz=timezone.utc))
                return req
        raise HTTPException(status_code=404, detail="가입 요청을 찾을 수 없습니다.")

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
        if not sess:
            return {
                "username": "anonymous",
                "role": "user",
                "allowed_tabs": _DEFAULT_ROLE_PERMISSIONS.get("user", ["dashboard", "assets", "guides"]),
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
        return {"ok": True, "username": uname, **_user_profile(uname)}


__all__ = ["register_auth"]
