"""Authentication, LDAP, RBAC, and session-management primitives.

Extracted from ``server.py`` (Task J-3). This module holds the *stateless*
auth logic — LDAP credential verification, environment-driven configuration,
the default RBAC table, local-account seeding, and a factory that builds the
session-auth middleware. Per-app mutable state (``sessions``, role overrides,
user profiles) stays owned by :func:`create_app` and is passed in where needed.

Dependency direction: ``i18n.py → templates.py → server.py`` with ``auth.py``
sitting alongside as a leaf used by ``server.py`` (no circular imports).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import quote as _url_quote
from typing import Any

try:
    from ldap3 import (
        Server as _LdapServer,
        Connection as _LdapConnection,
        ALL as _LDAP_ALL,
        SUBTREE as _LDAP_SUBTREE,
    )
    LDAP3_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    _LdapServer = None
    _LdapConnection = None
    _LDAP_ALL = None
    _LDAP_SUBTREE = None
    LDAP3_AVAILABLE = False


# Role permissions: role -> list of allowed tab ids
DEFAULT_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin": ["dashboard", "triage", "incidents", "assets", "compliance", "guides"],
    "security": ["dashboard", "triage", "incidents", "assets", "compliance", "guides"],
    "monitor": ["dashboard", "triage", "assets", "compliance", "guides"],
    "auditor": ["dashboard", "compliance", "guides"],
    "helpdesk": ["dashboard", "assets", "guides"],
    "user": ["dashboard", "assets", "guides"],
}


@dataclass
class AuthConfig:
    """Environment-driven authentication configuration."""

    ldap_url: str
    ldap_bind_dn: str
    ldap_bind_pw: str
    ldap_base_dn: str
    ldap_user_attr: str
    ldap_enabled: bool
    admin_user: str
    admin_password: str
    auth_enabled: bool


def read_auth_config() -> AuthConfig:
    """Read auth-related environment variables into an :class:`AuthConfig`."""
    ldap_url = os.environ.get("LDAP_URL", "").strip()
    ldap_bind_dn = os.environ.get("LDAP_BIND_DN", "").strip()
    ldap_bind_pw = os.environ.get("LDAP_BIND_PASSWORD", "").strip()
    ldap_base_dn = os.environ.get("LDAP_BASE_DN", "").strip()
    ldap_user_attr = os.environ.get("LDAP_USER_ATTR", "uid").strip()
    ldap_enabled = bool(ldap_url and LDAP3_AVAILABLE)
    admin_user = os.environ.get("MORI_ADMIN_USER", "admin")
    admin_password = os.environ.get("MORI_ADMIN_PASSWORD", "1234")
    auth_enabled = bool(os.environ.get("MORI_AUTH_ENABLED", "") or ldap_enabled)
    return AuthConfig(
        ldap_url=ldap_url,
        ldap_bind_dn=ldap_bind_dn,
        ldap_bind_pw=ldap_bind_pw,
        ldap_base_dn=ldap_base_dn,
        ldap_user_attr=ldap_user_attr,
        ldap_enabled=ldap_enabled,
        admin_user=admin_user,
        admin_password=admin_password,
        auth_enabled=auth_enabled,
    )


def default_local_users(admin_user: str, admin_password: str) -> dict[str, dict[str, str]]:
    """Predefined local accounts: username -> {password, role}."""
    return {
        admin_user: {"password": admin_password, "role": "admin"},
        "security": {"password": "1234", "role": "security"},
        "monitor": {"password": "1234", "role": "monitor"},
        "auditor": {"password": "1234", "role": "auditor"},
        "helpdesk": {"password": "1234", "role": "helpdesk"},
    }


def ldap_verify(
    username: str,
    password: str,
    ldap_url: str,
    bind_dn: str,
    bind_pw: str,
    base_dn: str,
    user_attr: str,
) -> bool:
    """Synchronous LDAP credential verification. Returns True if authenticated."""
    if not LDAP3_AVAILABLE or _LdapServer is None:
        return False
    try:
        server = _LdapServer(ldap_url, get_info=_LDAP_ALL, connect_timeout=5)
        user_dn: str
        if bind_dn and base_dn:
            # Search-then-bind: use service account to find the user DN
            admin_conn = _LdapConnection(server, bind_dn, bind_pw, auto_bind=True)
            admin_conn.search(base_dn, f"({user_attr}={username})", search_scope=_LDAP_SUBTREE, attributes=["dn"])
            if not admin_conn.entries:
                return False
            user_dn = str(admin_conn.entries[0].entry_dn)
        else:
            # Simple bind: construct DN directly
            user_dn = f"{user_attr}={username},{base_dn}" if base_dn else f"{user_attr}={username}"
        conn = _LdapConnection(server, user_dn, password, auto_bind=True)
        return conn.bound
    except Exception:
        return False


def verify_credentials(
    username: str,
    password: str,
    config: AuthConfig,
    local_users: dict[str, dict[str, str]],
) -> bool:
    """LDAP(설정 시) → 로컬 계정 순으로 인증."""
    if config.ldap_enabled:
        try:
            if ldap_verify(
                username,
                password,
                config.ldap_url,
                config.ldap_bind_dn,
                config.ldap_bind_pw,
                config.ldap_base_dn,
                config.ldap_user_attr,
            ):
                return True
        except Exception:
            pass
    user = local_users.get(username)
    return user is not None and user["password"] == password


# Public paths that bypass the session-auth middleware.
AUTH_PUBLIC_PATHS = {
    "/login", "/signup-request",
    "/auth/login", "/auth/logout", "/auth/signup-request", "/auth/me",
    "/docs", "/openapi.json", "/redoc", "/health",
}


def build_session_auth_middleware(sessions: dict[str, dict[str, Any]]):
    """Build a Starlette ``BaseHTTPMiddleware`` enforcing cookie-based sessions.

    The returned class closes over the live ``sessions`` dict owned by
    :func:`create_app`, so token revocation/expiry stays in sync without
    sharing module-level state.
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request as _StarletteRequest
    from starlette.responses import Response as _StarletteResponse

    class _SessionAuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: _StarletteRequest, call_next):  # type: ignore[override]
            path = request.url.path
            # ``/ingest/*`` push 엔드포인트는 자체 토큰(MORI_INGEST_TOKEN) 또는 세션
            # 인증을 핸들러에서 직접 강제한다 → 세션 미들웨어는 우회해야 무세션 토큰
            # push(에이전트/CSOP)가 가능. (조회용 /evidence 는 우회하지 않고 RBAC 적용.)
            if (
                path in AUTH_PUBLIC_PATHS
                or path.startswith("/redoc")
                or path.startswith("/static")
                or path.startswith("/ingest/")
            ):
                return await call_next(request)
            token = request.cookies.get("mori_session", "")
            if token and token in sessions:
                return await call_next(request)
            # Not authenticated
            accept = request.headers.get("accept", "")
            if "text/html" in accept:
                return _StarletteResponse(
                    status_code=302,
                    headers={"location": f"/login?next={_url_quote(path)}"},
                    content="",
                )
            return _StarletteResponse(
                status_code=401,
                content='{"detail":"Unauthorized. Please login at /login"}',
                media_type="application/json",
            )

    return _SessionAuthMiddleware
