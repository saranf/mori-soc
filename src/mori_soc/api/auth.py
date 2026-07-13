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
from typing import Any
from urllib.parse import quote as _url_quote
from urllib.parse import urlsplit as _urlsplit

# CSRF: 쿠키 세션으로 인증된 상태변경 요청에만 Origin allowlist 를 적용한다.
_CSRF_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _isoformat_utc(ts: float) -> str:
    from datetime import datetime as _dt
    from datetime import timezone as _tz
    return _dt.fromtimestamp(ts, tz=_tz.utc).isoformat()


def _session_ttls() -> tuple[int, int]:
    """(idle 초, absolute 초) — 미활동/절대 수명. env 로 조정."""
    def _int(name: str, default: int) -> int:
        try:
            return max(1, int(os.environ.get(name, "").strip() or default))
        except ValueError:
            return default
    return _int("MORI_SESSION_IDLE_SECONDS", 28800), _int("MORI_SESSION_ABSOLUTE_SECONDS", 604800)


def _session_expired(sess: dict[str, Any], now_ts: float) -> bool:
    """idle(마지막 활동) 또는 absolute(생성) 수명 초과 여부."""
    from datetime import datetime as _dt
    idle, absolute = _session_ttls()

    def _age(key: str) -> float:
        raw = str(sess.get(key) or "")
        if not raw:
            return 0.0
        try:
            return now_ts - _dt.fromisoformat(raw).timestamp()
        except ValueError:
            return 0.0

    created_age = _age("created_at")
    last_age = _age("last_seen") if sess.get("last_seen") else created_age
    return created_age > absolute or last_age > idle


def _origin_allowed(origin: str, host_header: str) -> bool:
    """Origin(scheme://host:port) 이 자기 자신·MORI_PUBLIC_URL·MORI_ALLOWED_ORIGINS 중 하나인가."""
    origin_host = _urlsplit(origin).netloc.lower()
    if not origin_host:
        return True  # 파싱 불가한 Origin 은 판단보류(차단하지 않음)
    if origin_host == (host_header or "").lower():
        return True  # 동일 출처
    allowed: set[str] = set()
    pub = os.environ.get("MORI_PUBLIC_URL", "").strip().lower()
    if pub:
        allowed.add(_urlsplit(pub).netloc)
    for extra in os.environ.get("MORI_ALLOWED_ORIGINS", "").split(","):
        extra = extra.strip().lower()
        if extra:
            allowed.add(_urlsplit(extra).netloc if "://" in extra else extra)
    return origin_host in allowed

try:
    from ldap3 import (
        ALL as _LDAP_ALL,
    )
    from ldap3 import (
        MODIFY_REPLACE as _LDAP_MODIFY_REPLACE,
    )
    from ldap3 import (
        SUBTREE as _LDAP_SUBTREE,
    )
    from ldap3 import (
        Connection as _LdapConnection,
    )
    from ldap3 import (
        Server as _LdapServer,
    )
    LDAP3_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by runtime guard tests
    _LdapServer = None
    _LdapConnection = None
    _LDAP_ALL = None
    _LDAP_SUBTREE = None
    _LDAP_MODIFY_REPLACE = None
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

# 계정 거버넌스(계정 탭·호스트 상세 계정 섹션·/accounts/*) 열람 역할.
# 기본 admin·security. admin이 ui_settings의 account_view_roles 로 자유롭게 조정.
_ALL_ROLES = ("admin", "security", "monitor", "auditor", "helpdesk", "user")
DEFAULT_ACCOUNT_VIEW_ROLES: list[str] = ["admin", "security"]


def parse_account_view_roles(settings: dict[str, str] | None) -> list[str]:
    """``ui_settings['account_view_roles']`` (콤마 구분)를 유효 역할 목록으로 파싱.

    admin은 항상 포함(자기 자신 lock-out 방지). 값이 없으면 기본값.
    """
    raw = (settings or {}).get("account_view_roles", "") if settings else ""
    roles = [r.strip() for r in str(raw).replace(";", ",").split(",") if r.strip()]
    valid = [r for r in roles if r in _ALL_ROLES]
    if not valid:
        return list(DEFAULT_ACCOUNT_VIEW_ROLES)
    if "admin" not in valid:
        valid = ["admin", *valid]
    return valid


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


def _env_first(*names: str, default: str = "") -> str:
    """First non-empty env var among ``names`` (for MORI_LDAP_* → LDAP_* fallback)."""
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


def read_auth_config() -> AuthConfig:
    """Read auth-related environment variables into an :class:`AuthConfig`.

    LDAP is **opt-in**: it activates only when ``MORI_LDAP_ENABLED`` is truthy
    *and* an LDAP URL is set *and* ``ldap3`` is installed. Env var names accept the
    canonical ``MORI_LDAP_*`` form (as wired in docker-compose), falling back to the
    legacy unprefixed ``LDAP_*`` for backward compatibility.
    """
    ldap_url = _env_first("MORI_LDAP_URL", "LDAP_URL")
    ldap_bind_dn = _env_first("MORI_LDAP_BIND_DN", "LDAP_BIND_DN")
    ldap_bind_pw = _env_first("MORI_LDAP_BIND_PW", "MORI_LDAP_BIND_PASSWORD", "LDAP_BIND_PASSWORD")
    ldap_base_dn = _env_first("MORI_LDAP_BASE_DN", "LDAP_BASE_DN")
    ldap_user_attr = _env_first("MORI_LDAP_USER_ATTR", "LDAP_USER_ATTR", default="uid")
    ldap_flag = os.environ.get("MORI_LDAP_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")
    ldap_enabled = bool(ldap_flag and ldap_url and LDAP3_AVAILABLE)
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
            # 'dn' 은 유효한 속성 타입이 아니므로 요청하지 않는다(entry_dn 은 항상 제공됨).
            admin_conn.search(base_dn, f"({user_attr}={username})", search_scope=_LDAP_SUBTREE, attributes=["cn"])
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


def ldap_add_user(
    config: AuthConfig,
    uid: str,
    password: str,
    cn: str = "",
    sn: str = "",
    mail: str = "",
) -> tuple[bool, str]:
    """Create an ``inetOrgPerson`` under the LDAP base DN. Returns (ok, error).

    Used by the approval-based signup flow to provision a real account that can
    then log in to MORI **and** any other service pointed at the same directory
    (Grafana/Zabbix/Fleet). Requires ``config.ldap_bind_dn`` to have write access.
    """
    if not config.ldap_enabled or not LDAP3_AVAILABLE or _LdapServer is None:
        return False, "LDAP is not enabled"
    if not (config.ldap_bind_dn and config.ldap_base_dn):
        return False, "LDAP bind DN / base DN required for account creation"
    try:
        server = _LdapServer(config.ldap_url, get_info=_LDAP_ALL, connect_timeout=5)
        conn = _LdapConnection(server, config.ldap_bind_dn, config.ldap_bind_pw, auto_bind=True)
        user_dn = f"{config.ldap_user_attr}={uid},{config.ldap_base_dn}"
        attrs: dict[str, Any] = {
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "cn": cn or uid,
            "sn": sn or uid,
            "userPassword": password,
        }
        if mail:
            attrs["mail"] = mail
        ok = conn.add(user_dn, attributes=attrs)
        if not ok:
            return False, str(conn.result.get("description", conn.result))
        return True, ""
    except Exception as exc:  # pragma: no cover - network/dir errors
        return False, str(exc)


def _ldap_admin_conn(config: AuthConfig):
    """Bind as the service account for admin operations. Returns (conn, error)."""
    if not config.ldap_enabled or not LDAP3_AVAILABLE or _LdapServer is None:
        return None, "LDAP is not enabled"
    if not (config.ldap_bind_dn and config.ldap_base_dn):
        return None, "LDAP bind DN / base DN required"
    try:
        server = _LdapServer(config.ldap_url, get_info=_LDAP_ALL, connect_timeout=5)
        return _LdapConnection(server, config.ldap_bind_dn, config.ldap_bind_pw, auto_bind=True), ""
    except Exception as exc:  # pragma: no cover
        return None, str(exc)


def ldap_list_users(config: AuthConfig, limit: int = 500) -> tuple[list[dict[str, str]], str]:
    """List directory users under the base DN. Returns (users, error)."""
    conn, err = _ldap_admin_conn(config)
    if conn is None:
        return [], err
    try:
        conn.search(
            config.ldap_base_dn, "(objectClass=inetOrgPerson)",
            search_scope=_LDAP_SUBTREE, attributes=["cn", "mail", config.ldap_user_attr],
            size_limit=max(1, int(limit)),
        )
        out: list[dict[str, str]] = []
        for e in conn.entries:
            attrs = e.entry_attributes_as_dict
            uid_vals = attrs.get(config.ldap_user_attr) or []
            cn_vals = attrs.get("cn") or []
            mail_vals = attrs.get("mail") or []
            out.append({
                "uid": str(uid_vals[0]) if uid_vals else "",
                "cn": str(cn_vals[0]) if cn_vals else "",
                "mail": str(mail_vals[0]) if mail_vals else "",
                "dn": str(e.entry_dn),
            })
        out.sort(key=lambda r: r["uid"])
        return out, ""
    except Exception as exc:  # pragma: no cover
        return [], str(exc)


def ldap_delete_user(config: AuthConfig, uid: str) -> tuple[bool, str]:
    """Delete ``uid=<uid>,<base_dn>``. Returns (ok, error)."""
    conn, err = _ldap_admin_conn(config)
    if conn is None:
        return False, err
    try:
        user_dn = f"{config.ldap_user_attr}={uid},{config.ldap_base_dn}"
        ok = conn.delete(user_dn)
        if not ok:
            return False, str(conn.result.get("description", conn.result))
        return True, ""
    except Exception as exc:  # pragma: no cover
        return False, str(exc)


def ldap_set_password(config: AuthConfig, uid: str, password: str) -> tuple[bool, str]:
    """Reset ``userPassword`` for ``uid``. Returns (ok, error)."""
    conn, err = _ldap_admin_conn(config)
    if conn is None:
        return False, err
    if _LDAP_MODIFY_REPLACE is None:
        return False, "ldap3 unavailable"
    try:
        user_dn = f"{config.ldap_user_attr}={uid},{config.ldap_base_dn}"
        ok = conn.modify(user_dn, {"userPassword": [(_LDAP_MODIFY_REPLACE, [password])]})
        if not ok:
            return False, str(conn.result.get("description", conn.result))
        return True, ""
    except Exception as exc:  # pragma: no cover
        return False, str(exc)


# Public paths that bypass the session-auth middleware.
AUTH_PUBLIC_PATHS = {
    "/login", "/signup-request",
    "/auth/login", "/auth/logout", "/auth/signup-request", "/auth/me",
    "/docs", "/openapi.json", "/redoc", "/health", "/health/live", "/health/ready", "/metrics",
    # CI 스캐너 자산(고객 GitHub Actions가 세션 없이 GET) — 시크릿 없음.
    # 무료 경로가 쓰는 pii-rules/flow-scanner, 유료 경로가 쓰는 fullscan 스크립트.
    "/privacy/pii-rules.yml", "/privacy/flow-scanner.py", "/code-review/fullscan.py",
    "/code-review/scanners/manifest.json",
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
                # 세션 수명(#13): idle/absolute 초과면 서버측 무효화 → 미인증 처리.
                import time as _time
                _now = _time.time()
                if _session_expired(sessions[token], _now):
                    sessions.pop(token, None)
                else:
                    sessions[token]["last_seen"] = _isoformat_utc(_now)
                if token not in sessions:
                    token = ""  # 만료 → 아래 미인증 경로로
            if token and token in sessions:
                # CSRF: 쿠키 인증된 상태변경 요청에 '교차 출처' Origin 이 붙으면 차단한다.
                # (Origin 이 없는 비브라우저/서버-서버 호출은 통과 — SameSite=Lax 와 이중방어.)
                if request.method in _CSRF_METHODS:
                    origin = request.headers.get("origin", "")
                    if origin and not _origin_allowed(origin, request.headers.get("host", "")):
                        return _StarletteResponse(
                            status_code=403,
                            content='{"detail":"CSRF: cross-origin state change blocked","code":"forbidden","retryable":false}',
                            media_type="application/json",
                        )
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
                content='{"detail":"Unauthorized. Please login at /login","code":"auth_required","retryable":false}',
                media_type="application/json",
            )

    return _SessionAuthMiddleware
