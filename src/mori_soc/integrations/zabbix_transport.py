"""Zabbix JSON-RPC transport (write-back 공용).

MORI 는 이미 :class:`mori_soc.collectors.zabbix_events.ZabbixEventCollector`
안에 검증된 JSON-RPC transport(``_api_call`` / ``_perform_api_call`` /
``_login``)를 가지고 있다. 이 모듈은 그 로직을 write-back 클라이언트가
재사용할 수 있도록 독립 클래스로 옮겨 담은 것이다.

인증 폴백은 콜렉터와 동일한 규칙을 따른다.
  * API 토큰이 있으면 ``Authorization: Bearer <token>`` 헤더 우선.
  * 서버가 body 의 ``auth`` 파라미터를 거부하면(신형 Zabbix) 헤더로 재시도.
  * user/password 로그인은 ``username`` → ``user`` 키 순서로 폴백.

TODO(후속): 콜렉터도 이 transport 로 통합해 중복 제거. 현재 콜렉터 쪽
transport 는 테스트가 내부 메서드/urlopen 경로에 묶여 있어 MVP 에서는
건드리지 않는다.
"""

from __future__ import annotations

import json
from urllib import error, request


class ZabbixApiError(RuntimeError):
    """Raised when the Zabbix API returns a JSON-RPC ``error`` object or the
    HTTP request itself fails."""


class ZabbixTransport:
    """Minimal JSON-RPC caller for a single Zabbix API endpoint."""

    def __init__(
        self,
        api_url: str,
        *,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        request_timeout: int = 10,
    ) -> None:
        if not api_url:
            raise ValueError("Zabbix API URL is required")
        self._api_url = api_url
        self._token = token or None
        self._username = username or None
        self._password = password or None
        self._request_timeout = request_timeout
        self._session_auth: str | None = None

    def resolve_auth(self) -> str:
        """Return an auth token, logging in with user/password if needed.

        Session logins are cached for the lifetime of the transport instance.
        """
        if self._token:
            return self._token
        if self._session_auth:
            return self._session_auth
        self._session_auth = self._login()
        return self._session_auth

    def call(self, method: str, params: dict[str, object], *, auth: str | None = None):
        """Invoke *method* with *params*, resolving auth automatically."""
        resolved = auth if auth is not None else self.resolve_auth()
        prefer_auth_header = bool(resolved and self._token)
        try:
            return self._perform(method, params, auth=resolved, use_auth_header=prefer_auth_header)
        except ZabbixApiError as exc:
            if resolved and not prefer_auth_header and 'unexpected parameter "auth"' in str(exc):
                return self._perform(method, params, auth=resolved, use_auth_header=True)
            raise

    # ── internals ─────────────────────────────────────────────────────────────
    def _login(self) -> str:
        if not self._username or not self._password:
            raise ZabbixApiError("Zabbix API credentials are missing")
        try:
            return str(self._perform("user.login", {"username": self._username, "password": self._password}, auth=None))
        except ZabbixApiError as exc:
            if "Invalid params" not in str(exc):
                raise
        return str(self._perform("user.login", {"user": self._username, "password": self._password}, auth=None))

    def _perform(
        self,
        method: str,
        params: dict[str, object],
        *,
        auth: str | None = None,
        use_auth_header: bool = False,
    ):
        payload: dict[str, object] = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        if auth and not use_auth_header:
            payload["auth"] = auth
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json-rpc"}
        if auth and use_auth_header:
            headers["Authorization"] = f"Bearer {auth}"
        req = request.Request(self._api_url, data=body, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=self._request_timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            raise ZabbixApiError(f"Zabbix API request failed: {exc}") from exc
        if "error" in data:
            err = data["error"]
            raise ZabbixApiError(
                f"Zabbix API error {err.get('code')}: {err.get('message')} {err.get('data', '')}".strip()
            )
        return data.get("result", [])


__all__ = ["ZabbixTransport", "ZabbixApiError"]
