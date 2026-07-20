"""RouteContext 공용 RBAC/세션 헬퍼 — 공통화 C3 회귀 방지.

라우터별로 복붙되던 쿠키→세션→role 추출과 403 게이트를 이 헬퍼로 단일화했다.
동작(auth off 통과·비권한 403·권한 통과·request None 안전)을 여기서 고정한다.
"""
from __future__ import annotations

import unittest

from mori_soc.api.routes.context import RouteContext


class _Req:
    def __init__(self, token: str = "") -> None:
        self.cookies = {"mori_session": token} if token else {}


def _ctx(auth_enabled: bool = True) -> RouteContext:
    sessions = {"tok-admin": {"role": "admin", "username": "adm"},
                "tok-sec": {"role": "security", "username": "sec"},
                "tok-infra": {"role": "infra", "username": "inf"}}
    return RouteContext(app=None, sessions=sessions, auth_enabled=auth_enabled)


class RouteContextRbacTests(unittest.TestCase):
    def test_session_role_and_username(self) -> None:
        ctx = _ctx()
        self.assertEqual(ctx.session_role(_Req("tok-admin")), "admin")
        self.assertEqual(ctx.session_username(_Req("tok-sec")), "sec")
        self.assertIsNone(ctx.session_role(_Req("nope")))
        self.assertEqual(ctx.session_username(_Req()), "")

    def test_session_safe_when_request_none(self) -> None:
        self.assertIsNone(_ctx().session(None))
        self.assertEqual(_ctx().session_username(None), "")

    def test_require_admin_or_security_passes_for_privileged(self) -> None:
        ctx = _ctx()
        self.assertEqual(ctx.require_admin_or_security(_Req("tok-admin"), detail="x"), "admin")
        self.assertEqual(ctx.require_admin_or_security(_Req("tok-sec"), detail="x"), "security")

    def test_require_admin_or_security_403_for_non_privileged(self) -> None:
        from fastapi import HTTPException
        ctx = _ctx()
        with self.assertRaises(HTTPException) as cm:
            ctx.require_admin_or_security(_Req("tok-infra"), detail="nope")
        self.assertEqual(cm.exception.status_code, 403)
        with self.assertRaises(HTTPException):
            ctx.require_admin_or_security(_Req("nope"), detail="nope")

    def test_auth_disabled_bypasses_gate(self) -> None:
        ctx = _ctx(auth_enabled=False)
        self.assertIsNone(ctx.require_admin_or_security(_Req(), detail="x"))
        self.assertIsNone(ctx.require_role(_Req(), {"admin"}, detail="x"))

    def test_require_role_custom_set(self) -> None:
        from fastapi import HTTPException
        ctx = _ctx()
        self.assertEqual(ctx.require_role(_Req("tok-infra"), {"infra", "admin"}, detail="x"), "infra")
        with self.assertRaises(HTTPException):
            ctx.require_role(_Req("tok-infra"), {"admin"}, detail="x")


if __name__ == "__main__":
    unittest.main()
