"""RouteContext 공용 RBAC 헬퍼(C1) — 8개 라우터 게이트 복붙 제거의 정합성 고정."""
from __future__ import annotations

import unittest

from fastapi import HTTPException

from mori_soc.api.routes.context import RouteContext


class _Req:
    def __init__(self, token: str = "") -> None:
        self.cookies = {"mori_session": token} if token else {}


class RbacHelperTest(unittest.TestCase):
    def _ctx(self, auth=True):
        return RouteContext(app=None, auth_enabled=auth,
                            sessions={"t-admin": {"role": "admin", "username": "al"},
                                      "t-sec": {"role": "security", "username": "se"},
                                      "t-mon": {"role": "monitor", "username": "mo"}})

    def test_session_role_and_username(self) -> None:
        c = self._ctx()
        self.assertEqual(c.session_role(_Req("t-admin")), "admin")
        self.assertEqual(c.session_username(_Req("t-sec")), "se")
        self.assertIsNone(c.session_role(_Req("nope")))
        self.assertEqual(c.session_username(_Req()), "")

    def test_require_role_allows_and_denies(self) -> None:
        c = self._ctx()
        self.assertEqual(c.require_role(_Req("t-admin"), {"admin", "security"}, detail="x"), "admin")
        self.assertEqual(c.require_role(_Req("t-sec"), {"admin", "security"}, detail="x"), "security")
        with self.assertRaises(HTTPException) as e:
            c.require_role(_Req("t-mon"), {"admin", "security"}, detail="denied")
        self.assertEqual(e.exception.status_code, 403)
        with self.assertRaises(HTTPException):
            c.require_role(_Req(), {"admin"}, detail="no session")

    def test_auth_disabled_bypasses(self) -> None:
        c = self._ctx(auth=False)
        # auth off → None 반환(라우터가 데모 기본값으로 처리), 예외 없음
        self.assertIsNone(c.require_role(_Req(), {"admin"}, detail="x"))


if __name__ == "__main__":
    unittest.main()
