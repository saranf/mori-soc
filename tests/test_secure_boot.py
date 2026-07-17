"""운영 모드 fail-closed 인증 + /health security_posture 검증(#1)."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None

from mori_soc.api.server import (  # noqa: E402
    _compute_security_posture,
    _enforce_secure_boot,
    _production_mode,
)


class SecureBootUnitTests(unittest.TestCase):
    def test_production_mode_only_when_demo_false(self) -> None:
        for val, expected in (("false", True), ("0", True), ("off", True),
                              ("true", False), ("", False)):
            with patch.dict(os.environ, {"MORI_DEMO_MODE": val}, clear=False):
                self.assertEqual(_production_mode(), expected, val)

    def test_enforce_raises_in_production_without_auth(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_MODE": "false", "MORI_ALLOW_INSECURE_AUTH": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                _enforce_secure_boot(auth_enabled=False)
            _enforce_secure_boot(auth_enabled=True)  # 인증 켜져 있으면 통과(예외 없음)

    def test_enforce_allows_demo_and_escape_hatch(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_MODE": "true"}, clear=False):
            _enforce_secure_boot(auth_enabled=False)  # 데모 → 허용
        with patch.dict(os.environ, {"MORI_DEMO_MODE": "false", "MORI_ALLOW_INSECURE_AUTH": "true"}, clear=False):
            _enforce_secure_boot(auth_enabled=False)  # 명시적 탈출구 → 허용

    def test_enforce_raises_on_insecure_defaults_in_production(self) -> None:
        # 운영 모드 + 인증 켜져도 약한 비밀번호·placeholder 시크릿이 있으면 부팅 거부(#26/C2).
        with patch.dict(os.environ, {"MORI_DEMO_MODE": "false", "MORI_ALLOW_INSECURE_AUTH": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                _enforce_secure_boot(auth_enabled=True, insecure_defaults=["MORI_ADMIN_PASSWORD"])
            _enforce_secure_boot(auth_enabled=True, insecure_defaults=[])  # 문제 없으면 통과

    def test_security_posture(self) -> None:
        self.assertEqual(_compute_security_posture(True, []), "hardened")
        self.assertEqual(_compute_security_posture(False, []), "insecure")   # 인증 꺼짐
        self.assertEqual(_compute_security_posture(True, ["MORI_ADMIN_PASSWORD"]), "insecure")  # 약한 기본값


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class SecureBootAppTests(unittest.TestCase):
    def test_create_app_fails_closed_in_production(self) -> None:
        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        # 운영 모드 + 인증 미설정 → create_app 이 RuntimeError 로 부팅 거부.
        with patch.dict(os.environ, {"MORI_DEMO_MODE": "false", "MORI_AUTH_ENABLED": "",
                                     "MORI_ALLOW_INSECURE_AUTH": "", "MORI_LDAP_ENABLED": "",
                                     "MORI_LDAP_URL": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                create_app(QueryService(InMemoryQueryStore()))

    def test_health_reports_security_posture(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
        body = c.get("/health").json()
        self.assertIn("security_posture", body)
        self.assertEqual(body["security_posture"], "insecure")   # 인증 꺼진 데모 → insecure

    def test_csrf_blocks_cross_origin_state_change(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
            login = c.post("/auth/login", json={"username": "admin", "password": "1234"})
        self.assertEqual(login.status_code, 200, login.text)
        # 교차 출처 Origin → 403(CSRF 차단)
        r_evil = c.post("/assets/owners", json={"hostname": "h", "owner": "o", "team": "t"},
                        headers={"origin": "https://evil.example.com"})
        self.assertEqual(r_evil.status_code, 403)
        # 동일 출처 Origin(testserver) → 통과(200)
        r_ok = c.post("/assets/owners", json={"hostname": "h", "owner": "o", "team": "t"},
                      headers={"origin": "http://testserver"})
        self.assertEqual(r_ok.status_code, 200, r_ok.text)


if __name__ == "__main__":
    unittest.main()
