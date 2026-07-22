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
    _https_ok,
    _production_mode,
    _strict_profile,
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
        # 운영 모드가 아닌 기본(데모)에서는 auth+시크릿만 본다.
        with patch.dict(os.environ, {"MORI_DEMO_MODE": "", "MORI_PROFILE": ""}, clear=False):
            self.assertEqual(_compute_security_posture(True, []), "hardened")
        self.assertEqual(_compute_security_posture(False, []), "insecure")   # 인증 꺼짐
        self.assertEqual(_compute_security_posture(True, ["MORI_ADMIN_PASSWORD"]), "insecure")  # 약한 기본값

    # ── M5: MORI_PROFILE=production 한 줄 프로파일 + HTTPS 게이트/태세 ─────────────
    def test_strict_profile_implies_production(self) -> None:
        with patch.dict(os.environ, {"MORI_PROFILE": "production", "MORI_DEMO_MODE": ""}, clear=False):
            self.assertTrue(_strict_profile())
            self.assertTrue(_production_mode())

    def test_https_ok_sources(self) -> None:
        with patch.dict(os.environ, {"MORI_PUBLIC_URL": "https://m", "MORI_COOKIE_SECURE": "",
                                     "MORI_BEHIND_TLS_PROXY": ""}, clear=False):
            self.assertTrue(_https_ok())
        with patch.dict(os.environ, {"MORI_PUBLIC_URL": "http://m", "MORI_COOKIE_SECURE": "",
                                     "MORI_BEHIND_TLS_PROXY": "true"}, clear=False):
            self.assertTrue(_https_ok())
        with patch.dict(os.environ, {"MORI_PUBLIC_URL": "http://m", "MORI_COOKIE_SECURE": "",
                                     "MORI_BEHIND_TLS_PROXY": ""}, clear=False):
            self.assertFalse(_https_ok())

    def test_strict_profile_refuses_plain_http(self) -> None:
        with patch.dict(os.environ, {"MORI_PROFILE": "production", "MORI_PUBLIC_URL": "http://x",
                                     "MORI_COOKIE_SECURE": "", "MORI_BEHIND_TLS_PROXY": "",
                                     "MORI_ALLOW_INSECURE_AUTH": ""}, clear=False):
            with self.assertRaises(RuntimeError):
                _enforce_secure_boot(auth_enabled=True, insecure_defaults=[])

    def test_strict_profile_ok_behind_tls_proxy(self) -> None:
        with patch.dict(os.environ, {"MORI_PROFILE": "production", "MORI_BEHIND_TLS_PROXY": "true",
                                     "MORI_ALLOW_INSECURE_AUTH": ""}, clear=False):
            _enforce_secure_boot(auth_enabled=True, insecure_defaults=[])  # 통과

    def test_demo_off_alone_does_not_https_refuse(self) -> None:
        # 엄격 프로파일이 아니면 HTTPS 미구성만으로 부팅을 막지 않는다(기존 배포 호환).
        with patch.dict(os.environ, {"MORI_PROFILE": "", "MORI_DEMO_MODE": "false",
                                     "MORI_PUBLIC_URL": "http://x", "MORI_BEHIND_TLS_PROXY": "",
                                     "MORI_ALLOW_INSECURE_AUTH": ""}, clear=False):
            _enforce_secure_boot(auth_enabled=True, insecure_defaults=[])  # 통과


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
