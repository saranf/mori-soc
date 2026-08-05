"""온보딩 라우트 E2E(R6) — admin 로그인 세션으로 5개 조회 + 연결테스트 게이트."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

_HAS_FASTAPI = importlib.util.find_spec("fastapi") is not None


@unittest.skipUnless(_HAS_FASTAPI, "requires fastapi")
class OnboardingRoutesTest(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        # 인증 켜고 admin/1234 로그인 — 세션 쿠키로 admin·security 게이트 통과.
        with patch.dict(os.environ, {"MORI_AUTH_ENABLED": "1", "MORI_ADMIN_PASSWORD": "1234",
                                     "MORI_DEMO_SEED": "0", "MORI_LDAP_ENABLED": ""}, clear=False):
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
        login = c.post("/auth/login", json={"username": "admin", "password": "1234"})
        self.assertEqual(login.status_code, 200, login.text)
        return c

    def test_status_checklist_shape(self) -> None:
        r = self._client().get("/onboarding/status")
        self.assertEqual(r.status_code, 200, r.text)
        d = r.json()
        self.assertEqual(d["checklist"]["total"], 5)
        self.assertIn("security_posture", d)
        self.assertIn("version", d)

    def test_connectors_include_pull_and_push(self) -> None:
        r = self._client().get("/onboarding/connectors")
        self.assertEqual(r.status_code, 200, r.text)
        by = {c["id"]: c for c in r.json()["connectors"]}
        self.assertEqual(by["zabbix"]["maturity"], "verified")
        self.assertTrue(by["zabbix"]["testable"])
        self.assertFalse(by["trivy"]["testable"])

    def test_scan_setup_free_default(self) -> None:
        d = self._client().get("/onboarding/scan-setup").json()
        self.assertTrue(d["free"])
        self.assertEqual(d["default_scanner"], "semgrep")
        self.assertIn("workflow_content", d)

    def test_go_live_five_steps(self) -> None:
        d = self._client().get("/onboarding/go-live").json()
        self.assertEqual(d["total"], 5)

    def test_control_todo_ok(self) -> None:
        r = self._client().get("/onboarding/control-todo?limit=3")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("total", r.json())

    def test_connector_test_rejects_push_source(self) -> None:
        # push 커넥터는 라이브 연결 테스트 불가 → 400 (CSRF 통과 위해 동일 출처 Origin).
        r = self._client().post("/onboarding/connectors/trivy/test", headers={"origin": "http://testserver"})
        self.assertEqual(r.status_code, 400, r.text)


if __name__ == "__main__":
    unittest.main()
