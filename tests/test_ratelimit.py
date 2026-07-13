"""IP 기반 rate limiting(#12) — 초과 시 429, 정상 사용은 통과."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


# 로그인 잠금(#14)이 섞이지 않게 매우 높게 잡아 rate-limit 만 격리 검증한다.
_NO_LOCKOUT = {"MORI_LOGIN_MAX_FAILURES": "100000"}


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class RateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        from mori_soc.api.routes.auth import _LOGIN_FAILURES
        _LOGIN_FAILURES.clear()   # 이전 테스트의 실패 카운터 격리

    def test_login_flood_returns_429(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "",
                                     "MORI_RATELIMIT_LOGIN_MAX": "3",
                                     "MORI_RATELIMIT_WINDOW_SECONDS": "60", **_NO_LOCKOUT}, clear=False):
            from fastapi.testclient import TestClient

            from mori_soc.api.server import create_app
            from mori_soc.services.query_service import InMemoryQueryStore, QueryService
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
            codes = [c.post("/auth/login", json={"username": "x", "password": "y"}).status_code
                     for _ in range(5)]
        self.assertIn(429, codes)                 # 초과분은 429
        self.assertEqual(codes.count(429), 2)     # 3 허용 후 2건 차단

    def test_disabled_allows_all(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "",
                                     "MORI_RATELIMIT_ENABLED": "false",
                                     "MORI_RATELIMIT_LOGIN_MAX": "2", **_NO_LOCKOUT}, clear=False):
            from fastapi.testclient import TestClient

            from mori_soc.api.server import create_app
            from mori_soc.services.query_service import InMemoryQueryStore, QueryService
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
            codes = [c.post("/auth/login", json={"username": "x", "password": "y"}).status_code
                     for _ in range(5)]
        self.assertNotIn(429, codes)              # 비활성 → 제한 없음

    def test_unlimited_paths_not_limited(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "",
                                     "MORI_RATELIMIT_LOGIN_MAX": "2", **_NO_LOCKOUT}, clear=False):
            from fastapi.testclient import TestClient

            from mori_soc.api.server import create_app
            from mori_soc.services.query_service import InMemoryQueryStore, QueryService
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
            codes = [c.get("/health").status_code for _ in range(10)]
        self.assertTrue(all(x == 200 for x in codes))   # /health 는 제한 대상 아님


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class BodyLimitTests(unittest.TestCase):
    def _client(self, env):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        base = {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "", **_NO_LOCKOUT}
        base.update(env)
        with patch.dict(os.environ, base, clear=False):
            return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_oversized_body_413(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "",
                                     "MORI_MAX_BODY_BYTES": "500", **_NO_LOCKOUT}, clear=False):
            from fastapi.testclient import TestClient

            from mori_soc.api.server import create_app
            from mori_soc.services.query_service import InMemoryQueryStore, QueryService
            c = TestClient(create_app(QueryService(InMemoryQueryStore())))
            r = c.post("/auth/login", json={"username": "x" * 1000, "password": "y"})
        self.assertEqual(r.status_code, 413)
        self.assertEqual(r.json()["code"], "payload_too_large")

    def test_findings_cap_logs_and_truncates(self) -> None:
        from mori_soc.api.routes.sources import _extract_code_findings
        with patch.dict(os.environ, {"MORI_MAX_FINDINGS": "3"}, clear=False):
            out = _extract_code_findings({"findings": [{"rule_id": str(i)} for i in range(10)]})
        self.assertEqual(len(out), 3)   # 초과분 잘림
