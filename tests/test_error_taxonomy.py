"""에러 택소노미(#39) — 응답에 안정 code·retryable."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

from mori_soc.api.errors import error_body, error_meta

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


class ErrorMetaTests(unittest.TestCase):
    def test_status_map(self) -> None:
        self.assertEqual(error_meta(400), ("validation_error", False))
        self.assertEqual(error_meta(403), ("forbidden", False))
        self.assertEqual(error_meta(429), ("rate_limited", True))
        self.assertEqual(error_meta(503), ("source_unavailable", True))
        self.assertEqual(error_meta(599)[1], True)   # 5xx 기본 재시도

    def test_error_body_defaults_and_override(self) -> None:
        self.assertEqual(error_body(400, "bad"),
                         {"detail": "bad", "code": "validation_error", "retryable": False})
        # 핸들러가 구조화 detail 로 code/retryable 명시 시 존중
        over = error_body(500, {"detail": "x", "code": "source_unavailable", "retryable": True})
        self.assertEqual(over["code"], "source_unavailable")
        self.assertTrue(over["retryable"])


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class ErrorResponseTests(unittest.TestCase):
    def _client(self, auth="1"):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": auth}, clear=False):
            return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_400_has_code(self) -> None:
        r = self._client().post("/auth/login", json={"username": "", "password": ""})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["code"], "validation_error")
        self.assertFalse(r.json()["retryable"])

    def test_middleware_401_has_code(self) -> None:
        # 세션 미들웨어 발신 401 도 code/retryable 포함
        r = self._client().get("/privacy/data-flow")
        self.assertIn(r.status_code, (401, 403))
        self.assertIn(r.json().get("code"), ("auth_required", "forbidden"))


if __name__ == "__main__":
    unittest.main()
