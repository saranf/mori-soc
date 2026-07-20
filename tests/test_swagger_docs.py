"""토스 테마 Swagger /docs 런타임 가드 — 토스 개편(#redesign-toss).

AST 검증(test_openapi_tags)과 별개로, 실제 앱을 띄워 /docs 가 토스 CSS 주입본으로
200 서빙되고 /openapi.json 에 기능 그룹 태그가 순서·설명과 함께 실리는지 확인.
fastapi 설치 환경(CI/venv)에서 실행 — 미설치면 스킵.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient  # noqa: F401

    _HAVE_FASTAPI = True
except Exception:  # pragma: no cover
    _HAVE_FASTAPI = False


@unittest.skipUnless(_HAVE_FASTAPI, "fastapi 미설치 — 런타임 docs 테스트 스킵")
class SwaggerDocsTest(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient
        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_docs_served_with_toss_theme(self) -> None:
        r = self._client().get("/docs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("swagger-ui", r.text)                       # swagger UI 로드
        self.assertIn(".swagger-ui .topbar{display:none}", r.text)  # 토스 CSS 주입
        self.assertIn("#3182f6", r.text)                          # 토스 블루

    def test_openapi_tags_ordered_and_described(self) -> None:
        spec = self._client().get("/openapi.json").json()
        tags = spec.get("tags", [])
        names = [t["name"] for t in tags]
        self.assertEqual(
            names[:5], ["Health", "Auth", "Compliance", "Governance", "Privacy"],
            "기능 그룹 논리 순서(핵심 통제·증적 우선) 불일치",
        )
        self.assertGreaterEqual(len(tags), 16)
        self.assertTrue(all(t.get("description", "").strip() for t in tags), "태그 설명 누락")


if __name__ == "__main__":
    unittest.main()
