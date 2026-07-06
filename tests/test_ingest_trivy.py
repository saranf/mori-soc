"""POST /ingest/trivy — 원격 Trivy 리포트 인제스트 인증 게이트 테스트.

전체 적재(→PostgreSQL)는 postgres 백엔드가 필요하므로 여기서는 인증/검증 경로만
확인한다(항상 실행). 실적재 round-trip 은 라이브 postgres 에서 별도 검증.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.models import Host
from mori_soc.services.query_service import InMemoryQueryStore, QueryService

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class IngestTrivyAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore(
            hosts=[Host(host_id="h1", hostname="onboard-web-01", status="online",
                        last_seen_at=datetime.now(tz=timezone.utc))]
        )
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0"}, clear=False):
            self.client = TestClient(create_app(QueryService(store)))

    def test_requires_token_when_configured(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_AUTH_ENABLED": "true"}, clear=False):
            r = self.client.post("/ingest/trivy", json={"Results": []})
            self.assertEqual(r.status_code, 401)

    def test_rejects_wrong_token(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret"}, clear=False):
            r = self.client.post("/ingest/trivy", json={"Results": []},
                                  headers={"Authorization": "Bearer nope"})
            self.assertEqual(r.status_code, 401)

    def test_token_ok_but_no_db_returns_503(self) -> None:
        # 올바른 토큰이면 인증은 통과, DB 미설정이면 503 (postgres 필요)
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_DATABASE_URL": ""}, clear=False):
            r = self.client.post("/ingest/trivy", json={"ArtifactName": "x", "Results": []},
                                  headers={"X-MORI-Token": "s3cret"})
            self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main()
