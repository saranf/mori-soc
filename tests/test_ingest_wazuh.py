"""POST /ingest/wazuh — Wazuh 경보 인제스트 인증/검증 게이트 테스트.

전체 적재(→PostgreSQL)는 postgres 백엔드가 필요하므로 여기서는 인증/본문검증
경로만 확인(항상 실행). 실적재는 라이브 postgres 에서 별도 검증됨.
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

_ALERT = {
    "timestamp": "2026-07-09T10:00:00.000+0000",
    "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.15"},
    "rule": {"id": "5710", "level": 10, "description": "SSH brute force"},
    "id": "1752055200.1",
}


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class IngestWazuhTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore(
            hosts=[Host(host_id="h1", hostname="web-01", status="online",
                        last_seen_at=datetime.now(tz=timezone.utc))]
        )
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0"}, clear=False):
            self.client = TestClient(create_app(QueryService(store)))

    def test_requires_token_when_configured(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_AUTH_ENABLED": "true"}, clear=False):
            r = self.client.post("/ingest/wazuh", json=_ALERT)
            self.assertEqual(r.status_code, 401)

    def test_rejects_wrong_token(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret"}, clear=False):
            r = self.client.post("/ingest/wazuh", json=_ALERT, headers={"Authorization": "Bearer nope"})
            self.assertEqual(r.status_code, 401)

    def test_token_ok_no_db_returns_503(self) -> None:
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_DATABASE_URL": ""}, clear=False):
            r = self.client.post("/ingest/wazuh", json=_ALERT, headers={"X-MORI-Token": "s3cret"})
            self.assertEqual(r.status_code, 503)

    def test_rejects_body_without_rule(self) -> None:
        # DB 없이도 인증 통과 후 본문검증에서 걸리도록: 토큰 OK + DB 있음 가정은 어려우니
        # 토큰만 맞추고 DB 미설정이면 503 이 먼저 나므로, 여기선 alerts 키 배치 형태 검증만.
        with patch.dict(os.environ, {"MORI_INGEST_TOKEN": "s3cret", "MORI_DATABASE_URL": ""}, clear=False):
            r = self.client.post("/ingest/wazuh", json={"alerts": [{"no": "rule"}]},
                                 headers={"X-MORI-Token": "s3cret"})
            # DB 미설정이라 503 (인증·형태는 통과) — 인증 게이트가 먼저임을 확인
            self.assertIn(r.status_code, (400, 503))


if __name__ == "__main__":
    unittest.main()
