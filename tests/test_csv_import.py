"""CSV 가져오기 공통 파서 + 자산 담당자 import(#자산 CSV import)."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

from mori_soc.services.csv_import import parse_csv, sample_csv

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None

_ALIASES = {"hostname": ["호스트명", "host"], "owner": ["담당자"], "team": ["팀"]}


class ParseCsvTests(unittest.TestCase):
    def test_header_alias_and_required(self) -> None:
        rows, errs = parse_csv("호스트명,담당자,팀\nweb-01,홍길동,인프라\n,없음,x\n",
                               _ALIASES, required=["hostname"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], {"hostname": "web-01", "owner": "홍길동", "team": "인프라"})
        self.assertEqual(len(errs), 1)   # hostname 없는 행

    def test_special_chars_roundtrip(self) -> None:
        # 콤마·따옴표·개행 포함 값도 표준 파싱
        rows, _ = parse_csv('host,담당자\nweb-1,"김,철수"\n', _ALIASES)
        self.assertEqual(rows[0]["owner"], "김,철수")

    def test_unknown_columns_error(self) -> None:
        rows, errs = parse_csv("foo,bar\n1,2\n", _ALIASES)
        self.assertEqual(rows, [])
        self.assertTrue(errs)

    def test_sample_has_headers(self) -> None:
        s = sample_csv(_ALIASES, {"hostname": "web-01"})
        self.assertIn("hostname", s.splitlines()[0])


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class AssetImportEndpointTests(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_admin_can_import(self) -> None:
        c = self._client()
        c.post("/auth/login", json={"username": "admin", "password": "1234"})
        r = c.post("/assets/owners/import",
                   json={"csv": "호스트명,담당자,팀\nweb-01,홍길동,인프라팀\n"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["imported"], 1)
        owners = c.get("/assets/owners").json()["owners"]
        self.assertTrue(any(o["hostname"] == "web-01" and o["owner"] == "홍길동" for o in owners))

    def test_unknown_host_surfaced_honestly(self) -> None:
        # 모리다움(정직): 현재 자산 목록에 없는 호스트는 배정하되 경고로 표면화(은폐 금지).
        from datetime import datetime, timezone

        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.models import Host
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            store = InMemoryQueryStore()
            store.hosts = [Host(host_id="h1", hostname="web-01", status="online",
                                last_seen_at=datetime.now(timezone.utc))]
            c = TestClient(create_app(QueryService(store)))
            c.post("/auth/login", json={"username": "admin", "password": "1234"})
            r = c.post("/assets/owners/import",
                       json={"csv": "호스트명,담당자\nweb-01,홍길동\nghost-99,김철수"})
        d = r.json()
        self.assertEqual(d["imported"], 2)                 # 둘 다 저장(배정은 유지)
        self.assertEqual(d["unknown_hosts"], ["ghost-99"])  # 미존재 호스트만 표면화
        self.assertTrue(d["warnings"])                      # 정직 경고 제공

    def test_non_privileged_forbidden(self) -> None:
        c = self._client()
        c.post("/auth/login", json={"username": "monitor", "password": "1234"})
        r = c.post("/assets/owners/import", json={"csv": "hostname\nweb-01\n"})
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
