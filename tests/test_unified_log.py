import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch


class UnifiedLogEndpointTests(unittest.TestCase):
    """GET /admin/logs — 여러 이력 소스 병합 + 검색/필터."""

    def _client(self):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.models.entities import Alert, Host
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        now = datetime.now(tz=timezone.utc)
        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-1", hostname="mbp-01", status="online", last_seen_at=now)],
            alerts=[Alert(alert_id="alert-1", source="zabbix", host_id="host-1", observed_at=now,
                          message="CPU high", severity="high", source_event_id="12345")],
        )
        env = {
            "MORI_DEMO_SEED": "0",
            "MORI_AUTH_ENABLED": "",
            "MORI_LDAP_ENABLED": "",
        }
        with patch.dict(os.environ, env, clear=False):
            return TestClient(create_app(QueryService(store)))

    def test_aggregates_action_and_triage_and_searches(self) -> None:
        client = self._client()

        # 1) 사용자 행동 로그 1건 기록
        client.post("/admin/action-audit-log", json={"action": "QUERY", "detail": "needle-xyz report"})
        # 2) 트리아지 상태 변경 → history 생성
        client.patch("/alerts/alert-1/triage", json={"status": "reviewing", "analyst": "kim", "note": "확인중"})

        resp = client.get("/admin/logs")
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIn("logs", body)
        self.assertIn("total", body)
        self.assertIn("categories", body)

        cats = {l["category"] for l in body["logs"]}
        self.assertIn("action", cats)   # QUERY 기록
        self.assertIn("triage", cats)   # triage history

        # 정규화 필드 존재
        for l in body["logs"]:
            self.assertEqual(set(l) >= {"ts", "actor", "category", "action", "target", "detail", "source"}, True)

        # triage 이벤트에 alert_id 가 target, 상태전이가 action
        triage = [l for l in body["logs"] if l["category"] == "triage"]
        self.assertTrue(any(l["target"] == "alert-1" and "reviewing" in l["action"] for l in triage))

    def test_search_q_filters(self) -> None:
        client = self._client()
        client.post("/admin/action-audit-log", json={"action": "QUERY", "detail": "needle-xyz"})
        client.post("/admin/action-audit-log", json={"action": "INTERPRET", "detail": "other stuff"})

        resp = client.get("/admin/logs", params={"q": "needle-xyz"})
        self.assertEqual(resp.status_code, 200)
        logs = resp.json()["logs"]
        self.assertTrue(logs)
        self.assertTrue(all("needle-xyz" in l["detail"] for l in logs))

    def test_category_filter(self) -> None:
        client = self._client()
        client.post("/admin/action-audit-log", json={"action": "QUERY", "detail": "x"})
        resp = client.get("/admin/logs", params={"category": "login"})
        self.assertEqual(resp.status_code, 200)
        # 로그인 이벤트만 (없으면 빈 목록) — action 은 섞이지 않음
        self.assertTrue(all(l["category"] == "login" for l in resp.json()["logs"]))

    def test_sorted_newest_first(self) -> None:
        client = self._client()
        resp = client.get("/admin/logs")
        logs = resp.json()["logs"]
        ts = [l["ts"] for l in logs]
        self.assertEqual(ts, sorted(ts, reverse=True))


if __name__ == "__main__":
    unittest.main()
