"""M2-1.7 integration: operational-state write-through + reboot reload over Postgres.

Exercises the 6 UI stores end-to-end through the API (mutate via one app
instance, then reload via a fresh ``create_app_from_env`` to simulate a reboot)
and asserts the change survived in PostgreSQL.

Guarded: runs only when the operational-state backend resolves to Postgres
(``MORI_QUERY_BACKEND=postgres`` or ``MORI_DATABASE_URL`` set) with ``psycopg``
and ``fastapi`` importable. Otherwise skipped, keeping the in-memory suite green.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
import uuid

DATABASE_URL = os.getenv("MORI_DATABASE_URL", "").strip()
BACKEND = os.getenv("MORI_QUERY_BACKEND", "postgres" if DATABASE_URL else "memory").strip().lower()
POSTGRES_STATE = BACKEND == "postgres" and bool(DATABASE_URL)
PSYCOPG_AVAILABLE = importlib.util.find_spec("psycopg") is not None
FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


@unittest.skipUnless(
    POSTGRES_STATE and PSYCOPG_AVAILABLE and FASTAPI_AVAILABLE,
    "requires Postgres operational-state backend + psycopg + fastapi",
)
class StatePersistenceRoundTripTests(unittest.TestCase):
    """변경 → 재부팅(새 app) → 잔존 확인을 6종 store에 대해 검증."""

    @classmethod
    def setUpClass(cls) -> None:
        from mori_soc.api.server import create_app_from_env, create_query_service_from_env

        # 스키마 자립 적용 — 테스트 실행 순서와 무관하게 hosts 등 전 테이블을 보장(순서 의존성 제거).
        dsn = os.getenv("MORI_DATABASE_URL", "").strip()
        if dsn and PSYCOPG_AVAILABLE:
            from mori_soc.repositories.state_postgres import PostgresStateRepository
            PostgresStateRepository(dsn).apply_schema()

        cls.create_app_from_env = staticmethod(create_app_from_env)
        store = create_query_service_from_env().store
        cls.alert_id = store.alerts[0].alert_id if store.alerts else ""
        cls.vuln_id = store.vulnerabilities[0].vuln_id if store.vulnerabilities else ""

    def _client(self):
        from fastapi.testclient import TestClient

        return TestClient(self.create_app_from_env())

    @staticmethod
    def _exec(sql: str, params: tuple) -> None:
        import psycopg

        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute(sql, params)

    @staticmethod
    def _audit_ids() -> set:
        import psycopg

        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute("SELECT log_id FROM ui_asset_audit_log")
            return {r[0] for r in cur.fetchall()}

    def _purge_audit(self, before: set) -> None:
        new = list(self._audit_ids() - before)
        if new:
            self._exec("DELETE FROM ui_asset_audit_log WHERE log_id = ANY(%s)", (new,))

    def test_asset_owner_and_audit_roundtrip(self) -> None:
        host = f"mori-it-{uuid.uuid4().hex[:8]}"
        pre = self._audit_ids()
        self.addCleanup(self._exec, "DELETE FROM ui_asset_owners WHERE hostname=%s", (host,))
        self.addCleanup(self._purge_audit, pre)

        r = self._client().post("/assets/owners", json={"hostname": host, "owner": "담당자", "team": "보안팀"})
        self.assertEqual(r.status_code, 200)

        owners = {o["hostname"]: o for o in self._client().get("/assets/owners").json()["owners"]}
        self.assertIn(host, owners, "owner not reloaded after reboot")
        self.assertEqual(owners[host]["owner"], "담당자")
        self.assertEqual(owners[host]["team"], "보안팀")
        self.assertTrue(len(self._audit_ids() - pre) >= 1, "owner change should append an audit row")

    def test_vuln_action_roundtrip(self) -> None:
        if not self.vuln_id:
            self.skipTest("no vulnerabilities seeded in query store")
        pre = self._audit_ids()
        self.addCleanup(self._exec, "DELETE FROM ui_vuln_actions WHERE vuln_id=%s", (self.vuln_id,))
        self.addCleanup(self._purge_audit, pre)

        r = self._client().put(
            f"/vulnerabilities/{self.vuln_id}/plan",
            json={"plan_text": "패치 적용", "plan_target_date": "2026-03-01", "plan_updated_by": "검증자"},
        )
        self.assertEqual(r.status_code, 200)
        reloaded = self._client().get(f"/vulnerabilities/{self.vuln_id}/action").json()
        self.assertEqual(reloaded.get("plan_text"), "패치 적용")
        self.assertEqual(reloaded.get("plan_target_date"), "2026-03-01")

    def test_triage_history_roundtrip(self) -> None:
        if not self.alert_id:
            self.skipTest("no alerts seeded in query store")
        self.addCleanup(self._exec, "DELETE FROM ui_triage_state WHERE alert_id=%s", (self.alert_id,))

        c = self._client()
        c.patch(f"/alerts/{self.alert_id}/triage", json={"status": "reviewing", "analyst": "분석가", "actor": "검증자"})
        c.patch(f"/alerts/{self.alert_id}/triage", json={"status": "resolved", "analyst": "분석가", "actor": "검증자"})

        rows = {a["alert_id"]: a for a in self._client().get("/alerts").json()["alerts"]}
        tri = rows.get(self.alert_id, {}).get("triage", {})
        self.assertEqual(tri.get("status"), "resolved")
        self.assertEqual(len(tri.get("history", [])), 2, "nested history JSONB not reloaded")

    def test_incident_notes_history_roundtrip(self) -> None:
        c = self._client()
        iid = c.post("/incidents", json={"title": "통합검증 인시던트", "analyst": "분석가"}).json()["incident_id"]
        self.addCleanup(self._exec, "DELETE FROM ui_incidents WHERE incident_id=%s", (iid,))
        c.patch(f"/incidents/{iid}", json={"status": "investigating", "actor": "검증자"})
        c.post(f"/incidents/{iid}/notes", json={"text": "초동 대응", "analyst": "검증자"})

        items = {i["incident_id"]: i for i in self._client().get("/incidents").json()["incidents"]}
        inc = items.get(iid, {})
        self.assertEqual(inc.get("status"), "investigating")
        self.assertEqual(len(inc.get("notes", [])), 1, "nested notes JSONB not reloaded")
        self.assertGreaterEqual(len(inc.get("history", [])), 2, "nested history JSONB not reloaded")

    def test_user_profile_roundtrip(self) -> None:
        username = os.getenv("MORI_ADMIN_USER", "admin").strip()
        password = os.getenv("MORI_ADMIN_PASSWORD", "1234")
        if not username or not password:
            self.skipTest("admin credentials unavailable; cannot authenticate profile write")
        self.addCleanup(self._exec, "DELETE FROM ui_user_profiles WHERE username=%s", (username,))

        c = self._client()
        login = c.post("/auth/login", json={"username": username, "password": password})
        if login.status_code != 200:
            self.skipTest("admin login failed; cannot exercise profile write-through")
        r = c.post("/auth/profile", json={"display_name": "운영자", "department": "보안팀", "assigned_servers": ["srv-a"]})
        self.assertEqual(r.status_code, 200)

        c2 = self._client()
        c2.post("/auth/login", json={"username": username, "password": password})
        prof = c2.get("/auth/profile").json()
        self.assertEqual(prof.get("display_name"), "운영자")
        self.assertEqual(prof.get("assigned_servers"), ["srv-a"])


if __name__ == "__main__":
    unittest.main()
