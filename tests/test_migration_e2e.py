"""Fresh-install + upgrade(migration) E2E — 실제 PostgreSQL 강제.

목표(‘DB 테스트 skip 금지’): CI 에서 `MORI_QUERY_BACKEND=postgres` + `MORI_DATABASE_URL`
+ postgres service 가 있으면 반드시 실행된다. 로컬에 DB 가 없을 때만 skip.

검증:
  1) fresh install — 빈 DB 에 schema/001~013 을 순서대로 적용, **각 파일이 오류 없이** 적용되는지
     (apply_schema 의 per-file silent-continue 와 달리 여기선 실패를 단정으로 잡는다).
  2) 핵심 테이블이 실제로 생성됐는지(phase 별 대표 테이블).
  3) upgrade/idempotency — 데이터를 넣고 전체 schema 를 재적용해도 오류·데이터 손실이 없는지
     (앱이 매 부팅 self-heal 재적용하는 실제 경로).
  4) 실제 코드 경로(PostgresStateRepository.apply_schema)도 fresh DB 에서 성공하는지.

격리: 전용 임시 데이터베이스를 만들어 쓰고 끝나면 DROP → 다른 테스트 DB 를 건드리지 않는다.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

DATABASE_URL = os.getenv("MORI_DATABASE_URL", "").strip()
BACKEND = os.getenv("MORI_QUERY_BACKEND", "").strip().lower()
POSTGRES_STATE = BACKEND == "postgres" and bool(DATABASE_URL)
PSYCOPG_AVAILABLE = importlib.util.find_spec("psycopg") is not None

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"
_TEST_DB = "mori_mig_e2e"


@unittest.skipUnless(
    POSTGRES_STATE and PSYCOPG_AVAILABLE,
    "requires MORI_QUERY_BACKEND=postgres + MORI_DATABASE_URL + psycopg (CI enforces this)",
)
class MigrationE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        cls._psycopg = psycopg
        base = conninfo_to_dict(DATABASE_URL)
        # 관리 연결(기존 DB)로 임시 DB 를 새로 만든다 — 완전한 fresh install 재현.
        admin = dict(base)
        with psycopg.connect(**admin, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS {_TEST_DB}')
            cur.execute(f'CREATE DATABASE {_TEST_DB}')
        cls._url = make_conninfo(**{**base, "dbname": _TEST_DB})

    @classmethod
    def tearDownClass(cls) -> None:
        from psycopg.conninfo import conninfo_to_dict
        base = conninfo_to_dict(DATABASE_URL)
        with cls._psycopg.connect(**base, autocommit=True) as conn, conn.cursor() as cur:
            # 연결 정리 후 DROP(다른 세션 없어야 함).
            cur.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()", (_TEST_DB,))
            cur.execute(f'DROP DATABASE IF EXISTS {_TEST_DB}')

    def _schema_files(self) -> list[Path]:
        files = sorted(_SCHEMA_DIR.glob("*.sql"))
        self.assertTrue(files, "schema/*.sql not found")
        return files

    def _apply_all(self) -> None:
        """모든 schema 파일을 순서대로 적용 — 실패하면 그 파일명과 함께 테스트 실패."""
        for f in self._schema_files():
            sql = f.read_text(encoding="utf-8")
            if not sql.strip():
                continue
            with self._psycopg.connect(self._url) as conn, conn.cursor() as cur:
                try:
                    cur.execute(sql)
                    conn.commit()
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"schema {f.name} failed to apply: {exc}")

    def _tables(self) -> set[str]:
        with self._psycopg.connect(self._url) as conn, conn.cursor() as cur:
            cur.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            return {r[0] for r in cur.fetchall()}

    def test_fresh_install_applies_all_schema(self) -> None:
        self._apply_all()
        tables = self._tables()
        # phase 별 대표 테이블(순차 마이그레이션이 끝까지 적용됐는지).
        for expected in ("control_evidence", "personal_data_flow", "ui_asset_owners",
                         "ui_risk_register", "ui_evidence_events", "ui_settings"):
            self.assertIn(expected, tables, f"{expected} 테이블이 fresh install 후 없음")

    def test_reapply_is_idempotent_and_preserves_data(self) -> None:
        self._apply_all()
        # 데이터 1건 삽입 → 전체 재적용(upgrade 시나리오) → 그대로 남아야 함(CREATE TABLE IF NOT EXISTS).
        with self._psycopg.connect(self._url) as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO ui_settings (key, value, updated_by, updated_at) "
                "VALUES ('mig_e2e_probe', 'v1', 'test', now()) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
            conn.commit()
        self._apply_all()  # 재적용해도 오류 없어야
        with self._psycopg.connect(self._url) as conn, conn.cursor() as cur:
            cur.execute("SELECT value FROM ui_settings WHERE key = 'mig_e2e_probe'")
            row = cur.fetchone()
        self.assertIsNotNone(row, "재적용 후 데이터가 사라짐(idempotency 위반)")
        self.assertEqual(row[0], "v1")

    def test_real_apply_schema_code_path_on_fresh_db(self) -> None:
        # 앱 부팅 self-heal 과 동일한 실제 코드 경로가 fresh DB 에서 성공하는지.
        from mori_soc.repositories.state_postgres import PostgresStateRepository
        repo = PostgresStateRepository(self._url)
        repo.apply_schema()  # 예외 없이 완료돼야
        self.assertIn("personal_data_flow", self._tables())

    def test_migration_metadata_recorded_with_checksum(self) -> None:
        # schema_migrations 에 파일별 checksum·성공여부가 기록되고, 목록 조회가 동작(#6).
        from mori_soc.repositories.state_postgres import PostgresStateRepository
        repo = PostgresStateRepository(self._url)
        repo.apply_schema()
        rows = repo.applied_migrations()
        self.assertGreaterEqual(len(rows), 13)
        self.assertTrue(all(r["success"] for r in rows))
        self.assertTrue(all(len(r["checksum"]) == 64 for r in rows))   # sha256
        # 재적용해도 개수 동일(idempotent) + 순서 정렬
        repo.apply_schema()
        rows2 = repo.applied_migrations()
        self.assertEqual(len(rows), len(rows2))
        self.assertEqual([r["version"] for r in rows2], sorted(r["version"] for r in rows2))

    def test_audit_log_persist_and_chain(self) -> None:
        # 감사로그 DB 영속 + hash chain 연속성(#20).
        from mori_soc.api.server import _audit_entry_hash, verify_audit_chain
        from mori_soc.repositories.state_postgres import PostgresStateRepository
        repo = PostgresStateRepository(self._url)
        repo.apply_schema()
        prev = "GENESIS"
        for i in range(1, 4):
            e = {"seq": i, "ts": f"2026-01-01T00:00:0{i}+00:00", "username": "u",
                 "action": "LOGIN", "detail": f"d{i}", "prev_hash": prev}
            e["hash"] = _audit_entry_hash(prev, e)
            repo.append_audit_event(e)
            prev = e["hash"]
        loaded = repo.load_audit_events(limit=100)
        self.assertEqual(len(loaded), 3)
        self.assertEqual([r["seq"] for r in loaded], [1, 2, 3])   # seq 오름차순
        self.assertTrue(verify_audit_chain(loaded)["ok"])          # 체인 무결
        self.assertEqual(repo.latest_audit_event()["seq"], 3)      # head 시딩용

    def test_worker_leader_lock_single_holder(self) -> None:
        # 리더 선출(#26): 한 번에 한 연결만 advisory lock 을 쥔다.
        import os
        from unittest.mock import patch

        from mori_soc.worker import _try_acquire_leader
        with patch.dict(os.environ, {"MORI_DATABASE_URL": self._url}, clear=False):
            c1 = _try_acquire_leader()
            self.assertIsNotNone(c1)                 # 첫 획득 = 리더
            self.assertIsNone(_try_acquire_leader())  # 두번째 = standby(None)
            c1.close()

    def test_schema_fail_fast_aborts_on_bad_ddl(self) -> None:
        # 잘못된 DDL + fail-fast → 부팅 중단(불완전 DB 로 서비스 방지). 정상 파일은 idempotent.
        import os
        import tempfile
        from unittest.mock import patch

        from mori_soc.repositories.state_postgres import PostgresStateRepository
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "001_bad.sql"), "w", encoding="utf-8") as fh:
                fh.write("INSERT INTO nonexistent_table VALUES (1);")
            with patch.dict(os.environ, {"MORI_SCHEMA_DIR": d, "MORI_SCHEMA_FAIL_FAST": "true"}, clear=False):
                with self.assertRaises(RuntimeError):
                    PostgresStateRepository(self._url).apply_schema()
            # fail-fast off 면 실패해도 부팅 계속(데모).
            with patch.dict(os.environ, {"MORI_SCHEMA_DIR": d, "MORI_SCHEMA_FAIL_FAST": "false"}, clear=False):
                PostgresStateRepository(self._url).apply_schema()  # 예외 없음


if __name__ == "__main__":
    unittest.main()
