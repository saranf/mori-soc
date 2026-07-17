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

    def test_evidence_approval_persist(self) -> None:
        # 증적 승인 스냅샷 영속·조회(#4 불변 기록).
        from mori_soc.repositories.state_postgres import PostgresStateRepository
        repo = PostgresStateRepository(self._url)
        repo.apply_schema()
        rec = {"approval_id": "appr-x1", "control_id": "3.1.1", "evidence_id": "3.1.1",
               "content_hash": "h" * 64, "version": "hhhhhhhhhhhh", "status": "approved",
               "reviewer": "", "approver": "admin", "reviewed_at": "", "approved_at": "2026-07-01T00:00:00+00:00",
               "pdf_sha256": "p" * 64, "prev_approval_id": "", "supersede_reason": "", "actor": "admin"}
        repo.save_evidence_approval("appr-x1", rec)
        rows = repo.load_evidence_approvals("3.1.1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "approved")
        self.assertEqual(rows[0]["pdf_sha256"], "p" * 64)

    def test_control_governance_persist_events_and_as_of(self) -> None:
        """통제 거버넌스 시나리오 E2E(S4): 등록 → 운영 → 버전변경 → 이관 → 재시작 → 과거 재현.

        실 postgres 에 저장하고 새 repo 인스턴스(=재시작)로 다시 읽어 governance 객체·이벤트
        원장·history 가 보존되는지, hash chain 이 무결한지, as-of 재현이 되는지 검증한다.
        """
        from mori_soc.repositories.state_postgres import PostgresStateRepository
        from mori_soc.services.control_governance import (
            apply_cycle_control_update,
            build_cycle_control,
            build_framework_version,
            build_governance_event,
            cycle_control_as_of,
            plan_cycle_migration,
            verify_governance_chain,
        )
        repo = PostgresStateRepository(self._url)
        repo.apply_schema()

        # 1) ISMS-P 2019 등록 + 통제 정의(구버전)
        v19 = build_framework_version(framework_id="ISMS-P", version="2019", now="2019-01-01")
        repo.save_governance("framework_version", v19["id"], v19)
        old_ctl = {"id": "isms-p:2019:2.9.4", "framework_version_id": "isms-p:2019",
                   "control_uid": "log", "display_code": "2.9.4", "title": "로그",
                   "requirement_text": "분기", "interpretations": {}}
        repo.save_governance("control_definition", old_ctl["id"], old_ctl)

        # 2) 2025 주기 통제 — 담당자·적용성 설정, 증적 approved·평가 effective 로 운영
        cc25 = build_cycle_control(cycle_id="c2025", control_ref="isms-p:2019:2.9.4",
                                   assignee="김보안", applicability="applicable",
                                   now="2025-02-01T00:00:00+00:00", created_by="u")
        apply_cycle_control_update(cc25, actor="u", now="2025-06-01T00:00:00+00:00",
                                   evidence_status="approved", assessment_status="effective")
        cc25.pop("_changed", None)
        repo.save_governance("cycle_control", cc25["id"], cc25)

        # 이벤트 원장에 create/update 기록(hash chain)
        prev = "GENESIS"
        for rev, etype in ((1, "create"), (2, "update")):
            ev = build_governance_event(prev, kind="cycle_control", entity_id=cc25["id"],
                                        revision=rev, event_type=etype, actor="u",
                                        occurred_at=f"2025-0{rev}-01T00:00:00+00:00", payload={})
            repo.append_governance_event(ev)
            prev = ev["hash"]

        # 3) ISMS-P 2023 — 통제 번호·내용 변경(2.9.4 → 2.10.2, 요구 변경)
        v23 = build_framework_version(framework_id="ISMS-P", version="2023", now="2023-01-01")
        repo.save_governance("framework_version", v23["id"], v23)
        new_ctl = {"id": "isms-p:2023:2.10.2", "framework_version_id": "isms-p:2023",
                   "control_uid": "log", "display_code": "2.10.2", "title": "로그",
                   "requirement_text": "월간", "interpretations": {}}
        repo.save_governance("control_definition", new_ctl["id"], new_ctl)

        # 4) 2026 주기 이관 — 계보 기반 마이그레이션
        plan = plan_cycle_migration([cc25], [old_ctl], [new_ctl], "c2026",
                                    now="2026-01-01T00:00:00+00:00", created_by="u")
        for cc in plan["cycle_controls"]:
            repo.save_governance("cycle_control", cc["id"], cc)

        # 5) 재시작(새 repo 인스턴스)
        repo2 = PostgresStateRepository(self._url)

        # governance 객체 보존
        ccs = repo2.load_governance("cycle_control")
        by_id = {c["id"]: c for c in ccs}
        self.assertIn("c2025:isms-p-2019-2.9.4", by_id)
        migrated = by_id["c2026:isms-p-2023-2.10.2"]
        self.assertEqual(migrated["assignee"], "김보안")               # 담당자 승계
        self.assertEqual(migrated["assessment_status"], "not_assessed")  # 평가 초기화
        self.assertEqual(migrated["carried_from_control_ref"], "isms-p:2019:2.9.4")
        self.assertTrue(migrated["requires_design_review"])              # 내용 변경

        # 이벤트 원장·hash chain 보존
        events = repo2.load_governance_events()
        self.assertGreaterEqual(len(events), 2)
        self.assertTrue(verify_governance_chain(
            repo2.load_governance_events(kind="cycle_control", entity_id=cc25["id"]))["ok"])

        # 6) 과거 재현 — 2025 통제의 2025-03 시점(승인 전)과 2025-07 시점(승인 후) 모두 재현
        cc25_loaded = by_id["c2025:isms-p-2019-2.9.4"]
        mar = cycle_control_as_of(cc25_loaded, "2025-03-01T00:00:00+00:00")
        self.assertEqual(mar["evidence_status"], "missing")           # 승인 전
        self.assertEqual(mar["assignee"], "김보안")                    # 최초 상태 복원(S1b)
        jul = cycle_control_as_of(cc25_loaded, "2025-07-01T00:00:00+00:00")
        self.assertEqual(jul["evidence_status"], "approved")          # 승인 후
        self.assertEqual(jul["assessment_status"], "effective")

    def test_migration_immutability_gate(self) -> None:
        """C3: 이미 성공 적용된 마이그레이션의 체크섬이 바뀌면 운영모드 부팅 거부(이력 덮기 금지)."""
        import os
        from unittest.mock import patch

        from mori_soc.repositories.state_postgres import (
            PostgresStateRepository,
            _schema_dir,
        )
        repo = PostgresStateRepository(self._url)
        repo.apply_schema()
        # 이미 적용된 한 마이그레이션의 기록 체크섬을 인위적으로 변조(=파일이 바뀐 상황을 모사).
        with self._psycopg.connect(self._url) as conn, conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations WHERE success = true ORDER BY version LIMIT 1")
            ver = cur.fetchone()[0]
            cur.execute("UPDATE schema_migrations SET checksum = %s WHERE version = %s",
                        ("0" * 64, ver))
            conn.commit()
        drift = repo._detect_migration_drift(_schema_dir())
        self.assertTrue(any(v == ver for v, _, _ in drift))
        # 운영 모드(fail-fast) → 부팅 거부
        with patch.dict(os.environ, {"MORI_SCHEMA_FAIL_FAST": "true"}, clear=False):
            with self.assertRaises(RuntimeError):
                repo.apply_schema()
        # 완화 모드 → 경고만, 통과
        with patch.dict(os.environ, {"MORI_SCHEMA_FAIL_FAST": "false"}, clear=False):
            repo.apply_schema()   # 예외 없이 완료(드리프트 기록은 재적용으로 정정됨)

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
