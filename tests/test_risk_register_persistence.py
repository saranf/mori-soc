"""R-2: 위험성 평가 대장(ui_risk_register) 영속화 라운드트립.

StateRepository 계층을 직접 검증한다(HTTP 라우트는 R-3에서 추가).
- InMemory 백엔드: 항상 실행.
- Postgres 백엔드: MORI_DATABASE_URL + psycopg 있을 때만(그 외 skip).
"""
from __future__ import annotations

import importlib.util
import os
import unittest
import uuid

from mori_soc.repositories import InMemoryStateRepository
from mori_soc.services import assess_risk

DATABASE_URL = os.getenv("MORI_DATABASE_URL", "").strip()
BACKEND = os.getenv("MORI_QUERY_BACKEND", "postgres" if DATABASE_URL else "memory").strip().lower()
POSTGRES_STATE = BACKEND == "postgres" and bool(DATABASE_URL)
PSYCOPG_AVAILABLE = importlib.util.find_spec("psycopg") is not None


def _sample_record(vuln_id: str) -> dict:
    a = assess_risk("상", "critical", fixed_available=True)
    return {
        "vuln_id": vuln_id,
        **a.to_dict(),
        "treatment": "accept",
        "accept_reason": "보상통제 존재",
        "accept_approver": "ciso",
        "residual_level": "중간",
        "review_due": "2026-09-01",
        "assessed_by": "analyst1",
        "assessed_at": "2026-07-06T20:00:00Z",
        "updated_at": "2026-07-06T20:00:00Z",
    }


class RiskRegisterMemoryTests(unittest.TestCase):
    def test_roundtrip_and_upsert(self) -> None:
        repo = InMemoryStateRepository()
        rec = _sample_record("CVE-2026-0001")
        repo.save_risk_assessment(rec["vuln_id"], rec)

        back = repo.load_risk_register()[rec["vuln_id"]]
        self.assertEqual(back["score"], 9)
        self.assertEqual(back["level"], "매우높음")
        self.assertEqual(back["treatment"], "accept")
        self.assertEqual(back["accept_approver"], "ciso")

        # write-through 시맨틱: load 결과 변형이 저장소를 오염시키지 않는다(deepcopy)
        back["treatment"] = "mutated"
        self.assertEqual(repo.load_risk_register()[rec["vuln_id"]]["treatment"], "accept")

        # 같은 vuln_id 재저장 → 갱신(업서트)
        repo.save_risk_assessment(rec["vuln_id"], dict(rec, treatment="mitigate", score=6, level="높음"))
        updated = repo.load_risk_register()[rec["vuln_id"]]
        self.assertEqual(updated["treatment"], "mitigate")
        self.assertEqual(updated["level"], "높음")


@unittest.skipUnless(
    POSTGRES_STATE and PSYCOPG_AVAILABLE,
    "requires Postgres operational-state backend + psycopg",
)
class RiskRegisterPostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        from mori_soc.repositories import PostgresStateRepository

        self.repo = PostgresStateRepository(DATABASE_URL)
        self.vuln_id = f"CVE-TEST-{uuid.uuid4().hex[:8]}"

    def tearDown(self) -> None:
        import psycopg

        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM ui_risk_register WHERE vuln_id = %s", (self.vuln_id,))

    def test_roundtrip_survives_reload(self) -> None:
        rec = _sample_record(self.vuln_id)
        self.repo.save_risk_assessment(self.vuln_id, rec)

        # 새 repo 인스턴스로 재조회(= 재부팅 시뮬레이션)
        from mori_soc.repositories import PostgresStateRepository

        loaded = PostgresStateRepository(DATABASE_URL).load_risk_register()[self.vuln_id]
        self.assertEqual(loaded["impact"], 3)
        self.assertEqual(loaded["likelihood"], 3)
        self.assertEqual(loaded["score"], 9)
        self.assertEqual(loaded["level"], "매우높음")
        self.assertEqual(loaded["treatment"], "accept")
        self.assertEqual(loaded["review_due"], "2026-09-01")
        # ISO 타임스탬프는 text로 byte-identical 왕복
        self.assertEqual(loaded["assessed_at"], "2026-07-06T20:00:00Z")

    def test_upsert_updates_in_place(self) -> None:
        self.repo.save_risk_assessment(self.vuln_id, _sample_record(self.vuln_id))
        self.repo.save_risk_assessment(
            self.vuln_id, dict(_sample_record(self.vuln_id), treatment="mitigate", score=6, level="높음")
        )
        loaded = self.repo.load_risk_register()[self.vuln_id]
        self.assertEqual(loaded["treatment"], "mitigate")
        self.assertEqual(loaded["level"], "높음")
        self.assertEqual(loaded["score"], 6)


if __name__ == "__main__":
    unittest.main()
