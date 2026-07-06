"""R-3: 위험성 평가 API 라우트 테스트 (자동 제안 + 저장/조회 + 감사).

TestClient + 인메모리 store. 데모 시드는 끄고 결정적으로 유지한다.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.models import Host, Vulnerability
from mori_soc.services.query_service import InMemoryQueryStore, QueryService

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class RiskRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        now = datetime.now(tz=timezone.utc)
        # db-* 호스트명 → asset_classifier 가 중요도 '상'(데이터베이스 서버)으로 분류.
        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-1", hostname="db-prod-01", status="online", last_seen_at=now)],
            vulnerabilities=[
                Vulnerability(
                    vuln_id="v-1", host_id="host-1", detected_at=now, source="trivy",
                    cve="CVE-2026-1234", severity="critical",
                    package_name="openssl", installed_version="1.0.0", fixed_version="1.0.1",
                ),
            ],
        )
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0"}, clear=False):
            self.client = TestClient(create_app(QueryService(store)))

    def test_get_suggests_when_unassessed(self) -> None:
        r = self.client.get("/vulnerabilities/v-1/risk")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["suggested"])
        # 중요도 상(3) × critical+패치가용(→likelihood 3) = 9 매우높음
        self.assertEqual(body["impact"], 3)
        self.assertEqual(body["likelihood"], 3)
        self.assertEqual(body["score"], 9)
        self.assertEqual(body["level"], "매우높음")
        self.assertTrue(body["suggestion"]["inputs"]["fixed_available"])
        self.assertEqual(body["suggestion"]["inputs"]["importance"], "상")

    def test_get_404_for_unknown_vuln(self) -> None:
        self.assertEqual(self.client.get("/vulnerabilities/nope/risk").status_code, 404)

    def test_put_accepts_suggestion_and_persists(self) -> None:
        r = self.client.put(
            "/vulnerabilities/v-1/risk",
            json={"treatment": "mitigate", "assessed_by": "analyst1", "review_due": "2026-09-01"},
        )
        self.assertEqual(r.status_code, 200)
        saved = r.json()
        self.assertEqual(saved["score"], 9)
        self.assertEqual(saved["level"], "매우높음")
        self.assertEqual(saved["treatment"], "mitigate")
        self.assertEqual(saved["assessed_by"], "analyst1")
        self.assertIsNotNone(saved["assessed_at"])

        # 재조회 시 저장본이 나오고 suggested=False
        again = self.client.get("/vulnerabilities/v-1/risk").json()
        self.assertFalse(again["suggested"])
        self.assertEqual(again["treatment"], "mitigate")
        self.assertIn("suggestion", again)  # 재산정 제안은 여전히 함께 제공

    def test_put_manual_override_axes(self) -> None:
        r = self.client.put(
            "/vulnerabilities/v-1/risk",
            json={"impact": 1, "likelihood": 2, "treatment": "accept",
                  "accept_reason": "보상통제", "accept_approver": "ciso", "residual_level": "낮음"},
        )
        self.assertEqual(r.status_code, 200)
        saved = r.json()
        self.assertEqual(saved["impact"], 1)
        self.assertEqual(saved["likelihood"], 2)
        self.assertEqual(saved["score"], 2)
        self.assertEqual(saved["level"], "낮음")
        self.assertEqual(saved["accept_approver"], "ciso")

    def test_put_rejects_bad_axes(self) -> None:
        r = self.client.put("/vulnerabilities/v-1/risk", json={"impact": 9, "likelihood": 1})
        self.assertEqual(r.status_code, 400)

    def test_put_rejects_bad_treatment(self) -> None:
        r = self.client.put("/vulnerabilities/v-1/risk", json={"treatment": "ignore-it"})
        self.assertEqual(r.status_code, 400)

    def test_put_writes_audit_log(self) -> None:
        self.client.put("/vulnerabilities/v-1/risk", json={"treatment": "accept", "assessed_by": "analyst1"})
        # asset_audit_log 에 vuln_level / vuln_treatment 변경이 기록됐는지 확인
        rows = self.client.get("/admin/audit-log").json()["audit_log"]
        fields = " ".join(str(r.get("field", "")) for r in rows)
        self.assertIn("vuln_treatment", fields)
        self.assertIn("vuln_level", fields)


if __name__ == "__main__":
    unittest.main()
