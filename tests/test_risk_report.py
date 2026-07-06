"""R-5: 위험성 평가 대장(risk_register) 증적 리포트 — 빌더 + CSV + 라우트."""
from __future__ import annotations

import importlib.util
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.models import Host, Vulnerability
from mori_soc.services.query_service import InMemoryQueryStore, QueryService
from mori_soc.services.reports import (
    REPORT_TYPES,
    build_risk_register_report,
    report_to_csv,
)

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


def _store():
    now = datetime.now(tz=timezone.utc)
    return InMemoryQueryStore(
        hosts=[Host(host_id="h1", hostname="db-prod-01", status="online", last_seen_at=now)],
        vulnerabilities=[
            Vulnerability(vuln_id="v1", host_id="h1", detected_at=now, source="trivy",
                          cve="CVE-2026-1", severity="critical", fixed_version="1.1"),
            Vulnerability(vuln_id="v2", host_id="h1", detected_at=now, source="trivy",
                          cve="CVE-2026-2", severity="low"),
        ],
    )


class RiskRegisterReportTests(unittest.TestCase):
    def test_registered_type(self) -> None:
        self.assertIn("risk_register", REPORT_TYPES)

    def test_builder_suggests_when_unassessed(self) -> None:
        rep = build_risk_register_report(QueryService(_store()), risk_register={}, asset_owners={})
        self.assertEqual(rep["report_type"], "risk_register")
        self.assertEqual(rep["summary"]["total"], 2)
        self.assertEqual(rep["summary"]["assessed"], 0)
        top = rep["rows"][0]
        self.assertEqual(top["cve"], "CVE-2026-1")
        self.assertEqual(top["level"], "매우높음")  # 상 × critical+patch
        self.assertEqual(top["status"], "자동제안(미평가)")

    def test_builder_uses_stored_assessment(self) -> None:
        register = {"v1": {"impact": 1, "likelihood": 1, "score": 1, "level": "낮음",
                           "treatment": "accept", "accept_approver": "ciso",
                           "residual_level": "낮음", "review_due": "2026-09-01",
                           "assessed_by": "analyst1", "assessed_at": "2026-07-06T20:00:00Z"}}
        rep = build_risk_register_report(QueryService(_store()), risk_register=register, asset_owners={})
        self.assertEqual(rep["summary"]["assessed"], 1)
        v1 = next(r for r in rep["rows"] if r["cve"] == "CVE-2026-1")
        self.assertEqual(v1["level"], "낮음")
        self.assertEqual(v1["treatment"], "accept")
        self.assertEqual(v1["status"], "평가완료")

    def test_csv_has_korean_header_and_treatment_label(self) -> None:
        register = {"v1": {"impact": 3, "likelihood": 3, "score": 9, "level": "매우높음",
                           "treatment": "mitigate", "assessed_by": "a"}}
        rep = build_risk_register_report(QueryService(_store()), risk_register=register, asset_owners={})
        csv_text = report_to_csv(rep)
        self.assertIn("위험등급", csv_text)
        self.assertIn("위험처리", csv_text)
        self.assertIn("조치(경감)", csv_text)  # mitigate → 한글 라벨

    def test_owner_override_importance(self) -> None:
        # 담당자가 중요도를 '하'로 재정의하면 영향도가 낮아진다
        rep = build_risk_register_report(
            QueryService(_store()),
            risk_register={},
            asset_owners={"db-prod-01": {"importance": "하"}},
        )
        top = next(r for r in rep["rows"] if r["cve"] == "CVE-2026-1")
        self.assertEqual(top["importance"], "하")
        self.assertEqual(top["impact"], 1)


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class RiskRegisterReportRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0"}, clear=False):
            self.client = TestClient(create_app(QueryService(_store())))

    def test_reports_list_includes_risk_register(self) -> None:
        r = self.client.get("/compliance/reports")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        types = [x.get("id") for x in body.get("report_types", [])]
        self.assertIn("risk_register", types)

    def test_csv_download(self) -> None:
        r = self.client.get("/compliance/reports/risk_register?format=csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.headers["content-type"])
        self.assertIn("위험등급", r.text)


if __name__ == "__main__":
    unittest.main()
