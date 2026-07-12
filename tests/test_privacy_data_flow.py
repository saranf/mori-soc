"""개인정보 처리흐름표/흐름도 — 서비스(순수) + 라우트(항상 실행).

영속은 InMemoryStateRepository(create_app 기본)로 검증되고, PostgreSQL 은
control_evidence 와 동형이라 별도 라이브 검증에 맡긴다.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

from mori_soc.models import Alert, Host
from mori_soc.services.data_flow import (
    infer_item,
    is_pii_finding,
    render_data_flow_svg,
    seed_rows_from_findings,
)
from mori_soc.services.query_service import InMemoryQueryStore, QueryService

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


class DataFlowServiceTests(unittest.TestCase):
    def test_is_pii_finding_detects_signals(self) -> None:
        self.assertTrue(is_pii_finding({"rule_id": "py/hardcoded-secret"}))
        self.assertTrue(is_pii_finding({"category": "email exposure", "message": "이메일 노출"}))
        self.assertTrue(is_pii_finding({"message": "주민등록번호 저장"}))
        self.assertFalse(is_pii_finding({"rule_id": "py/unused-import", "message": "unused"}))

    def test_infer_item(self) -> None:
        self.assertIn("이메일", infer_item({"message": "email leaked"}))
        self.assertIn("주민등록번호", infer_item({"rule_id": "ssn-detector"}))

    def test_korean_pii_rule_ids_classify(self) -> None:
        # 워크플로 커스텀 룰(korean-pii-*)이 MORI 측에서 PII 로 분류·항목추론돼야 한다.
        for rid, item in (("korean-pii-rrn", "주민등록번호"), ("korean-pii-phone", "전화번호"),
                          ("korean-pii-card", "카드번호")):
            self.assertTrue(is_pii_finding({"rule_id": rid}), rid)
            self.assertIn(item, infer_item({"rule_id": rid}), rid)

    def test_seed_rows_dedupe_and_fields(self) -> None:
        findings = [
            {"rule_id": "py/hardcoded-secret", "file": "config.py", "line": 3, "message": "api key"},
            {"rule_id": "py/hardcoded-secret", "file": "config.py", "line": 3, "message": "api key"},  # dup
            {"rule_id": "py/unused", "file": "x.py", "line": 1, "message": "unused"},  # not PII
        ]
        rows = seed_rows_from_findings(findings, repo="org/app")
        self.assertEqual(len(rows), 1)              # dup collapsed, non-PII skipped
        self.assertEqual(rows[0]["source"], "pii_scan")
        self.assertEqual(rows[0]["storage_location"], "org/app")
        self.assertIn("config.py:3", rows[0]["storage_table"])

    def test_render_svg_has_stages_and_values(self) -> None:
        svg = render_data_flow_svg([{"item": "이메일", "collection_source": "회원가입",
                                     "storage_location": "user-db", "storage_table": "users",
                                     "purpose": "회원관리", "destruction": "즉시파기", "overseas": "AWS 도쿄"}])
        for stage in ("수집", "저장", "이용", "파기"):
            self.assertIn(stage, svg)
        self.assertIn("user-db", svg)
        self.assertIn("국외이전", svg)               # overseas 배지
        self.assertTrue(svg.startswith("<svg"))


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class PrivacyRouteTests(unittest.TestCase):
    def _client(self, alerts=None):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore(
            hosts=[Host(host_id="h1", hostname="w", status="online",
                        last_seen_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))],
            alerts=alerts or [],
        )
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            return TestClient(create_app(QueryService(store)))

    def test_crud_svg_csv_promote(self) -> None:
        c = self._client()
        # 추가
        r = c.post("/privacy/data-flow", json={"item": "이메일, 이름", "storage_location": "user-db",
                                               "storage_table": "users(email)", "purpose": "회원관리",
                                               "destruction": "탈퇴 즉시", "overseas": "AWS 도쿄"})
        self.assertEqual(r.status_code, 200, r.text)
        fid = r.json()["id"]
        # 목록
        self.assertEqual(len(c.get("/privacy/data-flow").json()["rows"]), 1)
        # 수정
        self.assertEqual(c.put(f"/privacy/data-flow/{fid}", json={"purpose": "회원관리·CS"}).json()["purpose"], "회원관리·CS")
        # svg / csv
        sv = c.get("/privacy/data-flow.svg")
        self.assertEqual(sv.status_code, 200)
        self.assertIn("image/svg", sv.headers["content-type"])
        self.assertIn("user-db", sv.text)
        cs = c.get("/privacy/data-flow.csv")
        self.assertIn("개인정보 항목", cs.text)
        # 승격 → 3.1.1/3.2.1/3.4.1
        p = c.post("/privacy/data-flow/promote-evidence")
        self.assertEqual(p.json()["evidence_promoted"], 3)
        recs = [x for x in c.get("/controls/detail/3.2.1").json().get("evidence_records", [])
                if x.get("source") == "privacy_flow"]
        self.assertEqual(len(recs), 1)
        # 삭제
        self.assertTrue(c.delete(f"/privacy/data-flow/{fid}").json()["ok"])
        self.assertEqual(len(c.get("/privacy/data-flow").json()["rows"]), 0)

    def test_seed_from_scan_uses_pii_code_review_alerts(self) -> None:
        import datetime as _dt

        now = _dt.datetime.now(_dt.timezone.utc)
        alerts = [
            Alert(alert_id="c1", source="code_review", observed_at=now, message="hardcoded secret",
                  severity="high", rule_id="py/hardcoded-secret",
                  raw_payload={"file": "config.py", "line": 3, "rule_id": "py/hardcoded-secret",
                               "_provenance": {"repo": "org/app"}}),
            Alert(alert_id="c2", source="code_review", observed_at=now, message="unused import",
                  severity="low", rule_id="py/unused",
                  raw_payload={"file": "x.py", "line": 1, "rule_id": "py/unused",
                               "_provenance": {"repo": "org/app"}}),
        ]
        c = self._client(alerts=alerts)
        r = c.post("/privacy/data-flow/seed-from-scan")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["seeded"], 1)      # PII 1건만 시드(unused 제외)
        rows = c.get("/privacy/data-flow").json()["rows"]
        self.assertEqual(rows[0]["source"], "pii_scan")

    def test_role_gate_blocks_non_privileged(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore()
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            c = TestClient(create_app(QueryService(store)))
        # 미인증: 세션 미들웨어(401) 또는 라우트 role gate(403) 어느 쪽이든 차단돼야 한다.
        self.assertIn(c.get("/privacy/data-flow").status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
