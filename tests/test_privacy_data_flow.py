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
    infer_stage,
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
        self.assertEqual(rows[0]["storage_location"], "")   # repo 이름은 넣지 않음(테이블 없으면 빈값)
        self.assertIn("config.py:3", rows[0]["storage_table"])

    def test_seed_uses_db_table_not_repo(self) -> None:
        # Prisma model 스니펫 → 저장위치=테이블명(repo 아님)
        rows = seed_rows_from_findings([
            {"rule_id": "pii-prisma-model", "file": "prisma/schema.prisma", "line": 3,
             "snippet": "model User {\n  phone String\n  email String\n}"},
        ], repo="org/app")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["storage_location"], "User 테이블")
        self.assertIn("User", rows[0]["storage_table"])
        self.assertNotIn("org/app", rows[0]["storage_location"])   # repo 이름 미포함
        self.assertEqual(rows[0]["table"], "User")

    def test_infer_stage_from_path(self) -> None:
        self.assertEqual(infer_stage("src/app/signup/page.tsx"), "수집")
        self.assertEqual(infer_stage("src/app/checkout/page.tsx"), "수집")
        self.assertEqual(infer_stage("prisma/seed.ts"), "저장")
        self.assertEqual(infer_stage("db/schema.sql"), "저장")
        self.assertEqual(infer_stage("src/api/users/route.ts"), "이용")
        self.assertEqual(infer_stage("src/api/me/erase.ts"), "파기")
        self.assertIsNone(infer_stage("README.md"))

    def test_build_pii_rules_valid_yaml_with_defaults_and_custom(self) -> None:
        import yaml

        from mori_soc.services.data_flow import build_pii_semgrep_rules
        y = yaml.safe_load(build_pii_semgrep_rules([{"term": "배송지|shippingAddr", "item": "주소"}]))
        ids = [r["id"] for r in y["rules"]]
        self.assertIn("korean-pii-rrn", ids)          # 리터럴
        self.assertTrue(any(i.startswith("pii-field-") for i in ids))   # 필드명 기본셋
        self.assertIn("pii-custom-0", ids)            # 어드민 커스텀
        for r in y["rules"]:                          # 모든 룰이 generic + regex
            self.assertEqual(r["languages"], ["generic"])
            self.assertIn("pattern-regex", r["patterns"][0])

    def test_seed_routes_collection_point(self) -> None:
        rows = seed_rows_from_findings([
            {"rule_id": "korean-pii-phone", "file": "src/app/signup/page.tsx", "line": 89, "message": "전화"},
            {"rule_id": "korean-pii-phone", "file": "prisma/seed.ts", "line": 14, "message": "전화"},
        ], repo="org/app")
        by_file = {r["file"]: r for r in rows}
        # signup → 수집 칸에 코드위치, 저장 칸 비움
        self.assertIn("signup/page.tsx:89", by_file["src/app/signup/page.tsx"]["collection_source"])
        self.assertEqual(by_file["src/app/signup/page.tsx"]["storage_table"], "")
        # seed → 저장 칸
        self.assertIn("seed.ts:14", by_file["prisma/seed.ts"]["storage_table"])
        self.assertEqual(by_file["prisma/seed.ts"]["collection_source"], "")

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

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "requires reportlab")
    def test_data_flow_pdf_export(self) -> None:
        c = self._client()
        c.post("/privacy/data-flow", json={"item": "이메일", "storage_location": "db", "purpose": "가입"})
        r = c.get("/privacy/data-flow.pdf")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.headers["content-type"], "application/pdf")
        self.assertTrue(r.content.startswith(b"%PDF-"))

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
