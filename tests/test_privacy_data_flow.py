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
        # 개인정보는 True, 서비스 시크릿(API키·토큰)은 개인정보가 아니므로 False(분리).
        self.assertTrue(is_pii_finding({"category": "email exposure", "message": "이메일 노출"}))
        self.assertTrue(is_pii_finding({"message": "주민등록번호 저장"}))
        self.assertFalse(is_pii_finding({"rule_id": "py/hardcoded-secret", "message": "AWS api key"}))
        self.assertFalse(is_pii_finding({"rule_id": "py/unused-import", "message": "unused"}))

    def test_infer_item(self) -> None:
        self.assertIn("이메일", infer_item({"message": "email leaked"}))
        self.assertIn("주민등록번호", infer_item({"rule_id": "ssn-detector"}))
        # 단어경계로 부분문자열 오탐 차단(monkey→key, discard→card, headphone→phone, IP address→주소).
        self.assertEqual(infer_item({"message": "monkeypatch keyword"}), "")
        self.assertEqual(infer_item({"message": "discard the IP address"}), "")

    def test_korean_pii_rule_ids_classify(self) -> None:
        # 커스텀 룰(korean-pii-*)은 항목명이 담긴 message 로 오므로 그 message 로 분류·항목추론된다.
        for msg, item in (("주민등록번호로 보이는 값", "주민등록번호"),
                          ("휴대폰번호로 보이는 값", "전화번호"),
                          ("카드번호로 보이는 값", "카드번호")):
            f = {"rule_id": "korean-pii-x", "message": msg}
            self.assertTrue(is_pii_finding(f), msg)
            self.assertIn(item, infer_item(f), msg)

    def test_seed_rows_dedupe_and_fields(self) -> None:
        findings = [
            {"rule_id": "pii-field", "file": "db/schema.sql", "line": 3, "message": "email column"},
            {"rule_id": "pii-field", "file": "db/schema.sql", "line": 3, "message": "email column"},  # dup
            {"rule_id": "py/hardcoded-secret", "file": "config.py", "line": 1, "message": "AWS api key"},  # secret, not PII
            {"rule_id": "py/unused", "file": "x.py", "line": 1, "message": "unused"},  # not PII
        ]
        rows = seed_rows_from_findings(findings, repo="org/app")
        self.assertEqual(len(rows), 1)              # dup collapsed, secret·non-PII skipped
        self.assertEqual(rows[0]["source"], "pii_scan")
        self.assertEqual(rows[0]["item"], "이메일")
        self.assertEqual(rows[0]["category"], "일반개인정보")
        self.assertEqual(rows[0]["stage"], "저장")           # db/schema.sql → 저장 단계

    def test_seed_extracts_db_table_and_columns(self) -> None:
        # P1: Prisma model 스니펫 → 저장위치=테이블.컬럼(repo 아님), 컬럼까지 추출
        rows = seed_rows_from_findings([
            {"rule_id": "pii-prisma-model", "file": "prisma/schema.prisma", "line": 3,
             "snippet": "model User {\n  phone String\n  email String\n}"},
        ], repo="org/app")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["table"], "User")
        self.assertEqual(rows[0]["storage_column"], "email, phone")     # 컬럼 추출(패턴 우선순위 순)
        self.assertEqual(rows[0]["storage_location"], "User.email, phone")
        self.assertNotIn("org/app", rows[0]["storage_location"])        # repo 이름 미포함
        self.assertEqual(rows[0]["stage"], "저장")                       # 테이블 근거 → 저장 확정

    def test_infer_columns_across_orm_shapes(self) -> None:
        from mori_soc.services.data_flow import infer_columns, infer_table
        # SQL CREATE TABLE
        sql = {"snippet": "CREATE TABLE patients (id INT, resident_reg_num VARCHAR(13), email TEXT)"}
        self.assertEqual(infer_table(sql), "patients")
        self.assertEqual(infer_columns(sql), ["resident_reg_num", "email"])
        # 유료 Claude 형태(코드 근거가 'lines'/'code' 키로 올 수 있음)
        claude = {"lines": "model Member {\n  ssn String\n  cardNumber String\n}"}
        self.assertEqual(infer_table(claude), "Member")
        cols = infer_columns(claude)
        self.assertIn("ssn", cols)
        self.assertIn("cardNumber", cols)

    def test_seed_gap_filled_when_store_stage_no_table(self) -> None:
        # 지난 조사의 갭: 저장 단계인데 테이블 미추출 → 최소한 코드 위치를 남긴다(공백 금지)
        rows = seed_rows_from_findings([
            {"rule_id": "pii-field", "file": "db/schema.sql", "line": 7, "message": "email column"},
        ], repo="org/app")
        self.assertEqual(rows[0]["stage"], "저장")
        self.assertEqual(rows[0]["storage_location"], "db/schema.sql:7")   # 더 이상 공백 아님

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

    def test_build_file_overview_groups_by_table(self) -> None:
        from mori_soc.services.data_flow import build_file_overview
        rows = [
            {"item": "이메일", "table": "User", "purpose": "로그인", "third_party": "없음"},
            {"item": "전화번호", "table": "User", "requirement": "선택", "subject_count": "31,620,036"},
            {"item": "주민등록번호", "table": "Patient", "third_party": "국민건강보험공단", "purpose": "진료"},
        ]
        ov = build_file_overview(rows)
        by = {o["file_name"]: o for o in ov}
        self.assertEqual(set(by), {"User", "Patient"})
        # User: 이메일=필수, 전화번호=선택
        self.assertEqual(by["User"]["required_items"], "이메일")
        self.assertEqual(by["User"]["optional_items"], "전화번호")
        self.assertEqual(by["User"]["subject_count"], "31,620,036")
        self.assertEqual(by["User"]["third_party"], "없음")
        # Patient: 제3자 집계
        self.assertEqual(by["Patient"]["required_items"], "주민등록번호")
        self.assertEqual(by["Patient"]["third_party"], "국민건강보험공단")

    def test_encryption_marker_and_concerns(self) -> None:
        from mori_soc.services.data_flow import (
            derive_concerns,
            infer_encryption,
            seed_rows_from_findings,
            storage_display,
        )
        # 암호화 '표식'은 스캔 근거로만(단정 안 함). MORI 가 암호화하는 게 아니라 상태 기록.
        self.assertEqual(infer_encryption({"snippet": "email String @encrypted // AES-256-GCM"}), "AES-256-GCM")
        self.assertEqual(infer_encryption({"snippet": "email String"}), "")
        # 컬럼에 암호화 표식이 함께 렌더된다(테이블.컬럼 (암호화: X))
        row = {"storage_location": "User.email", "encryption": "AES-256-GCM"}
        self.assertEqual(storage_display(row), "User.email (암호화: AES-256-GCM)")

        # 우려사항→통제 매핑: 고유식별정보 암호화 미확인→2.7.1, 제3자→3.3.1, 파기 미기재→3.4.1
        rows = [
            {"item": "주민등록번호", "category": "고유식별정보", "storage_location": "Patient.rrn",
             "third_party": "국민건강보험공단"},
        ]
        cs = derive_concerns(rows)
        controls = {c["controls"][0] for c in cs}
        self.assertIn("2.7.1", controls)   # 암호화 미확인
        self.assertIn("3.3.1", controls)   # 제3자 제공
        self.assertIn("3.4.1", controls)   # 파기 미기재
        # 암호화가 확인되면 2.7.1 우려는 사라진다(과대경보 방지)
        rows[0]["encryption"] = "AES-256-GCM"
        self.assertNotIn("2.7.1", {c["controls"][0] for c in derive_concerns(rows)})

    def test_seed_sets_encryption_marker(self) -> None:
        rows = seed_rows_from_findings([
            {"rule_id": "pii-prisma", "file": "prisma/schema.prisma", "line": 2,
             "snippet": "model User {\n  email String @encrypted // AES-256-GCM\n}"},
        ], repo="org/app")
        self.assertEqual(rows[0]["storage_column"], "email")
        self.assertEqual(rows[0]["encryption"], "AES-256-GCM")

    def test_render_swimlane_starts_from_subject(self) -> None:
        from mori_soc.services.data_flow import render_data_flow_swimlane_svg
        svg = render_data_flow_swimlane_svg([
            {"item": "주민등록번호", "table": "Patient", "storage_location": "Patient.rrn",
             "collection_source": "접수", "purpose": "진료", "third_party": "국민건강보험공단",
             "destruction": "파기절차"},
        ])
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("정보주체(고객)", svg)             # 출발점 = 고객
        for stage in ("수집", "저장", "이용", "파기"):
            self.assertIn(stage, svg)
        self.assertIn("Patient.rrn", svg)               # 저장: 테이블.컬럼
        self.assertIn("국민건강보험공단", svg)            # 연계기관(제3자)
        self.assertIn("연계기관", svg)
        # 빈 상태 안내
        self.assertIn("비어 있습니다", render_data_flow_swimlane_svg([]))

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
        # 개인정보 파일 개요 CSV(레퍼런스 ③)
        ov = c.get("/privacy/data-file-overview.csv")
        self.assertEqual(ov.status_code, 200)
        self.assertIn("파일명", ov.text)
        self.assertIn("정보주체 수", ov.text)
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
            Alert(alert_id="c1", source="code_review", observed_at=now, message="email column in users table",
                  severity="info", rule_id="pii-field-0",
                  raw_payload={"file": "db/schema.sql", "line": 3, "rule_id": "pii-field-0",
                               "message": "email(개인정보) 항목이 코드에 사용됨",
                               "_provenance": {"repo": "org/app"}}),
            Alert(alert_id="c2", source="code_review", observed_at=now, message="hardcoded secret",
                  severity="high", rule_id="py/hardcoded-secret",
                  raw_payload={"file": "config.py", "line": 1, "rule_id": "py/hardcoded-secret",
                               "message": "AWS api key", "_provenance": {"repo": "org/app"}}),
            Alert(alert_id="c3", source="code_review", observed_at=now, message="unused import",
                  severity="low", rule_id="py/unused",
                  raw_payload={"file": "x.py", "line": 1, "rule_id": "py/unused",
                               "_provenance": {"repo": "org/app"}}),
        ]
        c = self._client(alerts=alerts)
        r = c.post("/privacy/data-flow/seed-from-scan")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["seeded"], 1)      # 개인정보(이메일) 1건만 — secret·unused 제외
        rows = c.get("/privacy/data-flow").json()["rows"]
        self.assertEqual(rows[0]["source"], "pii_scan")

    def test_ingest_privacy_flow_renders_rich(self) -> None:
        import os as _os
        from unittest.mock import patch as _patch
        with _patch.dict(_os.environ, {"MORI_INGEST_TOKEN": "s3cret"}, clear=False):
            c = self._client()
            flow = {"items": [{"item": "이메일", "category": "일반",
                               "collect": ["회원가입 signup/page.tsx"], "store": ["User.emailEnc"],
                               "encryption": "AES-256-GCM", "use": ["maskEmail()"],
                               "dispose": ["withdrawUser()"], "table": "User"}],
                    "gaps": ["비밀번호 즉시 파기 검토"], "summary": {"items": 12, "tables": 5}}
            r = c.post("/ingest/privacy-flow?repo=org/app", json=flow, headers={"X-MORI-Token": "s3cret"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["items_saved"], 1)
            d = c.get("/privacy/data-flow").json()
            row = d["rows"][0]
            self.assertEqual(row["source"], "ai_flow")
            # P1: 유료 경로도 테이블.컬럼으로 표시 + storage_column 채움
            self.assertEqual(row["storage_location"], "User.emailEnc")
            self.assertEqual(row["storage_column"], "emailEnc")
            self.assertIn("User.emailEnc", row["storage_table"])
            self.assertIn("AES-256-GCM", row["storage_table"])
            self.assertEqual(d["meta"]["summary"]["items"], 12)
            self.assertEqual(len(d["meta"]["gaps"]), 1)

    def test_flow_opts_roundtrip_and_injection(self) -> None:
        c = self._client()
        self.assertEqual(c.put("/privacy/flow-opts", json={"route_match": True, "orm_extra": True}).json()["route_match"], True)
        self.assertTrue(c.get("/privacy/flow-opts").json()["orm_extra"])
        script = c.get("/privacy/flow-scanner.py").text
        inj = [ln for ln in script.splitlines() if "MORI-INJECT-OPTS" in ln][0]
        self.assertIn('"route_match": true', inj)   # 어드민 옵션이 스크립트에 주입됨
        self.assertIn('"orm_extra": true', inj)

    def test_role_gate_blocks_non_privileged(self) -> None:
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore()
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            c = TestClient(create_app(QueryService(store)))
        # 미인증: 세션 미들웨어(401) 또는 라우트 role gate(403) 어느 쪽이든 차단돼야 한다.
        self.assertIn(c.get("/privacy/data-flow").status_code, (401, 403))

    def test_authenticated_non_privileged_role_forbidden(self) -> None:
        # 로그인은 됐지만 privacy/증적 권한이 없는 role(monitor)은 403 이어야 한다(RBAC 우회 방지).
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app

        store = InMemoryQueryStore()
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            c = TestClient(create_app(QueryService(store)))
            login = c.post("/auth/login", json={"username": "monitor", "password": "1234"})
        self.assertEqual(login.status_code, 200, login.text)   # 인증 자체는 성공
        # 권한 없는 role → admin·security 전용 자원은 403
        self.assertEqual(c.get("/privacy/data-flow").status_code, 403)
        self.assertEqual(c.get("/evidence").status_code, 403)
        self.assertEqual(c.get("/controls/code-review/findings.csv").status_code, 403)


if __name__ == "__main__":
    unittest.main()
