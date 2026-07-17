"""통제 운영 플랫폼 — 기반 모델(통제 신규 에픽 Phase 1)."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from mori_soc.services.control_governance import (
    apply_cycle_control_update,
    build_control_definition,
    build_cycle_control,
    build_framework_version,
    content_hash,
    cycle_control_as_of,
    is_mutable_version,
)


class ControlGovernanceServiceTests(unittest.TestCase):
    def test_content_hash_ignores_volatile(self) -> None:
        a = {"name": "x", "created_at": "2026-01-01", "created_by": "u1"}
        b = {"name": "x", "created_at": "2027-09-09", "created_by": "u2"}
        self.assertEqual(content_hash(a), content_hash(b))  # 시각·작성자 무시
        c = {"name": "y"}
        self.assertNotEqual(content_hash(a), content_hash(c))

    def test_version_id_and_immutability(self) -> None:
        v = build_framework_version(framework_id="ISMS-P", version="2023", now="2026-01-01")
        self.assertEqual(v["id"], "isms-p:2023")
        self.assertEqual(v["status"], "draft")
        self.assertTrue(is_mutable_version(v))
        v["status"] = "active"
        self.assertFalse(is_mutable_version(v))
        self.assertTrue(v["content_hash"].startswith("sha256:"))

    def test_control_definition_separates_interpretation_layers(self) -> None:
        c = build_control_definition(
            framework_version_id="isms-p:2023", display_code="2.9.4",
            title="로그 및 접속기록 관리", requirement_text="공식 원문",
            interpretations={"mori_summary": "요약", "org_interpretation": "조직 해석"})
        self.assertEqual(c["interpretations"]["official"], "공식 원문")
        self.assertEqual(c["interpretations"]["mori_summary"], "요약")
        self.assertEqual(c["interpretations"]["org_interpretation"], "조직 해석")
        self.assertEqual(c["interpretations"]["operation_guide"], "")
        self.assertEqual(c["id"], "isms-p:2023:2.9.4")


    def test_cycle_control_separates_evidence_and_assessment(self) -> None:
        cc = build_cycle_control(cycle_id="isms-p-2026", control_ref="corp-log-002:v1",
                                 now="2026-01-01T00:00:00+00:00", created_by="u")
        self.assertEqual(cc["evidence_status"], "missing")
        self.assertEqual(cc["assessment_status"], "not_assessed")
        # 증적이 approved 여도 평가는 자동으로 effective 가 되지 않는다(분리).
        apply_cycle_control_update(cc, actor="u", now="2026-02-01T00:00:00+00:00",
                                   evidence_status="approved")
        self.assertEqual(cc["evidence_status"], "approved")
        self.assertEqual(cc["assessment_status"], "not_assessed")  # 여전히 미평가
        apply_cycle_control_update(cc, actor="u", now="2026-03-01T00:00:00+00:00",
                                   assessment_status="effective")
        self.assertEqual(cc["assessment_status"], "effective")
        self.assertEqual(len(cc["history"]), 3)  # created + 2 updates

    def test_cycle_control_as_of_replays_history(self) -> None:
        cc = build_cycle_control(cycle_id="c1", control_ref="x", now="2026-01-01T00:00:00+00:00",
                                 created_by="u")
        apply_cycle_control_update(cc, actor="u", now="2026-02-01T00:00:00+00:00",
                                   evidence_status="available")
        apply_cycle_control_update(cc, actor="u", now="2026-04-01T00:00:00+00:00",
                                   evidence_status="approved", assessment_status="effective")
        # 3월 시점엔 available/미평가, 5월 시점엔 approved/effective
        mar = cycle_control_as_of(cc, "2026-03-15T00:00:00+00:00")
        self.assertEqual(mar["evidence_status"], "available")
        self.assertEqual(mar["assessment_status"], "not_assessed")
        may = cycle_control_as_of(cc, "2026-05-01T00:00:00+00:00")
        self.assertEqual(may["evidence_status"], "approved")
        self.assertEqual(may["assessment_status"], "effective")


class ControlGovernanceRouteTests(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": ""}, clear=False):
            return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_framework_version_control_flow(self) -> None:
        c = self._client()
        # framework → version → control
        self.assertEqual(c.post("/governance/frameworks",
                                json={"framework_id": "ISMS-P", "name": "ISMS-P",
                                      "publisher": "KISA"}).status_code, 200)
        v = c.post("/governance/framework-versions",
                   json={"framework_id": "ISMS-P", "version": "2023",
                         "effective_from": "2024-01-02"})
        self.assertEqual(v.status_code, 200, v.text)
        fv_id = v.json()["id"]
        self.assertEqual(fv_id, "isms-p:2023")
        # 중복 버전 거부(불변)
        self.assertEqual(c.post("/governance/framework-versions",
                                json={"framework_id": "ISMS-P", "version": "2023"}).status_code, 409)
        # draft 에는 통제 추가 가능
        cc = c.post("/governance/control-definitions",
                    json={"framework_version_id": fv_id, "display_code": "2.9.4",
                          "title": "로그 및 접속기록 관리", "requirement_text": "..."})
        self.assertEqual(cc.status_code, 200, cc.text)
        # activate → active 버전엔 통제 추가 거부(409)
        self.assertEqual(c.post(f"/governance/framework-versions/{fv_id}/activate").status_code, 200)
        blocked = c.post("/governance/control-definitions",
                         json={"framework_version_id": fv_id, "display_code": "2.9.5", "title": "x"})
        self.assertEqual(blocked.status_code, 409)
        # 목록 확인
        controls = c.get(f"/governance/framework-versions/{fv_id}/controls").json()["controls"]
        self.assertEqual(len(controls), 1)

    def test_relationship_and_org_control(self) -> None:
        c = self._client()
        rel = c.post("/governance/relationships",
                     json={"source_control_id": "isms-p:2019:2.9.4",
                           "target_control_id": "isms-p:2023:2.10.2",
                           "relationship_type": "replaced_by", "coverage_percent": 80})
        self.assertEqual(rel.status_code, 200, rel.text)
        self.assertEqual(rel.json()["coverage_percent"], 80)
        # 잘못된 관계 유형 거부
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": "a", "target_control_id": "b",
                                      "relationship_type": "bogus"}).status_code, 400)
        oc = c.post("/governance/organization-controls",
                    json={"code": "CORP-LOG-002", "title": "관리자 접속기록 월간 검토",
                          "owner_team": "보안운영팀", "frequency": "monthly",
                          "mapped_controls": ["isms-p:2023:2.9.4", "iso27001:2022:A.8.15"]})
        self.assertEqual(oc.status_code, 200, oc.text)
        self.assertEqual(oc.json()["id"], "corp-log-002:v1")

    def test_cycle_control_and_evidence_contract_endpoints(self) -> None:
        c = self._client()
        # evidence contract 버전관리
        ec = c.post("/governance/evidence-contracts",
                    json={"organization_control_id": "corp-acc-004", "version": 3,
                          "frequency": "monthly", "required_fields": ["account_id", "reviewer"],
                          "minimum_coverage": 0.95, "maximum_age_days": 35,
                          "allowed_sources": ["LDAP", "Fleet"]})
        self.assertEqual(ec.status_code, 200, ec.text)
        self.assertEqual(ec.json()["id"], "corp-acc-004:v3")
        # cycle control 생성 + 증적/평가 분리 갱신
        cyc = c.post("/governance/assurance-cycles",
                     json={"cycle_id": "isms-p-2026", "name": "2026 ISMS-P",
                           "framework_version_id": "isms-p:2023"})
        self.assertEqual(cyc.status_code, 200, cyc.text)
        cc = c.post("/governance/cycle-controls",
                    json={"cycle_id": "isms-p-2026", "control_ref": "corp-acc-004"})
        self.assertEqual(cc.status_code, 200, cc.text)
        cc_id = cc.json()["id"]
        # 잘못된 상태값 거부
        self.assertEqual(c.post(f"/governance/cycle-controls/{cc_id}/update",
                                json={"evidence_status": "bogus"}).status_code, 400)
        # 증적 approved 갱신 → 평가는 그대로 not_assessed
        up = c.post(f"/governance/cycle-controls/{cc_id}/update",
                    json={"evidence_status": "approved"}).json()
        self.assertEqual(up["evidence_status"], "approved")
        self.assertEqual(up["assessment_status"], "not_assessed")
        # as-of 재현
        aof = c.get(f"/governance/cycle-controls/{cc_id}/as-of").json()
        self.assertEqual(aof["evidence_status"], "approved")


if __name__ == "__main__":
    unittest.main()
