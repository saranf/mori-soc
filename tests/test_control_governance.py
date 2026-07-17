"""통제 운영 플랫폼 — 기반 모델(통제 신규 에픽 Phase 1)."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from mori_soc.services.control_governance import (
    build_control_definition,
    build_framework_version,
    content_hash,
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


if __name__ == "__main__":
    unittest.main()
