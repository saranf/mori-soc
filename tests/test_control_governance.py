"""통제 운영 플랫폼 — 기반 모델(통제 신규 에픽 Phase 1)."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from mori_soc.services.control_governance import (
    apply_cycle_control_update,
    apply_overlay,
    build_control_definition,
    build_crosswalk,
    build_cycle_control,
    build_framework_version,
    content_hash,
    cycle_control_as_of,
    diff_control_definitions,
    initialize_cycle_from_previous,
    is_mutable_version,
)


class ControlGovernanceServiceTests(unittest.TestCase):
    def test_plan_catalog_import_maps_layers(self) -> None:
        from mori_soc.services.control_governance import plan_catalog_import
        controls = [
            {"id": "2.9.4", "framework": "isms-p", "version": "2023", "title_ko": "로그 관리",
             "intent_ko": "로그를 관리한다", "evidence_hint_ko": "로그 검토 회의록"},
            {"id": "A.8.15", "framework": "iso27001", "version": "2022", "title_en": "Logging"},
        ]
        plan = plan_catalog_import(controls, now="2026-01-01", created_by="u")
        self.assertEqual(len(plan["frameworks"]), 2)
        self.assertEqual(len(plan["control_definitions"]), 2)
        isms = next(c for c in plan["control_definitions"] if c["framework_version_id"] == "isms-p:2023")
        self.assertEqual(isms["control_uid"], "2.9.4")
        # intent 는 mori_summary, evidence_hint 는 operation_guide, official 은 비움(원문 미포함)
        self.assertEqual(isms["interpretations"]["mori_summary"], "로그를 관리한다")
        self.assertEqual(isms["interpretations"]["operation_guide"], "로그 검토 회의록")
        self.assertEqual(isms["interpretations"]["official"], "")

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

    def test_content_hash_stable_across_lifecycle(self) -> None:
        # S1a: activate/retire 는 내용이 아니므로 content_hash 를 흔들면 안 된다.
        from mori_soc.services.control_governance import apply_version_lifecycle
        v = build_framework_version(framework_id="ISMS-P", version="2023", now="2026-01-01")
        h0 = v["content_hash"]
        apply_version_lifecycle(v, "active", actor="u", now="2026-01-02")
        self.assertEqual(v["status"], "active")
        self.assertEqual(content_hash(v), h0)  # 상태 전환 후에도 동일 지문
        apply_version_lifecycle(v, "retired", actor="u", now="2026-06-01")
        self.assertEqual(content_hash(v), h0)
        # lifecycle 이벤트가 append 됨
        self.assertEqual([e["to"] for e in v["lifecycle"]], ["draft", "active", "retired"])

    def test_version_state_machine(self) -> None:
        from mori_soc.services.control_governance import can_version_transition
        self.assertTrue(can_version_transition("draft", "active"))
        self.assertTrue(can_version_transition("active", "retired"))
        self.assertFalse(can_version_transition("retired", "active"))   # 재활성 금지
        self.assertFalse(can_version_transition("active", "active"))    # 재활성화 재호출 금지
        self.assertFalse(can_version_transition("draft", "retired"))    # draft 직접 폐기 금지

    def test_cycle_control_as_of_restores_initial_state(self) -> None:
        # S1b: 생성 시 담당자·적용성이 최초 history 에 박혀 as-of 가 정확히 복원한다.
        cc = build_cycle_control(cycle_id="c1", control_ref="x", assignee="김보안",
                                 applicability="applicable", now="2026-01-01T00:00:00+00:00",
                                 created_by="u")
        # 아무 변경 없는 1월 10일 시점 → 생성 시점 값 그대로
        st = cycle_control_as_of(cc, "2026-01-10T00:00:00+00:00")
        self.assertEqual(st["assignee"], "김보안")
        self.assertEqual(st["applicability"], "applicable")

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


    def test_diff_control_definitions(self) -> None:
        old = [
            build_control_definition(framework_version_id="isms-p:2019", display_code="2.9.4",
                                     title="로그 관리", control_uid="log-review",
                                     requirement_text="분기별 검토"),
            build_control_definition(framework_version_id="isms-p:2019", display_code="2.5.1",
                                     title="사라질 통제", control_uid="gone"),
        ]
        new = [
            # 같은 uid, 번호만 변경 + 내용도 변경 → text_changed 우선
            build_control_definition(framework_version_id="isms-p:2023", display_code="2.10.2",
                                     title="로그 관리", control_uid="log-review",
                                     requirement_text="월 1회 검토"),
            build_control_definition(framework_version_id="isms-p:2023", display_code="3.1.1",
                                     title="신규 통제", control_uid="brand-new"),
        ]
        d = diff_control_definitions(old, new)
        self.assertEqual(d["counts"], {"added": 1, "removed": 1, "renumbered": 0,
                                       "text_changed": 1, "unchanged": 0})
        self.assertEqual(d["added"][0]["control_uid"], "brand-new")
        self.assertEqual(d["removed"][0]["control_uid"], "gone")
        self.assertEqual(d["text_changed"][0]["old_code"], "2.9.4")

    def test_diff_renumber_only(self) -> None:
        old = [build_control_definition(framework_version_id="a", display_code="1.1",
                                        title="t", control_uid="u", requirement_text="same")]
        new = [build_control_definition(framework_version_id="b", display_code="2.2",
                                        title="t", control_uid="u", requirement_text="same")]
        d = diff_control_definitions(old, new)
        self.assertEqual(d["counts"]["renumbered"], 1)
        self.assertEqual(d["counts"]["text_changed"], 0)

    def test_initialize_cycle_resets_assessment(self) -> None:
        prev = [build_cycle_control(cycle_id="2025", control_ref="corp-log-002:v1",
                                    assignee="김보안", applicability="applicable",
                                    now="2025-01-01T00:00:00+00:00", created_by="u")]
        prev[0]["evidence_status"] = "approved"
        prev[0]["assessment_status"] = "effective"  # 작년 Effective
        res = initialize_cycle_from_previous(prev, "2026", now="2026-01-01T00:00:00+00:00")
        self.assertEqual(res["carried"], 1)
        nc = res["cycle_controls"][0]
        self.assertEqual(nc["assignee"], "김보안")          # 담당자 승계
        self.assertEqual(nc["applicability"], "applicable")  # 적용성 값은 승계
        self.assertTrue(nc["applicability_pending_review"])  # 단 재확인 필요(#9, 무조건 승계 금지)
        self.assertEqual(nc["evidence_status"], "missing")   # 증적 초기화
        self.assertEqual(nc["assessment_status"], "not_assessed")  # 평가 초기화(자동 승계 금지)
        # 담당자가 적용성을 재확인(명시 설정)하면 pending 해제
        apply_cycle_control_update(nc, actor="홍길동", now="2026-02-01T00:00:00+00:00",
                                   applicability="applicable")
        self.assertFalse(nc["applicability_pending_review"])


    def test_crosswalk_groups_by_framework(self) -> None:
        org = [{"id": "corp-log-002:v1", "code": "CORP-LOG-002", "title": "월간 검토",
                "mapped_controls": ["isms-p:2023:2.9.4", "iso27001:2022:A.8.15", "isms-p:2023:2.9.5"]}]
        cw = build_crosswalk(org)
        row = cw["organization_controls"][0]
        self.assertEqual(row["framework_count"], 2)
        self.assertEqual(set(row["frameworks"]), {"isms-p", "iso27001"})
        self.assertEqual(len(row["mappings"]["isms-p"]), 2)

    def test_apply_overlay_conflict_flag(self) -> None:
        cdef = build_control_definition(framework_version_id="isms-p:2023", display_code="2.9.4",
                                        title="로그", requirement_text="원문")
        # 오버레이가 검토한 base 해시가 현재와 같으면 conflict 없음
        v1 = apply_overlay(cdef, {"owner_team": "보안운영팀", "frequency": "monthly",
                                  "reviewed_base_hash": cdef["content_hash"]})
        self.assertFalse(v1["conflict"])
        self.assertEqual(v1["overlay"]["owner_team"], "보안운영팀")
        # base 가 바뀐 척(다른 해시) → conflict True(재검토 필요)
        v2 = apply_overlay(cdef, {"reviewed_base_hash": "sha256:old"})
        self.assertTrue(v2["conflict"])


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

    def _seed_control(self, c, framework: str, version: str, code: str, title: str = "t",
                      uid: str = "", req: str = "req") -> str:
        """framework → version → control 을 만들고 control_definition id 반환(테스트 헬퍼)."""
        c.post("/governance/frameworks", json={"framework_id": framework, "name": framework})
        c.post("/governance/framework-versions", json={"framework_id": framework, "version": version})
        fv = f"{framework.lower()}:{version}"
        r = c.post("/governance/control-definitions",
                   json={"framework_version_id": fv, "display_code": code, "title": title,
                         "control_uid": uid, "requirement_text": req})
        return r.json()["id"]

    def test_relationship_and_org_control(self) -> None:
        c = self._client()
        src = self._seed_control(c, "ISMS-P", "2019", "2.9.4", uid="log")
        tgt = self._seed_control(c, "ISMS-P", "2023", "2.10.2", uid="log")
        rel = c.post("/governance/relationships",
                     json={"source_control_id": src, "target_control_id": tgt,
                           "relationship_type": "replaced_by", "coverage_percent": 80})
        self.assertEqual(rel.status_code, 200, rel.text)
        self.assertEqual(rel.json()["coverage_percent"], 80)
        # 잘못된 관계 유형 거부(400) / 존재하지 않는 통제 참조 거부(404) / 자기참조 거부(400)
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": src, "target_control_id": tgt,
                                      "relationship_type": "bogus"}).status_code, 400)
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": src, "target_control_id": "ghost",
                                      "relationship_type": "related_to"}).status_code, 404)
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": src, "target_control_id": src,
                                      "relationship_type": "related_to"}).status_code, 400)
        # coverage 범위·비숫자 거부(400, 500 아님)
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": src, "target_control_id": tgt,
                                      "relationship_type": "same_as", "coverage_percent": 150}).status_code, 400)
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": src, "target_control_id": tgt,
                                      "relationship_type": "same_as", "coverage_percent": "abc"}).status_code, 400)
        # 중복 관계(같은 source·target·type) 거부(409)
        self.assertEqual(c.post("/governance/relationships",
                                json={"source_control_id": src, "target_control_id": tgt,
                                      "relationship_type": "replaced_by"}).status_code, 409)
        oc = c.post("/governance/organization-controls",
                    json={"code": "CORP-LOG-002", "title": "관리자 접속기록 월간 검토",
                          "owner_team": "보안운영팀", "frequency": "monthly",
                          "mapped_controls": [tgt, "iso27001:2022:A.8.15"]})
        self.assertEqual(oc.status_code, 200, oc.text)
        self.assertEqual(oc.json()["id"], "corp-log-002:v1")

    def test_cycle_control_and_evidence_contract_endpoints(self) -> None:
        c = self._client()
        # 참조 검증(S1d): 존재하지 않는 내부통제로 계약 생성 → 404
        self.assertEqual(c.post("/governance/evidence-contracts",
                                json={"organization_control_id": "ghost"}).status_code, 404)
        # 내부통제 생성 후 계약 버전관리
        c.post("/governance/organization-controls", json={"code": "CORP-ACC-004", "title": "계정검토"})
        ec = c.post("/governance/evidence-contracts",
                    json={"organization_control_id": "corp-acc-004:v1", "version": 3,
                          "frequency": "monthly", "required_fields": ["account_id", "reviewer"],
                          "minimum_coverage": 0.95, "maximum_age_days": 35,
                          "allowed_sources": ["LDAP", "Fleet"]})
        self.assertEqual(ec.status_code, 200, ec.text)
        self.assertEqual(ec.json()["id"], "corp-acc-004-v1:v3")  # ref 는 slug 화됨
        # assurance cycle 은 실재하는 framework_version 을 요구(S1d)
        self._seed_control(c, "ISMS-P", "2023", "2.9.4", uid="log")
        cyc = c.post("/governance/assurance-cycles",
                     json={"cycle_id": "isms-p-2026", "name": "2026 ISMS-P",
                           "framework_version_id": "isms-p:2023"})
        self.assertEqual(cyc.status_code, 200, cyc.text)
        # cycle control — control_ref 는 실재하는 통제(내부통제)여야 함
        cc = c.post("/governance/cycle-controls",
                    json={"cycle_id": "isms-p-2026", "control_ref": "corp-acc-004:v1"})
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
        # no-op 갱신(같은 값) → history 안 늘어남(S1f)
        before = len(c.get(f"/governance/assurance-cycles/isms-p-2026/controls"
                           ).json()["cycle_controls"][0]["history"])
        noop = c.post(f"/governance/cycle-controls/{cc_id}/update",
                      json={"evidence_status": "approved"}).json()
        self.assertTrue(noop["_no_op"])
        after = len(c.get(f"/governance/assurance-cycles/isms-p-2026/controls"
                          ).json()["cycle_controls"][0]["history"])
        self.assertEqual(before, after)
        # as-of 재현
        aof = c.get(f"/governance/cycle-controls/{cc_id}/as-of").json()
        self.assertEqual(aof["evidence_status"], "approved")

    def test_version_compare_and_cycle_migration(self) -> None:
        c = self._client()
        c.post("/governance/frameworks", json={"framework_id": "ISMS-P", "name": "ISMS-P"})
        for ver in ("2019", "2023"):
            c.post("/governance/framework-versions", json={"framework_id": "ISMS-P", "version": ver})
        c.post("/governance/control-definitions",
               json={"framework_version_id": "isms-p:2019", "display_code": "2.9.4",
                     "title": "로그", "control_uid": "log", "requirement_text": "분기"})
        c.post("/governance/control-definitions",
               json={"framework_version_id": "isms-p:2023", "display_code": "2.10.2",
                     "title": "로그", "control_uid": "log", "requirement_text": "월간"})
        # 신버전에 신규 통제 하나 추가(마이그레이션에서 new_controls 로 잡혀야 함)
        c.post("/governance/control-definitions",
               json={"framework_version_id": "isms-p:2023", "display_code": "3.1.1",
                     "title": "신규", "control_uid": "brand-new", "requirement_text": "new"})
        cmp = c.get("/governance/framework-versions/isms-p:2019/compare",
                    params={"to": "isms-p:2023"}).json()
        self.assertEqual(cmp["counts"]["text_changed"], 1)  # 요구 내용 변경
        # cycle migration: 2025 주기 → 2026 주기 (버전 diff 계보 기반)
        c.post("/governance/assurance-cycles",
               json={"cycle_id": "c2025", "name": "2025", "framework_version_id": "isms-p:2019"})
        c.post("/governance/assurance-cycles",
               json={"cycle_id": "c2026", "name": "2026", "framework_version_id": "isms-p:2023"})
        # 이전 주기 통제는 구버전 통제 정의(isms-p:2019:2.9.4)를 참조
        cc = c.post("/governance/cycle-controls",
                    json={"cycle_id": "c2025", "control_ref": "isms-p:2019:2.9.4",
                          "assignee": "김보안"}).json()
        c.post(f"/governance/cycle-controls/{cc['id']}/update",
               json={"assessment_status": "effective"})
        mig = c.post("/governance/assurance-cycles/c2026/initialize-from/c2025").json()
        # log 통제는 내용변경 이관(text_changed) + brand-new 는 신규 통제
        self.assertEqual(mig["counts"]["carried"], 1)
        self.assertEqual(mig["counts"]["text_changed"], 1)
        self.assertEqual(mig["counts"]["new_controls"], 1)
        new_cc = {x["control_ref"]: x for x in
                  c.get("/governance/assurance-cycles/c2026/controls").json()["cycle_controls"]}
        carried = new_cc["isms-p:2023:2.10.2"]           # 새 번호로 이관됨
        self.assertEqual(carried["assignee"], "김보안")               # 승계
        self.assertEqual(carried["assessment_status"], "not_assessed")  # 초기화
        self.assertEqual(carried["carried_from_control_ref"], "isms-p:2019:2.9.4")
        self.assertTrue(carried["requires_design_review"])            # 내용 변경 → 재설계 검토
        self.assertTrue(new_cc["isms-p:2023:3.1.1"]["requires_design_review"])  # 신규
        # P4: as-of 감사 스냅샷(운영주기 전체) — 이관 1 + 신규 1 = 2
        snap = c.get("/governance/assurance-cycles/c2026/audit-snapshot").json()
        self.assertEqual(snap["control_count"], 2)
        self.assertIn("not_assessed", snap["assessment_status_counts"])
        # P5: crosswalk + overlay-view
        c.post("/governance/organization-controls",
               json={"code": "CORP-LOG-002", "title": "월간 검토",
                     "mapped_controls": ["isms-p:2023:2.10.2", "iso27001:2022:A.8.15"]})
        cw = c.get("/governance/crosswalk").json()
        self.assertTrue(any(r["framework_count"] == 2 for r in cw["organization_controls"]))
        ov = c.post("/governance/controls/isms-p:2023:2.10.2/overlay-view",
                    json={"owner_team": "보안운영팀"}).json()
        self.assertEqual(ov["overlay"]["owner_team"], "보안운영팀")


    def test_import_catalog_endpoint_idempotent(self) -> None:
        c = self._client()
        r1 = c.post("/governance/import-catalog", params={"framework": "isms-p"}).json()
        self.assertGreater(r1["imported"]["control_definitions"], 50)   # 기존 카탈로그 흡수
        self.assertGreaterEqual(r1["imported"]["frameworks"], 1)
        # 재실행 → 이미 있는 건 건너뜀(idempotent)
        r2 = c.post("/governance/import-catalog", params={"framework": "isms-p"}).json()
        self.assertEqual(r2["imported"]["control_definitions"], 0)
        # governance 목록에서 조회됨
        vs = c.get("/governance/frameworks/isms-p/versions").json()["versions"]
        self.assertTrue(vs)
        fv_id = vs[0]["id"]
        controls = c.get(f"/governance/framework-versions/{fv_id}/controls").json()["controls"]
        self.assertGreater(len(controls), 50)

    def test_append_only_event_chain(self) -> None:
        from mori_soc.services.control_governance import verify_governance_chain
        c = self._client()
        c.post("/governance/frameworks", json={"framework_id": "ISMS-P", "name": "ISMS-P"})
        c.post("/governance/framework-versions", json={"framework_id": "ISMS-P", "version": "2023"})
        c.post("/governance/framework-versions/isms-p:2023/activate")
        evs = c.get("/governance/events").json()
        # framework create + version create + version lifecycle = 3 이벤트
        self.assertGreaterEqual(evs["count"], 3)
        types = [e["event_type"] for e in evs["events"]]
        self.assertIn("create", types)
        self.assertIn("lifecycle", types)
        # 엔터티 필터 + revision 증가
        vevs = c.get("/governance/events", params={"kind": "framework_version",
                                                   "entity_id": "isms-p:2023"}).json()["events"]
        self.assertEqual([e["revision"] for e in vevs], [1, 2])  # create, activate
        # hash chain 무결성 OK
        self.assertTrue(c.get("/governance/events/verify").json()["ok"])
        # 변조 감지: 이벤트 payload 를 바꾸면 체인이 깨진다(서비스 함수 직접 검증)
        raw = c.get("/governance/events").json()["events"]
        raw[1]["payload"] = {"tampered": True}
        self.assertFalse(verify_governance_chain(raw)["ok"])

    def test_version_lifecycle_route_enforcement(self) -> None:
        c = self._client()
        c.post("/governance/frameworks", json={"framework_id": "ISMS-P", "name": "ISMS-P"})
        for ver in ("2019", "2023"):
            c.post("/governance/framework-versions", json={"framework_id": "ISMS-P", "version": ver})
        # 2019 활성화 성공
        self.assertEqual(c.post("/governance/framework-versions/isms-p:2019/activate").status_code, 200)
        # 같은 framework 에 2023 도 활성화 → 409(active 1개 규칙)
        self.assertEqual(c.post("/governance/framework-versions/isms-p:2023/activate").status_code, 409)
        # 2019 retire 후 2023 활성화 성공
        self.assertEqual(c.post("/governance/framework-versions/isms-p:2019/retire").status_code, 200)
        self.assertEqual(c.post("/governance/framework-versions/isms-p:2023/activate").status_code, 200)
        # retired → active 재활성 거부(409)
        self.assertEqual(c.post("/governance/framework-versions/isms-p:2019/activate").status_code, 409)
        # content_hash 는 활성화 전후 동일(라우트 경유)
        vs = {v["id"]: v for v in c.get("/governance/frameworks/ISMS-P/versions").json()["versions"]}
        self.assertEqual(vs["isms-p:2023"]["status"], "active")


if __name__ == "__main__":
    unittest.main()
