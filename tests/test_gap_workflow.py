"""기술 Gap 워크플로 상태기계(#5)."""
from __future__ import annotations

import unittest

from mori_soc.services.gap_workflow import (
    apply_transition,
    build_gap,
    can_transition,
    evaluate_gap_deadlines,
    gap_id_for,
)


class GapWorkflowTests(unittest.TestCase):
    def test_transitions(self) -> None:
        self.assertTrue(can_transition("candidate", "confirmed"))
        self.assertTrue(can_transition("candidate", "false_positive"))
        self.assertTrue(can_transition("candidate", "policy_review"))
        self.assertTrue(can_transition("confirmed", "remediation"))
        self.assertTrue(can_transition("remediation", "resolved"))
        self.assertFalse(can_transition("candidate", "resolved"))     # 바로 해결 불가
        self.assertFalse(can_transition("false_positive", "confirmed"))  # 종결됨

    def test_deterministic_id(self) -> None:
        a = gap_id_for("privacy", "3.4.1", "파기 미발견")
        b = gap_id_for("privacy", "3.4.1", "파기 미발견")
        self.assertEqual(a, b)                        # 같은 결함 → 같은 id(중복 방지)

    def test_build_and_transition_history(self) -> None:
        g = build_gap(source="privacy", control_id="3.4.1", key="파기 미발견",
                      title="개인정보 파기 구현 근거 미발견", detail="withdrawUser 경로 없음",
                      now="2026-07-01T00:00:00+00:00", created_by="admin")
        self.assertEqual(g["status"], "candidate")
        apply_transition(g, "confirmed", actor="dev", now="2026-07-02T00:00:00+00:00",
                         assignee="개발팀", due_date="2026-07-15")
        self.assertEqual(g["status"], "confirmed")
        self.assertEqual(g["assignee"], "개발팀")
        self.assertEqual(len(g["history"]), 2)        # created + transition
        apply_transition(g, "remediation", actor="dev", now="2026-07-03T00:00:00+00:00")
        apply_transition(g, "resolved", actor="dev", now="2026-07-10T00:00:00+00:00",
                         note="재스캔에서 파기 경로 확인", resolution_type="automatically_reverified",
                         verifying_scan="scan-2026-07-10", evidence_ref="3.4.1")
        self.assertEqual(g["status"], "resolved")
        self.assertEqual(g["resolution"], "재스캔에서 파기 경로 확인")
        # 리뷰 #19: 해결 근거가 남는다 — '사람이 눌렀다'로 끝나지 않음
        self.assertEqual(g["resolution_type"], "automatically_reverified")
        self.assertEqual(g["verifier"], "dev")
        self.assertEqual(g["verifying_scan"], "scan-2026-07-10")
        self.assertTrue(g["verified_at"])

    def test_resolution_type_defaults_and_exception_is_not_resolved(self) -> None:
        from mori_soc.services.gap_workflow import RESOLUTION_TYPES
        # resolution_type 미지정 → manually_verified 기본
        g = build_gap(source="s", control_id="c", key="k", title="t", detail="d", now="2026-01-01T00:00:00+00:00")
        apply_transition(g, "confirmed", actor="u", now="2026-01-02T00:00:00+00:00")
        apply_transition(g, "resolved", actor="u", now="2026-01-03T00:00:00+00:00")
        self.assertEqual(g["resolution_type"], "manually_verified")
        self.assertIn("manually_verified", RESOLUTION_TYPES)
        # accepted_exception 은 해결이 아님(resolution_type 없음)
        g2 = build_gap(source="s", control_id="c", key="k2", title="t2", detail="d", now="2026-01-01T00:00:00+00:00")
        apply_transition(g2, "confirmed", actor="u", now="2026-01-02T00:00:00+00:00")
        apply_transition(g2, "accepted_exception", actor="u", now="2026-01-03T00:00:00+00:00", note="보완통제 있음")
        self.assertNotIn("resolution_type", g2)

    def test_evaluate_gap_deadlines(self) -> None:
        gaps = [
            {"gap_id": "g1", "status": "remediation", "due_date": "2026-07-01", "title": "초과 조치"},
            {"gap_id": "g2", "status": "remediation", "due_date": "2026-08-01", "title": "여유"},
            {"gap_id": "g3", "status": "accepted_exception", "due_date": "2026-07-10", "title": "만료 예외"},
            {"gap_id": "g4", "status": "accepted_exception", "due_date": "2026-07-20", "title": "임박 예외"},
            {"gap_id": "g5", "status": "resolved", "due_date": "2026-01-01", "title": "종결"},
        ]
        res = evaluate_gap_deadlines(gaps, "2026-07-17", soon_days=14)
        # g1: remediation 기한 초과 / g2: 여유 → overdue 아님
        self.assertEqual([r["gap_id"] for r in res["overdue"]], ["g1"])
        # g3: 예외 만료 지남 → expired(자동연장 금지) / g4: 14일 내 임박
        self.assertEqual([r["gap_id"] for r in res["expired_exception"]], ["g3"])
        self.assertEqual([r["gap_id"] for r in res["expiring_soon"]], ["g4"])
        # g5(resolved)는 due 지나도 제외
        self.assertEqual(res["counts"], {"overdue": 1, "expired_exception": 1, "expiring_soon": 1})

    def test_deadlines_ignore_missing_dates(self) -> None:
        res = evaluate_gap_deadlines([{"gap_id": "x", "status": "remediation", "due_date": ""}], "2026-07-17")
        self.assertEqual(res["counts"]["overdue"], 0)


if __name__ == "__main__":
    unittest.main()
