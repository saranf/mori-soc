"""기술 Gap 워크플로 상태기계(#5)."""
from __future__ import annotations

import unittest

from mori_soc.services.gap_workflow import (
    apply_transition,
    build_gap,
    can_transition,
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
        apply_transition(g, "resolved", actor="dev", now="2026-07-10T00:00:00+00:00", note="재스캔에서 파기 경로 확인")
        self.assertEqual(g["status"], "resolved")
        self.assertEqual(g["resolution"], "재스캔에서 파기 경로 확인")


if __name__ == "__main__":
    unittest.main()
