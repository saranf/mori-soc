"""증적 승인 라이프사이클 상태기계(#4)."""
from __future__ import annotations

import unittest

from mori_soc.services.evidence_approval import (
    build_approval,
    can_transition,
    pdf_sha256,
)


class ApprovalStateMachineTests(unittest.TestCase):
    def test_valid_transitions(self) -> None:
        self.assertTrue(can_transition("draft", "reviewed"))
        self.assertTrue(can_transition("reviewed", "approved"))
        self.assertTrue(can_transition("approved", "superseded"))
        self.assertTrue(can_transition("approved", "revoked"))
        self.assertTrue(can_transition("reviewed", "draft"))    # 반려

    def test_invalid_transitions(self) -> None:
        self.assertFalse(can_transition("draft", "approved"))   # 검토 없이 승인 불가
        self.assertFalse(can_transition("revoked", "approved"))
        self.assertFalse(can_transition("draft", "superseded"))

    def test_build_approval_snapshot(self) -> None:
        a = build_approval(control_id="3.1.1", evidence_id="ev1", content_hash="h"*64,
                           version="hhhhhhhhhhhh", status="approved", actor="admin",
                           pdf_hash="p"*64, now="2026-07-01T00:00:00+00:00")
        self.assertEqual(a["status"], "approved")
        self.assertEqual(a["approver"], "admin")
        self.assertEqual(a["reviewer"], "")            # approved 는 approver 만
        self.assertEqual(a["pdf_sha256"], "p"*64)
        self.assertTrue(a["approval_id"].startswith("appr-"))

    def test_pdf_hash(self) -> None:
        self.assertEqual(len(pdf_sha256(b"%PDF-1.4 test")), 64)


if __name__ == "__main__":
    unittest.main()
