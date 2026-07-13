"""통제 증적 provenance·불변성(#21) — content_hash 결정성·변경 감지."""
from __future__ import annotations

import unittest

from mori_soc.services.evidence import content_hash, stamp_evidence


class EvidenceProvenanceTests(unittest.TestCase):
    def test_content_hash_deterministic_ignores_timestamps(self) -> None:
        # 같은 내용이면 승격 시각(created_at)·id 가 달라도 같은 content_hash → 재승격 무변경 판별.
        a = {"id": "x1", "control_id": "2.8.1", "title": "t", "body": "b",
             "source": "code_review", "created_at": "2026-01-01T00:00:00Z"}
        b = {"id": "x2", "control_id": "2.8.1", "title": "t", "body": "b",
             "source": "code_review", "created_at": "2026-06-01T00:00:00Z"}
        self.assertEqual(content_hash(a), content_hash(b))

    def test_content_change_changes_hash(self) -> None:
        a = {"control_id": "2.8.1", "title": "t", "body": "b"}
        b = {"control_id": "2.8.1", "title": "t", "body": "b2"}   # body 변경
        self.assertNotEqual(content_hash(a), content_hash(b))

    def test_stamp_adds_fields(self) -> None:
        rec = {"id": "x", "control_id": "3.1.1", "title": "t", "body": "b",
               "created_at": "2026-01-01T00:00:00Z"}
        stamp_evidence(rec)
        self.assertEqual(len(rec["content_hash"]), 64)
        self.assertEqual(rec["version"], rec["content_hash"][:12])
        self.assertEqual(rec["generated_at"], "2026-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
