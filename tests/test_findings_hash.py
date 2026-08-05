"""findings_content_hash(R4) — AI 스캔 결과 불변 앵커. 순서무관·변동감지·결정적."""
from __future__ import annotations

import unittest

from mori_soc.services.provenance import findings_content_hash


class FindingsHashTest(unittest.TestCase):
    A = [
        {"rule_id": "r1", "file": "a.py", "line": 1, "severity": "high", "message": "m1"},
        {"rule_id": "r2", "file": "b.py", "line": 2, "severity": "low", "message": "m2"},
    ]

    def test_order_independent(self) -> None:
        # 순서만 다른 동일 findings → 같은 해시(집합 앵커).
        self.assertEqual(findings_content_hash(self.A), findings_content_hash(list(reversed(self.A))))

    def test_content_change_detected(self) -> None:
        changed = self.A + [{"rule_id": "r3", "file": "c.py", "line": 3, "message": "m3"}]
        self.assertNotEqual(findings_content_hash(self.A), findings_content_hash(changed))

    def test_deterministic_and_prefixed(self) -> None:
        h = findings_content_hash(self.A)
        self.assertEqual(h, findings_content_hash(self.A))
        self.assertTrue(h.startswith("sha256:"))

    def test_empty_stable(self) -> None:
        self.assertTrue(findings_content_hash([]).startswith("sha256:"))
        self.assertEqual(findings_content_hash([]), findings_content_hash(None))

    def test_field_aliases(self) -> None:
        # ruleId/level/title/path 별칭도 동일 정규화 → 같은 해시.
        canonical = [{"rule_id": "r", "file": "f", "line": 1, "severity": "high", "message": "m"}]
        alias = [{"ruleId": "r", "path": "f", "line": 1, "level": "high", "title": "m"}]
        self.assertEqual(findings_content_hash(canonical), findings_content_hash(alias))


if __name__ == "__main__":
    unittest.main()
