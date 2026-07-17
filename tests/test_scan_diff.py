"""스캔 간 diff·변경 사유 귀속(#3)."""
from __future__ import annotations

import unittest

from mori_soc.services.scan_diff import attribute_change, diff_findings, summarize_diff


class ScanDiffTests(unittest.TestCase):
    def test_diff_new_removed(self) -> None:
        prev = [{"file": "a.py", "line": 1, "rule_id": "r1"}, {"file": "b.py", "line": 2, "rule_id": "r2"}]
        cur = [{"file": "a.py", "line": 1, "rule_id": "r1"}, {"file": "c.py", "line": 3, "rule_id": "r3"}]
        d = diff_findings(prev, cur)
        self.assertEqual(d["new_count"], 1)          # c.py
        self.assertEqual(d["removed_count"], 1)      # b.py
        self.assertEqual(d["unchanged_count"], 1)    # a.py

    def test_attribute_causes(self) -> None:
        self.assertEqual(attribute_change({"commit": "a"}, {"commit": "b"}), ["code"])
        self.assertEqual(attribute_change({"ruleset": "x"}, {"ruleset": "y"}), ["ruleset"])
        self.assertEqual(attribute_change({"model": "m1"}, {"model": "m2"}), ["ai"])
        self.assertEqual(attribute_change({"commit": "a"}, {"commit": "a"}), [])  # 동일 입력

    def test_nondeterminism_flag(self) -> None:
        # 같은 입력(원인 없음)인데 결과가 다르면 비결정성 경고
        env = {"commit": "a", "ruleset": "x", "model": "m", "tool": "Claude"}
        s = summarize_diff(env, dict(env),
                           [{"file": "a.py", "line": 1, "rule_id": "r1"}],
                           [{"file": "a.py", "line": 1, "rule_id": "r1"}, {"file": "b.py", "line": 2, "rule_id": "r2"}])
        self.assertTrue(s["same_input"])
        self.assertTrue(s["nondeterministic"])       # 입력 같은데 신규 1건 → 비결정성

    def test_code_change_not_nondeterministic(self) -> None:
        s = summarize_diff({"commit": "a"}, {"commit": "b"},
                           [], [{"file": "x", "line": 1, "rule_id": "r"}])
        self.assertEqual(s["causes"], ["code"])
        self.assertFalse(s["nondeterministic"])      # 코드가 바뀌었으니 정상


if __name__ == "__main__":
    unittest.main()
