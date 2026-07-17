"""스캔 간 diff·변경 사유 귀속(#3)."""
from __future__ import annotations

import unittest

from mori_soc.services.scan_diff import (
    attribute_change,
    diff_findings,
    finding_identity,
    summarize_diff,
)


class ScanDiffTests(unittest.TestCase):
    def test_line_shift_is_moved_not_delete_add(self) -> None:
        # 리뷰 #18: 코드 한 줄 삽입으로 line 만 바뀌면 delete+add 가 아니라 moved.
        prev = [{"file": "a.py", "line": 10, "rule_id": "sql", "message": "SQL injection in query"}]
        cur = [{"file": "a.py", "line": 11, "rule_id": "sql", "message": "SQL injection in query"}]
        d = diff_findings(prev, cur)
        self.assertEqual(d["new_count"], 0)
        self.assertEqual(d["removed_count"], 0)
        self.assertEqual(d["moved_count"], 1)
        self.assertEqual(d["moved"][0]["prev_line"], 10)

    def test_severity_change_is_modified(self) -> None:
        prev = [{"file": "a.py", "line": 5, "rule_id": "r", "message": "x", "severity": "low"}]
        cur = [{"file": "a.py", "line": 5, "rule_id": "r", "message": "x", "severity": "high"}]
        d = diff_findings(prev, cur)
        self.assertEqual(d["modified_count"], 1)
        self.assertEqual(d["modified"][0]["change"], "severity_changed")
        self.assertEqual(d["modified"][0]["prev_severity"], "low")

    def test_identity_is_line_independent(self) -> None:
        a = finding_identity({"file": "a.py", "line": 1, "rule_id": "r", "message": "leak email at line 1"})
        b = finding_identity({"file": "a.py", "line": 99, "rule_id": "r", "message": "leak email at line 99"})
        self.assertEqual(a, b)   # 숫자·줄이 지문에서 정규화됨

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
