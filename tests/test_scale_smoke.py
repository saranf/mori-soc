"""대규모 스케일 스모크(2차 리뷰 #6 성능) — 순수 함수가 리뷰 규모에서 안 터지고 정확한지.

브리틀한 wall-clock 게이트가 아니라(환경 의존·flaky), 리뷰가 제시한 규모
(10k findings·100k population·수천 통제)에서 알고리즘이 완료되고 결과가 정확한지 검증한다.
실제 DB·엔드포인트 성능 벤치는 별도 부하 인프라가 필요(에픽에 기록).
"""
from __future__ import annotations

import unittest


class ScaleSmokeTests(unittest.TestCase):
    def test_scan_diff_10k_findings(self) -> None:
        from mori_soc.services.scan_diff import diff_findings
        prev = [{"file": f"f{i}.py", "line": i, "rule_id": "r", "message": f"issue {i}"}
                for i in range(10_000)]
        # 절반은 유지(줄만 +1 이동), 절반은 제거, 신규 2천
        cur = [{"file": f"f{i}.py", "line": i + 1, "rule_id": "r", "message": f"issue {i}"}
               for i in range(5_000)]
        cur += [{"file": f"n{i}.py", "line": i, "rule_id": "r", "message": f"new {i}"}
                for i in range(2_000)]
        d = diff_findings(prev, cur)
        self.assertEqual(d["moved_count"], 5_000)     # 줄 이동은 moved(삭제+신규 아님)
        self.assertEqual(d["new_count"], 2_000)
        self.assertEqual(d["removed_count"], 5_000)

    def test_sampling_100k_population_deterministic(self) -> None:
        from mori_soc.services.sampling import risk_based_sample
        pop = [{"id": f"{i:06d}", "risk": "관리자" if i < 30 else "일반"} for i in range(100_000)]
        a = risk_based_sample(pop, high_cap=20, sample_rate=0.01, expected_population=100_000)
        b = risk_based_sample(list(reversed(pop)), high_cap=20, sample_rate=0.01,
                              expected_population=100_000)
        self.assertEqual(a["high_count"], 20)          # 고위험 상한
        self.assertTrue(a["population_complete"])
        # 결정적 — 순서 달라도 같은 표본
        self.assertEqual([x["id"] for x in a["sample"]], [x["id"] for x in b["sample"]])

    def test_governance_diff_5k_controls(self) -> None:
        from mori_soc.services.control_governance import diff_control_definitions
        old = [{"id": f"v1:{i}", "control_uid": f"u{i}", "display_code": str(i), "title": "t",
                "requirement_text": "req"} for i in range(5_000)]
        # 절반 번호변경, 500 내용변경, 500 삭제, 신규 300
        new = [{"id": f"v2:{i}", "control_uid": f"u{i}", "display_code": str(i + 1), "title": "t",
                "requirement_text": ("changed" if i < 500 else "req")}
               for i in range(4_500)]
        new += [{"id": f"v2:n{i}", "control_uid": f"new{i}", "display_code": str(i), "title": "t"}
                for i in range(300)]
        d = diff_control_definitions(old, new)
        self.assertEqual(d["counts"]["text_changed"], 500)
        self.assertEqual(d["counts"]["added"], 300)
        self.assertEqual(d["counts"]["removed"], 500)   # u4500..u4999


if __name__ == "__main__":
    unittest.main()
