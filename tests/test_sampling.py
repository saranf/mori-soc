import unittest

from mori_soc.services.sampling import risk_based_sample, sample_size_for


class SamplingTests(unittest.TestCase):
    def _pop(self, n: int) -> list[dict]:
        # id 0..n-1; 5개는 관리자(고위험)
        pop = [{"id": f"{i:03d}", "risk": "관리자" if i < 5 else "일반"} for i in range(n)]
        return pop

    def test_high_risk_full_plus_systematic(self) -> None:
        res = risk_based_sample(self._pop(100), risk_field="risk", high_cap=20, sample_rate=0.1)
        self.assertEqual(res["population"], 100)
        self.assertEqual(res["high_count"], 5)          # 관리자 5명 전수
        # 나머지 95명 계통추출 1-in-10 → ceil(95/10)=10
        self.assertEqual(res["systematic_count"], 10)
        self.assertEqual(res["sample_count"], 15)

    def test_deterministic(self) -> None:
        a = risk_based_sample(self._pop(50))
        b = risk_based_sample(list(reversed(self._pop(50))))  # 순서 달라도 동일 표본
        self.assertEqual([x["id"] for x in a["sample"]], [x["id"] for x in b["sample"]])

    def test_high_cap(self) -> None:
        pop = [{"id": f"{i:03d}", "risk": "critical"} for i in range(30)]
        res = risk_based_sample(pop, high_cap=20, sample_rate=0.1)
        self.assertEqual(res["high_count"], 20)         # 상한 적용
        self.assertEqual(res["systematic_count"], 0)

    def test_empty(self) -> None:
        res = risk_based_sample([])
        self.assertEqual(res["sample_count"], 0)
        self.assertEqual(res["coverage_pct"], 0)

    def test_population_completeness(self) -> None:
        # 리뷰 #22: 소스가 아는 실제 대상 수보다 모집단이 작으면 표면화한다.
        res = risk_based_sample(self._pop(100), expected_population=150)
        self.assertFalse(res["population_complete"])
        self.assertEqual(res["missing_from_population"], 50)
        self.assertIn("population_warning", res)
        # 완전하면 경고 없음
        ok = risk_based_sample(self._pop(100), expected_population=100)
        self.assertTrue(ok["population_complete"])
        self.assertNotIn("population_warning", ok)
        # expected_population 미지정이면 완전성 판단 안 함(키 없음)
        none = risk_based_sample(self._pop(10))
        self.assertNotIn("population_complete", none)

    def test_sample_size_for(self) -> None:
        self.assertEqual(sample_size_for(0), 0)
        self.assertEqual(sample_size_for(100, high_cap=20, sample_rate=0.1), 20 + 8)  # 80/10=8


if __name__ == "__main__":
    unittest.main()
