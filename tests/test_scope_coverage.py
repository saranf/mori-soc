import unittest

from mori_soc.services.scope_coverage import compute_scope_coverage, normalize_tags


class ScopeCoverageTests(unittest.TestCase):
    def test_normalize_tags(self) -> None:
        self.assertEqual(normalize_tags("인증범위 포함, 운영환경"), ["인증범위 포함", "운영환경"])
        self.assertEqual(normalize_tags(["a", "a", " b "]), ["a", "b"])
        self.assertEqual(normalize_tags(None), [])

    def test_coverage_counts(self) -> None:
        owners = [
            {"hostname": "web-01", "scope_tags": ["인증범위 포함", "운영환경"]},
            {"hostname": "web-02", "scope_tags": ["인증범위 포함"]},
            {"hostname": "legacy-01", "scope_tags": ["인증범위 포함"]},  # 모니터링 안 됨
            {"hostname": "dev-01", "scope_tags": ["개발환경"]},
        ]
        monitored = ["web-01", "WEB-02"]  # 대소문자 무시
        cov = compute_scope_coverage(owners, monitored)
        by = {t["tag"]: t for t in cov["tags"]}
        # 인증범위 포함: 3자산 중 2 모니터링 = 67%
        self.assertEqual(cov["in_scope"]["assets"], 3)
        self.assertEqual(cov["in_scope"]["monitored"], 2)
        self.assertEqual(cov["in_scope"]["coverage_pct"], 67)
        self.assertEqual(by["운영환경"]["assets"], 1)
        self.assertEqual(by["개발환경"]["monitored"], 0)

    def test_empty(self) -> None:
        cov = compute_scope_coverage([], [])
        self.assertEqual(cov["in_scope"]["coverage_pct"], 0)
        self.assertEqual(cov["tags"], [])


if __name__ == "__main__":
    unittest.main()
