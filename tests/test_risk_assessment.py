"""R-1: 위험성 평가 산정 엔진 단위 테스트.

순수 함수(모델/DB 무의존)이므로 어떤 백엔드 설정에서도 항상 실행된다.
"""
from __future__ import annotations

import unittest

from mori_soc.services.risk_assessment import (
    IMPACT_SCORE,
    SEVERITY_LIKELIHOOD,
    RiskAssessment,
    assess_risk,
)


class RiskAssessmentTests(unittest.TestCase):
    def test_matrix_corners(self) -> None:
        """3×3 매트릭스 네 모서리의 등급이 설계와 일치한다."""
        # 상 × critical(발생가능성 상) → 9 매우높음
        top = assess_risk("상", "critical")
        self.assertEqual((top.impact, top.likelihood, top.score), (3, 3, 9))
        self.assertEqual(top.level, "매우높음")
        self.assertEqual(top.level_en, "Critical")

        # 하 × info → 1 낮음
        low = assess_risk("하", "info")
        self.assertEqual((low.impact, low.likelihood, low.score), (1, 1, 1))
        self.assertEqual(low.level, "낮음")

        # 상 × info → impact3 × likelihood1 = 3 중간
        self.assertEqual(assess_risk("상", "info").level, "중간")
        # 하 × critical → 1 × 3 = 3 중간
        self.assertEqual(assess_risk("하", "critical").level, "중간")

    def test_level_bands(self) -> None:
        """점수 1~9 → 4등급 경계 매핑."""
        cases = {
            (1, "하", "low"): "낮음",       # 1*1=1
            (2, "중", "low"): "낮음",       # 2*1=2
            (3, "중", "medium"): "중간",    # 2*2=4 -> 중간 (아래서 재확인)
        }
        # 명시적 점수-등급 경계
        self.assertEqual(assess_risk("하", "low").score, 1)
        self.assertEqual(assess_risk("하", "low").level, "낮음")
        self.assertEqual(assess_risk("중", "medium").score, 4)
        self.assertEqual(assess_risk("중", "medium").level, "중간")
        self.assertEqual(assess_risk("상", "high").score, 9)  # 3*3
        self.assertEqual(assess_risk("상", "high").level, "매우높음")
        self.assertEqual(assess_risk("중", "critical").score, 6)  # 2*3
        self.assertEqual(assess_risk("중", "critical").level, "높음")

    def test_fixed_available_bumps_likelihood(self) -> None:
        """공개 패치 존재 시 발생가능성 +1, 등급 상승."""
        base = assess_risk("중", "medium")  # likelihood 2, score 4 중간
        bumped = assess_risk("중", "medium", fixed_available=True)  # likelihood 3, score 6 높음
        self.assertEqual(base.likelihood, 2)
        self.assertEqual(bumped.likelihood, 3)
        self.assertEqual(bumped.level, "높음")
        # 보정 전 값은 감사 추적용으로 보존
        self.assertEqual(bumped.likelihood_base, 2)

    def test_exception_expired_bumps_likelihood(self) -> None:
        base = assess_risk("상", "low")  # likelihood 1, score 3 중간
        bumped = assess_risk("상", "low", exception_expired=True)  # likelihood 2, score 6 높음
        self.assertEqual(bumped.likelihood, 2)
        self.assertEqual(bumped.level, "높음")

    def test_likelihood_clamped_to_three(self) -> None:
        """두 보정이 겹쳐도 발생가능성은 3을 넘지 않는다."""
        r = assess_risk("상", "critical", fixed_available=True, exception_expired=True)
        self.assertEqual(r.likelihood, 3)
        self.assertEqual(r.score, 9)

    def test_unknown_inputs_use_safe_defaults(self) -> None:
        """중요도/severity 미상 → 중(2) / 하(1) 로 안전 기본값."""
        r = assess_risk(None, None)
        self.assertEqual(r.impact, 2)      # 중
        self.assertEqual(r.likelihood, 1)  # 하
        self.assertEqual(r.impact_label, "중")
        self.assertEqual(r.likelihood_label, "하")
        # 사전에 없는 문자열도 동일 처리
        self.assertEqual(assess_risk("HIGH", "unknown").impact, 2)

    def test_severity_case_insensitive(self) -> None:
        self.assertEqual(assess_risk("상", "CRITICAL").likelihood_base, 3)
        self.assertEqual(assess_risk("상", " High ").likelihood_base, 3)

    def test_to_dict_shape(self) -> None:
        d = assess_risk("상", "critical").to_dict()
        self.assertEqual(
            set(d),
            {
                "impact",
                "likelihood",
                "likelihood_base",
                "score",
                "level",
                "level_en",
                "impact_label",
                "likelihood_label",
            },
        )
        self.assertEqual(d["level"], "매우높음")

    def test_result_is_frozen(self) -> None:
        r = assess_risk("상", "critical")
        self.assertIsInstance(r, RiskAssessment)
        with self.assertRaises(Exception):
            r.score = 0  # type: ignore[misc]

    def test_constants_cover_expected_domains(self) -> None:
        self.assertEqual(set(IMPACT_SCORE), {"상", "중", "하"})
        self.assertEqual(
            set(SEVERITY_LIKELIHOOD),
            {"critical", "high", "medium", "low", "info"},
        )


if __name__ == "__main__":
    unittest.main()
