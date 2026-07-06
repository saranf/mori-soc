"""취약점 위험성 평가(Risk Assessment) 산정 엔진 — R-1.

ISMS-P(2.10 시스템 및 서비스 보안 / 위험관리) · ISO/IEC 27001:2022(6.1.2, 8.8)
요구사항인 **위험도 = 영향도(Impact) × 발생가능성(Likelihood)** 를 산정한다.

설계 원칙:
- 순수 함수. 모델/DB에 의존하지 않고 문자열·정수만 다룬다(단위 테스트 용이).
- 영향도 축은 이미 존재하는 **자산 중요도 상/중/하**(``asset_classifier`` 산출값 +
  ``asset_owners`` override, ``payloads.py``에서 해석)를 그대로 재사용한다.
- 발생가능성 축은 현재 데이터에 CVSS 숫자 점수가 없으므로(스키마·모델 부재)
  **severity(critical~info)** 를 기본값으로 하고, 조치 맥락(패치 가용·예외 만료)으로
  보정한다. 추후 폴러가 CVSS를 적재하면 5×5로 승격하기 쉽도록 축을 분리해 둔다.

3×3 매트릭스(영향도 × 발생가능성 = 점수 1~9)를 4개 위험등급으로 매핑한다::

    발생가능성→   하(1)   중(2)   상(3)
    영향도 상(3)   중간3   높음6   매우높음9
    영향도 중(2)   낮음2   중간4   높음6
    영향도 하(1)   낮음1   낮음2   중간3
"""
from __future__ import annotations

from dataclasses import dataclass

# ── 축 정의 ────────────────────────────────────────────────────────────────
# 영향도(Impact): 자산 중요도 상/중/하 → 3/2/1
IMPACT_SCORE: dict[str, int] = {"상": 3, "중": 2, "하": 1}

# 발생가능성(Likelihood) 기본값: severity → 3/2/1
SEVERITY_LIKELIHOOD: dict[str, int] = {
    "critical": 3,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 1,
}

# 위험등급 라벨 (score 1~9 → 4단계)
RISK_LEVELS: list[tuple[int, str, str]] = [
    # (이 점수 이하이면, 국문 등급, 영문 등급)
    (2, "낮음", "Low"),
    (4, "중간", "Medium"),
    (6, "높음", "High"),
    (9, "매우높음", "Critical"),
]

_DEFAULT_IMPACT = 2  # 중요도 미상 → '중'
_DEFAULT_LIKELIHOOD = 1  # severity 미상 → '하'
_LABEL_BY_SCORE = {3: "상", 2: "중", 1: "하"}


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """단일 (자산, 취약점) 조합의 산정 결과."""

    impact: int              # 영향도 1~3
    likelihood: int          # 발생가능성 1~3 (보정 후, clamp)
    score: int               # impact * likelihood (1~9)
    level: str               # 낮음 / 중간 / 높음 / 매우높음
    level_en: str            # Low / Medium / High / Critical
    impact_label: str        # 상 / 중 / 하
    likelihood_label: str    # 상 / 중 / 하
    likelihood_base: int     # 보정 전 severity 기반 발생가능성(감사 추적용)

    def to_dict(self) -> dict[str, object]:
        """API/CSV 직렬화용 평탄 dict."""
        return {
            "impact": self.impact,
            "likelihood": self.likelihood,
            "likelihood_base": self.likelihood_base,
            "score": self.score,
            "level": self.level,
            "level_en": self.level_en,
            "impact_label": self.impact_label,
            "likelihood_label": self.likelihood_label,
        }


def _clamp(value: int, low: int = 1, high: int = 3) -> int:
    return max(low, min(high, value))


def _level_for(score: int) -> tuple[str, str]:
    for threshold, ko, en in RISK_LEVELS:
        if score <= threshold:
            return ko, en
    return RISK_LEVELS[-1][1], RISK_LEVELS[-1][2]


def assess_risk(
    importance: str | None,
    severity: str | None,
    *,
    fixed_available: bool = False,
    exception_expired: bool = False,
) -> RiskAssessment:
    """영향도(자산 중요도) × 발생가능성(severity + 보정) → 위험등급.

    Args:
        importance: 자산 중요도 ``"상"/"중"/"하"`` (미상/None → '중' 처리).
        severity: 취약점 ``"critical"/"high"/"medium"/"low"/"info"``
            (미상/None → '하' 처리).
        fixed_available: 수정 버전(``fixed_version``)이 존재하면 True.
            공개 패치가 있다는 것은 취약점이 공개·알려져 있어 악용 가능성이
            높다는 신호이므로 발생가능성을 +1 보정한다.
        exception_expired: 등록된 예외(exception)의 유효기간이 만료됐는데도
            방치된 경우 True. 통제 공백으로 보고 발생가능성을 +1 보정한다.

    Returns:
        RiskAssessment. 보정은 발생가능성에만 적용되며 1~3으로 clamp된다.
    """
    impact = IMPACT_SCORE.get((importance or "").strip(), _DEFAULT_IMPACT)

    likelihood_base = SEVERITY_LIKELIHOOD.get((severity or "").strip().lower(), _DEFAULT_LIKELIHOOD)
    likelihood = likelihood_base
    if fixed_available:
        likelihood += 1
    if exception_expired:
        likelihood += 1
    likelihood = _clamp(likelihood)

    score = impact * likelihood
    level, level_en = _level_for(score)

    return RiskAssessment(
        impact=impact,
        likelihood=likelihood,
        score=score,
        level=level,
        level_en=level_en,
        impact_label=_LABEL_BY_SCORE[impact],
        likelihood_label=_LABEL_BY_SCORE[likelihood],
        likelihood_base=likelihood_base,
    )


__all__ = [
    "RiskAssessment",
    "assess_risk",
    "IMPACT_SCORE",
    "SEVERITY_LIKELIHOOD",
    "RISK_LEVELS",
]
