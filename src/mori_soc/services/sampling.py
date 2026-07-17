"""위험 기반 감사 표본 추출(#13).

전체 내부감사 모듈이 아니라, 특정 통제의 증적 **모집단에서 위험 기반 표본을 추출해 감사 패키지**로
만드는 최소 기능(모리다움 — 작게, 증적 중심). 감사 재현성을 위해 **결정적**(난수 미사용) 추출:
고위험 전수(또는 상한) + 나머지는 계통추출(1-in-k). 같은 모집단·파라미터면 항상 같은 표본.
"""
from __future__ import annotations

import math
from typing import Any, Iterable

DEFAULT_HIGH_VALUES = ("high", "critical", "상", "관리자", "admin", "퇴사자", "leaver")


def _key(item: dict[str, Any], field: str) -> str:
    return str(item.get(field) or "")


def risk_based_sample(
    population: Iterable[dict[str, Any]],
    *,
    risk_field: str = "risk",
    high_values: Iterable[str] = DEFAULT_HIGH_VALUES,
    high_cap: int = 20,
    sample_rate: float = 0.1,
    order_field: str = "id",
    expected_population: int | None = None,
) -> dict[str, Any]:
    """모집단에서 위험 기반 표본을 결정적으로 추출한다.

    - 고위험(risk_field 값이 high_values 에 포함): order_field 정렬 후 high_cap 까지 전수.
    - 나머지: order_field 정렬 후 계통추출(1-in-k, k=round(1/sample_rate)) — 결정적.
    반환: population/sample 수·표본 목록·선정 방법 설명(감사관 제출용).

    **모집단 완전성(리뷰 #22)**: expected_population(소스가 아는 실제 대상 수)을 주면, MORI 가 수집한
    모집단이 그보다 작을 때 `population_complete=False` + 누락 수를 표시한다. 모집단이 불완전하면
    표본이 무의미하므로 감사 전에 반드시 표면화한다(모리다움 — 정직).
    """
    pop = list(population)
    highs = {str(v).strip().lower() for v in high_values}

    def _is_high(it: dict[str, Any]) -> bool:
        return _key(it, risk_field).strip().lower() in highs

    ordered = sorted(pop, key=lambda it: (_key(it, order_field), _key(it, risk_field)))
    high_items = [it for it in ordered if _is_high(it)][:high_cap]
    rest = [it for it in ordered if not _is_high(it)]

    k = max(1, round(1 / sample_rate)) if sample_rate > 0 else 0
    systematic = rest[::k] if k else []

    sample = high_items + systematic
    method = (f"위험 기반 — 고위험 전수(최대 {high_cap}) + 나머지 계통추출 1-in-{k}"
              if k else f"위험 기반 — 고위험 전수(최대 {high_cap})")
    result: dict[str, Any] = {
        "population": len(pop),
        "high_count": len(high_items),
        "systematic_count": len(systematic),
        "sample_count": len(sample),
        "coverage_pct": round(len(sample) * 100 / len(pop)) if pop else 0,
        "method": method,
        "sample": sample,
        "params": {"risk_field": risk_field, "high_cap": high_cap,
                   "sample_rate": sample_rate, "interval_k": k, "order_field": order_field},
    }
    # 모집단 완전성(리뷰 #22) — 소스가 아는 실제 대상 수 대비 수집된 모집단이 온전한가.
    if expected_population is not None:
        missing = max(0, int(expected_population) - len(pop))
        result["expected_population"] = int(expected_population)
        result["missing_from_population"] = missing
        result["population_complete"] = missing == 0
        if missing:
            result["population_warning"] = (
                f"모집단 불완전: 소스 기준 {expected_population}건 중 {len(pop)}건만 수집됨"
                f"({missing}건 누락). 표본 결과 신뢰 전에 소스 수집 상태를 먼저 확인하세요."
            )
    return result


def sample_size_for(population_n: int, high_cap: int = 20, sample_rate: float = 0.1) -> int:
    """대략적 표본 크기(고위험 상한 + 나머지 계통)를 미리 계산(UI 안내용, 결정치 아님)."""
    if population_n <= 0:
        return 0
    high = min(high_cap, population_n)
    rest = population_n - high
    k = max(1, round(1 / sample_rate)) if sample_rate > 0 else 0
    return high + (math.ceil(rest / k) if k else 0)


__all__ = ["risk_based_sample", "sample_size_for", "DEFAULT_HIGH_VALUES"]
