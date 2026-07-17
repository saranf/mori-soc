"""통제별 증적 신선도·데이터 품질 계산(#11).

MORI 는 자동 수집 증적이 많다. 각 통제 증적이 **얼마나 최신인지·담당자가 언제 검토했는지·
소스가 연결돼 있는지**를 계산해 '초록 Compliant' 대신 신뢰 품질 상태를 보여준다.
GRC 기능이 아니라 **자동 증적의 신뢰 품질을 관리**하는 기능(모리다움).

순수 함수 — I/O 없음. 시각은 호출자가 ISO 문자열로 주입(테스트 결정성).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

# 상태값 — '초록 하나'가 아니라 신뢰 품질을 구분한다.
STATUSES = (
    "no_evidence",       # 증적 없음
    "evidence_stale",    # 증적이 오래됨(수집 후 stale_days 초과)
    "review_required",   # 담당자 검토가 없거나 오래됨
    "human_verified",    # 승인(사람 검증) 완료 + 최신
    "evidence_available",  # 최신 증적 있음(검토 전)
)


def _parse(iso: str) -> datetime | None:
    s = str(iso or "").strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_days(iso: str, now: datetime) -> int | None:
    dt = _parse(iso)
    if dt is None:
        return None
    if dt.tzinfo is None and now.tzinfo is not None:
        dt = dt.replace(tzinfo=now.tzinfo)
    return max(0, (now - dt).days)


def _latest(recs: list[dict[str, Any]], field: str) -> str:
    vals = [str(r.get(field) or "") for r in recs if str(r.get(field) or "")]
    return max(vals) if vals else ""


def compute_freshness(
    recs: list[dict[str, Any]],
    now_iso: str,
    *,
    approval: dict[str, Any] | None = None,
    approval_status: str = "",
    stale_days: int = 90,
    review_stale_days: int = 180,
) -> dict[str, Any]:
    """한 통제의 증적 신선도·품질을 계산한다.

    - last_collected: 증적 중 가장 최신 generated_at.
    - age_days: last_collected 로부터 경과일. stale_days 초과면 stale.
    - applied/missing: 증적 레코드에 적용/누락 대상 수가 있으면 합산(없으면 0).
    - reviewed_at/review_age_days: 최신 승인본의 승인 시각(승인=사람 검토).
    - status: STATUSES 중 하나(신뢰 품질).
    """
    now = _parse(now_iso) or datetime.now()
    count = len(recs)
    if count == 0:
        return {
            "count": 0, "status": "no_evidence", "last_collected": "", "age_days": None,
            "stale": False, "applied": 0, "missing": 0, "sources": [],
            "reviewed_at": "", "review_age_days": None,
        }

    last_collected = _latest(recs, "generated_at") or _latest(recs, "created_at")
    age = _age_days(last_collected, now)
    stale = age is not None and age > stale_days

    applied = sum(int(r.get("applied") or r.get("target_count") or 0) for r in recs)
    missing = sum(int(r.get("missing") or r.get("missing_count") or 0) for r in recs)
    sources = sorted({str(r.get("source") or "") for r in recs if r.get("source")})

    reviewed_at = ""
    if approval:
        reviewed_at = str(approval.get("approved_at") or approval.get("reviewed_at")
                          or approval.get("created_at") or "")
    review_age = _age_days(reviewed_at, now) if reviewed_at else None
    approved = approval_status == "approved"
    review_ok = approved and review_age is not None and review_age <= review_stale_days

    in_review_cycle = approval is not None and approval_status in ("draft", "reviewed", "superseded")
    if stale:
        status = "evidence_stale"
    elif review_ok:
        status = "human_verified"
    elif approved:
        # 승인은 됐으나 검토가 오래됨 → 재검토 필요.
        status = "review_required"
    elif in_review_cycle:
        # 검토 사이클은 시작됐으나 아직 승인 전 → 검토 필요.
        status = "review_required"
    else:
        # 최신 증적이 있으나 검토 사이클 미시작 → 사용 가능(검토로 승격 가능).
        status = "evidence_available"

    return {
        "count": count, "status": status, "last_collected": last_collected, "age_days": age,
        "stale": stale, "applied": applied, "missing": missing, "sources": sources,
        "reviewed_at": reviewed_at, "review_age_days": review_age,
    }


__all__ = ["STATUSES", "compute_freshness"]
