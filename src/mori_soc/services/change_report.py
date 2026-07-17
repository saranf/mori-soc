"""월별 evidence change report(#15).

경영진·감사용 '지난달 대비 무엇이 바뀌었나'를 MORI 데이터에서 **바로 도출**한다(별도 BI 제품이
아님, 모리다움). 새 증적·승인/대체·신규 Gap·조치/예외/재검증을 기간으로 집계한다.

순수 함수 — I/O 없음. 기간은 [start, end) ISO 문자열(문자열 비교로 안전).
"""
from __future__ import annotations

from calendar import monthrange
from typing import Any


def month_bounds(month: str) -> tuple[str, str]:
    """'YYYY-MM' → (해당 달 1일 ISO, 다음 달 1일 ISO). 잘못된 입력은 ValueError."""
    y, m = month.split("-")
    yi, mi = int(y), int(m)
    if not (1 <= mi <= 12):
        raise ValueError("month must be YYYY-MM")
    start = f"{yi:04d}-{mi:02d}-01T00:00:00+00:00"
    ny, nm = (yi + 1, 1) if mi == 12 else (yi, mi + 1)
    end = f"{ny:04d}-{nm:02d}-01T00:00:00+00:00"
    _ = monthrange(yi, mi)  # 유효 월 검증
    return start, end


def _in(iso: Any, start: str, end: str) -> bool:
    s = str(iso or "")
    return bool(s) and start <= s < end


def build_evidence_change_report(
    period_start: str,
    period_end: str,
    *,
    evidence: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    gaps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """기간 내 증적·승인·Gap 변화를 집계한다.

    - new_evidence: generated_at 이 기간 내인 증적(통제별 카운트 포함).
    - approvals: 기간 내 생성된 승인 스냅샷을 status 별 집계(approved/superseded/revoked…).
    - new_gaps: 기간 내 생성된 Gap 후보.
    - gap_transitions: 기간 내 Gap history 전이를 to 상태별 집계(resolved/accepted_exception 등).
    """
    evidence = evidence or []
    approvals = approvals or []
    gaps = gaps or []

    new_ev = [e for e in evidence if _in(e.get("generated_at") or e.get("created_at"),
                                          period_start, period_end)]
    ev_by_control: dict[str, int] = {}
    for e in new_ev:
        cid = str(e.get("control_id") or "")
        ev_by_control[cid] = ev_by_control.get(cid, 0) + 1

    appr_by_status: dict[str, int] = {}
    for a in approvals:
        if _in(a.get("created_at"), period_start, period_end):
            st = str(a.get("status") or "unknown")
            appr_by_status[st] = appr_by_status.get(st, 0) + 1

    new_gaps = [g for g in gaps if _in(g.get("created_at"), period_start, period_end)]

    gap_trans: dict[str, int] = {}
    resolved: list[dict[str, Any]] = []
    exceptions: list[dict[str, Any]] = []
    for g in gaps:
        for h in g.get("history") or []:
            if h.get("action") == "transition" and _in(h.get("ts"), period_start, period_end):
                to = str(h.get("to") or "")
                gap_trans[to] = gap_trans.get(to, 0) + 1
                row = {"gap_id": g.get("gap_id"), "title": g.get("title"),
                       "control_id": g.get("control_id"), "ts": h.get("ts")}
                if to == "resolved":
                    resolved.append(row)
                elif to == "accepted_exception":
                    exceptions.append(row)

    return {
        "period_start": period_start,
        "period_end": period_end,
        "new_evidence_count": len(new_ev),
        "new_evidence_by_control": ev_by_control,
        "approvals_by_status": appr_by_status,
        "new_gap_count": len(new_gaps),
        "new_gaps": [{"gap_id": g.get("gap_id"), "title": g.get("title"),
                      "control_id": g.get("control_id")} for g in new_gaps],
        "gap_transitions": gap_trans,
        "resolved_gaps": resolved,
        "new_exceptions": exceptions,
    }


__all__ = ["month_bounds", "build_evidence_change_report"]
