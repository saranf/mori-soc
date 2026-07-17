"""기술 Gap 워크플로(#5) — MORI 가 발견한 기술 결함 후보를 사람이 판단·조치·재검증.

풀 GRC 의 시정조치 모듈이 아니라, 스캔이 만든 기술 Gap 을 닫는 최소 흐름:
  candidate(후보) → confirmed(실제 결함) / false_positive(오탐) / policy_review(정책 확인)
  confirmed → remediation(조치 중) / accepted_exception(예외 수용)
  remediation → resolved(재검증됨) / confirmed(재조치)
AI 가 확정하지 않는다 — 후보를 만들고 사람이 판단한다(모리다움).
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

STATUSES = ("candidate", "confirmed", "policy_review", "false_positive",
            "remediation", "accepted_exception", "resolved")

# target -> 그 상태로 갈 수 있는 현재 상태들.
_VALID: dict[str, set[str]] = {
    "confirmed": {"candidate", "policy_review", "remediation", "accepted_exception"},
    "false_positive": {"candidate", "policy_review"},
    "policy_review": {"candidate"},
    "remediation": {"confirmed"},
    "accepted_exception": {"confirmed"},
    "resolved": {"remediation"},
    "candidate": set(),   # 생성 전용
}

# 사람 판단이 필요한(=담당자 지정 권장) 상태.
OPEN_STATUSES = {"candidate", "confirmed", "policy_review", "remediation"}
CLOSED_STATUSES = {"false_positive", "accepted_exception", "resolved"}


def can_transition(current: str, target: str) -> bool:
    return target in _VALID and str(current or "candidate") in _VALID[target]


def gap_id_for(source: str, control_id: str, key: str) -> str:
    """Gap 결정적 id — 같은 결함(source·control·key)이면 같은 id(중복 생성 방지)."""
    return "gap-" + hashlib.sha1(f"{source}|{control_id}|{key}".encode("utf-8")).hexdigest()[:16]


def build_gap(*, source: str, control_id: str, key: str, title: str, detail: str, now: str,
              created_by: str = "system") -> dict[str, Any]:
    """Gap 후보 레코드(candidate)."""
    return {
        "gap_id": gap_id_for(source, control_id, key),
        "source": source, "control_id": control_id, "key": key,
        "title": title, "detail": detail,
        "status": "candidate", "assignee": "", "due_date": "",
        "resolution": "", "evidence_ref": "",
        "created_by": created_by, "created_at": now, "updated_at": now,
        "history": [{"ts": now, "actor": created_by, "action": "created", "to": "candidate"}],
    }


def apply_transition(gap: dict[str, Any], target: str, *, actor: str, now: str,
                     assignee: str = "", due_date: str = "", note: str = "") -> dict[str, Any]:
    """Gap 상태 전이(제자리 갱신). history 에 append. 유효성은 호출자가 can_transition 으로 확인."""
    gap["status"] = target
    gap["updated_at"] = now
    if assignee:
        gap["assignee"] = assignee
    if due_date:
        gap["due_date"] = due_date
    if note and target in ("resolved", "accepted_exception", "false_positive"):
        gap["resolution"] = note
    gap.setdefault("history", []).append(
        {"ts": now, "actor": actor, "action": "transition", "to": target, "note": note})
    return gap


def _as_date(v: str) -> datetime | None:
    s = str(v or "").strip()
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(s[:len(fmt) + 6], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def evaluate_gap_deadlines(
    gaps: list[dict[str, Any]], now: str, *, soon_days: int = 14,
) -> dict[str, Any]:
    """Gap 조치 기한·예외 만료를 평가한다(#14).

    모리다움 — 예외는 영구가 아니다. 자동 연장하지 않고 **만료를 표면화**해 재검토를 강제한다.
    - overdue: 열린 Gap(candidate/confirmed/policy_review/remediation)이 due_date 를 넘김.
    - expired_exception: accepted_exception 의 만료일(due_date)이 지남 → 재검토 필요(자동연장 금지).
    - expiring_soon: 예외 만료가 soon_days 이내로 임박.
    """
    nd = _as_date(now)
    overdue: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    soon: list[dict[str, Any]] = []
    for g in gaps:
        status = str(g.get("status") or "")
        due = _as_date(g.get("due_date"))
        if nd is None or due is None:
            continue
        days_left = (due - nd).days
        row = {"gap_id": g.get("gap_id"), "title": g.get("title"), "control_id": g.get("control_id"),
               "assignee": g.get("assignee"), "due_date": g.get("due_date"),
               "status": status, "days_left": days_left}
        if status == "accepted_exception":
            if due < nd:
                expired.append(row)
            elif days_left <= soon_days:
                soon.append(row)
        elif status in OPEN_STATUSES and due < nd:
            overdue.append(row)
    overdue.sort(key=lambda r: r["days_left"])
    expired.sort(key=lambda r: r["days_left"])
    soon.sort(key=lambda r: r["days_left"])
    return {"overdue": overdue, "expired_exception": expired, "expiring_soon": soon,
            "counts": {"overdue": len(overdue), "expired_exception": len(expired),
                       "expiring_soon": len(soon)}}
