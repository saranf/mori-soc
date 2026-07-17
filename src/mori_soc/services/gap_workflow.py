"""기술 Gap 워크플로(#5) — MORI 가 발견한 기술 결함 후보를 사람이 판단·조치·재검증.

풀 GRC 의 시정조치 모듈이 아니라, 스캔이 만든 기술 Gap 을 닫는 최소 흐름:
  candidate(후보) → confirmed(실제 결함) / false_positive(오탐) / policy_review(정책 확인)
  confirmed → remediation(조치 중) / accepted_exception(예외 수용)
  remediation → resolved(재검증됨) / confirmed(재조치)
AI 가 확정하지 않는다 — 후보를 만들고 사람이 판단한다(모리다움).
"""
from __future__ import annotations

import hashlib
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
