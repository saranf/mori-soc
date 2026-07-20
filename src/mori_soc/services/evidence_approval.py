"""증적 승인 라이프사이클·버전·불변성(#4) — MORI 가 만든 기술 증적을 감사 가능한 기록으로 고정.

새 스캔이 나와도 과거 **승인본을 덮어쓰지 않는다**. 승인은 그 시점의 스냅샷(기준 커밋·데이터
해시·PDF SHA-256·검토자·승인자)으로 고정되고, 새 내용이 승인되면 이전 승인본은 superseded 된다.

상태: draft → reviewed → approved → superseded / (어디서든) revoked.
"""
from __future__ import annotations

import hashlib
from typing import Any

from mori_soc.services.hashing import short_id

STATUSES = ("draft", "reviewed", "approved", "superseded", "revoked")

# 허용 전이(요청 상태로 갈 수 있는 현재 상태들).
_VALID: dict[str, set[str]] = {
    "reviewed": {"draft"},
    "approved": {"reviewed"},
    "draft": {"reviewed"},              # 반려(재검토 요청)
    "superseded": {"approved"},         # 새 승인본이 이전 것을 대체(보통 시스템이 처리)
    "revoked": {"draft", "reviewed", "approved", "superseded"},
}

# 각 전이에 필요한 역할(최소). approve 는 admin, review 는 admin·security.
ROLE_FOR: dict[str, tuple[str, ...]] = {
    "reviewed": ("admin", "security"),
    "approved": ("admin",),
    "draft": ("admin", "security"),
    "revoked": ("admin",),
    "superseded": ("admin",),
}


def can_transition(current: str, target: str) -> bool:
    """current → target 전이가 상태기계상 허용되는가."""
    return target in _VALID and str(current or "draft") in _VALID[target]


def pdf_sha256(pdf_bytes: bytes) -> str:
    """승인 대상 PDF 의 SHA-256(무결성 고정용)."""
    return hashlib.sha256(pdf_bytes or b"").hexdigest()


def build_approval(*, control_id: str, evidence_id: str, content_hash: str, version: str,
                   status: str, actor: str, reason: str = "", pdf_hash: str = "",
                   prev_approval_id: str = "", generated_at: str = "", now: str) -> dict[str, Any]:
    """승인 스냅샷 레코드를 만든다(불변 기록). approval_id 는 (evidence_id·content_hash·status·now) 결정적."""
    approval_id = short_id(evidence_id, content_hash, status, now, prefix="appr")
    record: dict[str, Any] = {
        "approval_id": approval_id,
        "control_id": control_id,
        "evidence_id": evidence_id,
        "content_hash": content_hash,
        "version": version or (content_hash[:12] if content_hash else ""),
        "status": status,
        "reviewer": actor if status == "reviewed" else "",
        "approver": actor if status == "approved" else "",
        "reviewed_at": now if status == "reviewed" else "",
        "approved_at": now if status == "approved" else "",
        "pdf_sha256": pdf_hash,
        "prev_approval_id": prev_approval_id,
        "supersede_reason": reason if status in ("superseded", "revoked", "draft") else "",
        "actor": actor,
        "created_at": now,
    }
    return record
