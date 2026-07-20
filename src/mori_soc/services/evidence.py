"""통제 증적 provenance·불변성 헬퍼(#21).

증적 레코드는 재승격 시 결정적 id 로 upsert(덮어쓰기)된다. 감사 시점 재현을 위해 각 레코드에
**content_hash**(의미 내용의 sha256) 와 **version** 을 찍는다. 같은 내용이면 같은 해시(재승격이
실제로 내용을 바꿨는지 판별 가능), 내용이 바뀌면 해시가 달라져 변경을 감지할 수 있다.
"""
from __future__ import annotations

from typing import Any

from mori_soc.services.hashing import content_hash as _content_hash

# content_hash 계산에 쓰는 '의미 있는' 필드(존재하는 것만). id·타임스탬프·updated_at 은 제외
# (같은 증적 내용이면 언제 승격하든 같은 해시가 나오도록).
_CONTENT_KEYS = (
    "control_id", "title", "body", "summary", "source", "source_event_id",
    "repo", "commit", "reference", "findings_count", "verified", "collected_at",
    "collected_by",
)


def content_hash(rec: dict[str, Any]) -> str:
    return _content_hash(rec, include=_CONTENT_KEYS)


def stamp_evidence(rec: dict[str, Any]) -> dict[str, Any]:
    """레코드에 content_hash·version·generated_at·provenance 를 채운다(제자리 수정)."""
    from mori_soc.services.provenance import attach_provenance
    h = content_hash(rec)
    rec["content_hash"] = h
    rec.setdefault("version", h[:12])
    rec.setdefault("generated_at", rec.get("created_at") or rec.get("collected_at"))
    attach_provenance(rec)   # 출처 태그(CODE/API/RULE/AI/HUMAN/POLICY) — 모리다움
    return rec
