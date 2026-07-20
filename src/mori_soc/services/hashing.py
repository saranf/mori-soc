"""해시·캐노니컬화 단일 소스 (공통화 C1).

이전엔 content_hash/캐노니컬 JSON/짧은 결정적 id 가 evidence.py·control_governance.py·
evidence_bundle.py·provenance.py 등에 제각각 구현돼 캐노니컬화 규칙이 미묘하게 달랐다(감사
해시 드리프트 위험). 이 모듈이 유일한 구현이고, 호출부는 파라미터로 자기 규칙을 지정한다.

**출력 안정성** — 기존 각 구현의 바이트 출력을 그대로 재현하도록 파라미터화했다(separators·
접두어·포함/제외). 규칙이 바뀌면 같은 내용도 해시가 달라지므로 CANONICALIZATION 으로 방식을
레코드에 함께 기록한다. 순수 함수 — I/O·환경 접근 없음.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

# 캐노니컬화 방식 메타 — 레코드/매니페스트에 함께 남겨 재현성을 보장(리뷰 #6·#2).
CANONICALIZATION = "mori-jcs-v1"   # json.dumps(sort_keys · ensure_ascii=False · UTF-8)
HASH_ALGORITHM = "sha256"


def canonical_json(obj: Any, *, compact: bool = False) -> bytes:
    """캐노니컬 JSON 바이트 — 정렬 키·비ASCII 보존·UTF-8. 같은 내용이면 항상 같은 바이트.

    compact=True 면 separators=(",",":")(공백 없음) — Signed Evidence Bundle 매니페스트용.
    기본(False)은 dumps 기본 separators — content_hash 계열용(기존 출력과 동일).
    """
    seps = (",", ":") if compact else None
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=seps).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(record: Mapping[str, Any], *, include: Iterable[str] | None = None,
                 exclude: Iterable[str] | None = None, prefix: str = "",
                 compact: bool = False) -> str:
    """레코드 실질 내용의 sha256. include(화이트리스트) 또는 exclude(블랙리스트)로 대상 선정.

    - include: 그중 record 에 존재하는 키만(값은 record.get) — evidence 증적용.
    - exclude: 그 키를 뺀 전체 — control governance 용(prefix="sha256:").
    둘 다 없으면 record 전체. 접두어·compact 로 기존 각 구현의 출력을 그대로 재현한다.
    """
    if include is not None:
        core: dict[str, Any] = {k: record.get(k) for k in include if k in record}
    elif exclude is not None:
        ex = set(exclude)
        core = {k: v for k, v in record.items() if k not in ex}
    else:
        core = dict(record)
    return prefix + sha256_hex(canonical_json(core, compact=compact))


def short_id(*parts: Any, prefix: str = "", length: int = 16) -> str:
    """결정적 짧은 id — sha1(parts를 '|'로 결합)[:length]. prefix 있으면 'prefix-...'.

    기존 산재하던 `sha1(f"{a}|{b}").hexdigest()[:16]` 패턴을 그대로 재현(값은 str(p or ""))."""
    raw = "|".join(str(p or "") for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}" if prefix else digest
