"""CSV 가져오기 공통 헬퍼 — export(csv_export)와 짝을 이루는 import 쪽 공통화.

`csv.DictReader` 로 콤마·따옴표·개행을 표준 파싱하고, 헤더를 정규 필드로 매핑한다(한/영 별칭
허용). BOM 제거·최대 행수 제한·필수 필드 검증까지 한 곳에서. 어떤 리소스든 (field_aliases 만
바꿔) 재사용할 수 있다.
"""
from __future__ import annotations

import csv as _csv
import io
import os
from collections.abc import Mapping, Sequence
from typing import Any


def _max_import_rows() -> int:
    """단일 import 최대 행수(대량 업로드 방어). 0 이면 무제한. 기본 100000."""
    try:
        return int(os.environ.get("MORI_MAX_IMPORT_ROWS", "100000"))
    except ValueError:
        return 100000


def _normalize(h: str) -> str:
    return str(h or "").strip().lower().replace(" ", "").replace("_", "")


def parse_csv(
    text: str,
    field_aliases: Mapping[str, Sequence[str]],
    *,
    required: Sequence[str] = (),
) -> tuple[list[dict[str, str]], list[str]]:
    """CSV 텍스트 → 정규화된 dict 행 목록 + 오류 메시지 목록.

    field_aliases: {정규필드: [허용 헤더 별칭...]}. 헤더는 대소문자·공백·언더스코어 무시로 매칭.
    required: 값이 비면 그 행을 건너뛰고 오류로 기록할 필수 정규필드.
    반환: (rows, errors). 파싱 자체 실패도 errors 로 돌려준다(예외를 던지지 않음).
    """
    errors: list[str] = []
    text = (text or "").lstrip("﻿")
    if not text.strip():
        return [], ["빈 CSV 입니다."]

    # 정규필드 <- 정규화된 별칭 역인덱스
    alias_to_field: dict[str, str] = {}
    for field, aliases in field_aliases.items():
        alias_to_field[_normalize(field)] = field
        for a in aliases:
            alias_to_field[_normalize(a)] = field

    try:
        reader = _csv.reader(io.StringIO(text))
        raw_rows = list(reader)
    except Exception as exc:  # noqa: BLE001
        return [], [f"CSV 파싱 실패: {exc}"]
    if not raw_rows:
        return [], ["헤더가 없습니다."]

    header = raw_rows[0]
    # 컬럼 index -> 정규필드 (매핑 안 되는 컬럼은 무시)
    col_field: dict[int, str] = {}
    for i, h in enumerate(header):
        f = alias_to_field.get(_normalize(h))
        if f is not None:
            col_field[i] = f
    if not col_field:
        return [], [f"알 수 있는 컬럼이 없습니다(허용: {', '.join(field_aliases.keys())})."]

    cap = _max_import_rows()
    rows: list[dict[str, str]] = []
    for lineno, raw in enumerate(raw_rows[1:], start=2):
        if not any(str(c).strip() for c in raw):
            continue  # 빈 줄 스킵
        if cap > 0 and len(rows) >= cap:
            errors.append(f"행 상한 {cap} 초과 — 이후 행 무시.")
            break
        rec: dict[str, str] = {}
        for i, val in enumerate(raw):
            f = col_field.get(i)
            if f is not None:
                rec[f] = str(val).strip()
        missing = [r for r in required if not rec.get(r)]
        if missing:
            errors.append(f"{lineno}행: 필수값 누락({', '.join(missing)}) — 건너뜀.")
            continue
        rows.append(rec)
    return rows, errors


def sample_csv(field_aliases: Mapping[str, Sequence[str]], example: Mapping[str, Any] | None = None) -> str:
    """가져오기 양식(헤더 + 예시 1행) 문자열 — UI 다운로드용."""
    fields = list(field_aliases.keys())
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(fields)
    if example:
        w.writerow([str(example.get(f, "")) for f in fields])
    return buf.getvalue()
