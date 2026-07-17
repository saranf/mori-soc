"""공용 소형 유틸(중복 제거) — 시각·CSV 인코딩.

리뷰 findings C6(datetime.now 반복)·C4(CSV BOM 반복) 대응. 순수 함수.
"""
from __future__ import annotations

from datetime import datetime, timezone

_UTF8_BOM = "﻿"   # Excel 이 UTF-8 을 인식하도록 앞에 붙이는 BOM


def now_iso() -> str:
    """현재 UTC 시각 ISO8601 문자열. (테스트는 이 함수를 patch 해 고정)"""
    return datetime.now(tz=timezone.utc).isoformat()


def to_utf8_bom(text: str) -> bytes:
    """CSV 문자열 → BOM 접두 UTF-8 바이트(Excel 한글 호환). 이미 BOM 이면 중복 안 붙임."""
    if text.startswith(_UTF8_BOM):
        return text.encode("utf-8")
    return (_UTF8_BOM + text).encode("utf-8")


__all__ = ["now_iso", "to_utf8_bom"]
