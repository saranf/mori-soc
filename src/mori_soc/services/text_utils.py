"""문자열·시간 파싱 공용 헬퍼 (공통화 C11).

ISO 시각 파싱(`fromisoformat` + `Z`→`+00:00`)이 account_recon·evidence_freshness·
fleet_api 등에 제각각 복붙돼 있던 것을 모은다. tz 처리만 호출부마다 달라 파라미터로 둔다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_iso(value: Any, *, assume_utc: bool = False) -> datetime | None:
    """ISO 문자열 → datetime(파싱 실패 시 None). `Z` 접미어를 `+00:00` 로 보정.

    assume_utc=True 면 tz 없는 값에 UTC 를 붙인다(순진한 로컬 해석 방지). 빈/None 은 None.
    """
    s = str(value or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if assume_utc and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
