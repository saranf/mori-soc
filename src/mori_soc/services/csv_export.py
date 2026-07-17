"""CSV 다운로드 공통 헬퍼 — 라우트마다 반복되던 StringIO+DictWriter+파일명 로직을 한 곳에.

`csv.DictWriter` 를 쓰므로 콤마·따옴표·개행·유니코드가 자동으로 올바르게 이스케이프된다
(수기 join 이 아니라 표준 모듈 → 필드깨짐 방지). 파일명은 UTC 타임스탬프를 붙인다.

추가로 **CSV 수식 인젝션(Formula/DDE injection)** 을 막는다 — DictWriter 는 구분자만 이스케이프하고
Excel/Sheets 가 `=`,`+`,`-`,`@`,탭/CR 로 시작하는 셀을 수식으로 실행하는 것은 막지 못한다.
MORI 는 자산 담당자·finding·개인정보 등 **사용자 입력**을 감사관용 CSV 로 내보내므로, 위험 문자로
시작하는 셀(숫자는 제외) 앞에 `'` 를 붙여 무력화한다(OWASP 권고).
"""
from __future__ import annotations

import csv as _csv
import io
import logging
import os
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import StreamingResponse

_log = logging.getLogger("mori_soc.export")


def _max_export_rows() -> int:
    """단일 export 행 상한(#25 — 대량 export 메모리 폭증 방어). 0 이면 무제한. 기본 100000."""
    try:
        return int(os.environ.get("MORI_MAX_EXPORT_ROWS", "100000"))
    except ValueError:
        return 100000


def _cap_rows(rows: Iterable[Mapping[str, Any]]) -> tuple[list[Mapping[str, Any]], bool]:
    rows = list(rows)
    cap = _max_export_rows()
    if cap > 0 and len(rows) > cap:
        _log.warning("export 행 %d건이 상한 %d 초과 — 초과분 제외(필터로 좁혀 다시 받으세요)", len(rows), cap)
        return rows[:cap], True
    return rows, False


_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _looks_numeric(s: str) -> bool:
    """정상 숫자(음수·소수·천단위 콤마 포함)면 True — 무력화 대상에서 제외한다."""
    t = s.strip().replace(",", "")
    if not t:
        return False
    try:
        float(t)
        return True
    except ValueError:
        return False


def _defuse(value: Any) -> Any:
    """수식 인젝션 무력화 — 위험 문자로 시작하는 문자열(숫자 아님) 앞에 `'` 를 붙인다."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in _FORMULA_TRIGGERS and not _looks_numeric(value):
        return "'" + value
    return value


def render_csv(rows: Iterable[Mapping[str, Any]], header_map: Mapping[str, str]) -> str:
    """행 목록 → CSV 문자열. header_map = {필드키: 표시헤더}. 표시헤더가 첫 줄.

    각 셀은 수식 인젝션 무력화(_defuse)를 거친다(감사관 CSV 안전).
    """
    buf = io.StringIO()
    keys = list(header_map.keys())
    writer = _csv.DictWriter(buf, fieldnames=keys, extrasaction="ignore")
    writer.writerow(dict(header_map))
    for row in rows:
        writer.writerow({k: _defuse(row.get(k)) for k in keys})
    return buf.getvalue()


def csv_streaming_response(
    rows: Iterable[Mapping[str, Any]],
    header_map: Mapping[str, str],
    filename_prefix: str,
    *,
    timestamp: str | None = None,
) -> StreamingResponse:
    """UI 공통 CSV 다운로드 응답 — `<prefix>-<UTC타임스탬프>.csv` 첨부.

    행이 상한(MORI_MAX_EXPORT_ROWS)을 넘으면 초과분을 제외하고 헤더로 알린다(잘림 표시).
    """
    capped_rows, truncated = _cap_rows(rows)
    body = render_csv(capped_rows, header_map)
    ts = timestamp or datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    headers = {"Content-Disposition": f'attachment; filename="{filename_prefix}-{ts}.csv"'}
    if truncated:
        headers["X-MORI-Export-Truncated"] = "true"   # 클라이언트가 잘림을 인지할 수 있게
    return StreamingResponse(iter([body]), media_type="text/csv; charset=utf-8", headers=headers)
