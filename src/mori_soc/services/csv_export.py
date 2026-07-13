"""CSV 다운로드 공통 헬퍼 — 라우트마다 반복되던 StringIO+DictWriter+파일명 로직을 한 곳에.

`csv.DictWriter` 를 쓰므로 콤마·따옴표·개행·유니코드가 자동으로 올바르게 이스케이프된다
(수기 join 이 아니라 표준 모듈 → CSV 인젝션/필드깨짐 방지). 파일명은 UTC 타임스탬프를 붙인다.
"""
from __future__ import annotations

import csv as _csv
import io
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from fastapi.responses import StreamingResponse


def render_csv(rows: Iterable[Mapping[str, Any]], header_map: Mapping[str, str]) -> str:
    """행 목록 → CSV 문자열. header_map = {필드키: 표시헤더}. 표시헤더가 첫 줄."""
    buf = io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=list(header_map.keys()), extrasaction="ignore")
    writer.writerow(dict(header_map))
    writer.writerows(rows)
    return buf.getvalue()


def csv_streaming_response(
    rows: Iterable[Mapping[str, Any]],
    header_map: Mapping[str, str],
    filename_prefix: str,
    *,
    timestamp: str | None = None,
) -> StreamingResponse:
    """UI 공통 CSV 다운로드 응답 — `<prefix>-<UTC타임스탬프>.csv` 첨부."""
    body = render_csv(rows, header_map)
    ts = timestamp or datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(
        iter([body]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename_prefix}-{ts}.csv"'},
    )
