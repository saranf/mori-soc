"""라우트 공용 HTTP 응답 헬퍼 (공통화 C6).

PDF 다운로드 응답(media_type + Content-Disposition + UTC 타임스탬프 파일명)이 여러 라우트에
복붙돼 있던 것을 한 곳으로 모은다. CSV 는 services/csv_export(csv_streaming_response·
csv_text_response), ZIP 은 services/evidence_bundle 에 대응 헬퍼가 있다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi.responses import Response


def _utc_stamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def pdf_response(pdf_bytes: bytes, filename_prefix: str, *, timestamp: str | None = None) -> "Response":
    """PDF 바이트 → 다운로드 응답(`<prefix>-<UTC>.pdf`, application/pdf)."""
    from fastapi.responses import Response
    ts = timestamp or _utc_stamp()
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename_prefix}-{ts}.pdf"'})
