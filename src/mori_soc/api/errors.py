"""일관된 에러 택소노미(#39).

모든 에러 응답에 안정적인 `code` 와 `retryable` 을 실어 UI 가 재시도 여부를 판단할 수 있게
한다. 개별 raise 사이트를 모두 고칠 필요 없이 **예외 핸들러 한 곳**에서 HTTP status 기준으로
기본 code/retryable 을 부여한다(특정 핸들러가 구조화 detail 로 code 를 명시하면 그것을 우선).

응답 형태: {"detail": <사람이 읽는 메시지>, "code": <안정 코드>, "retryable": <bool>}
"""
from __future__ import annotations

from typing import Any

# HTTP status -> (안정 코드, 재시도 가능 여부)
_STATUS_MAP: dict[int, tuple[str, bool]] = {
    400: ("validation_error", False),
    401: ("auth_required", False),
    403: ("forbidden", False),
    404: ("not_found", False),
    409: ("conflict", False),
    422: ("validation_error", False),
    429: ("rate_limited", True),
    500: ("internal_error", True),
    502: ("external_api_error", True),
    503: ("source_unavailable", True),
    504: ("external_api_error", True),
}

_DEFAULT = ("error", False)


def error_meta(status_code: int) -> tuple[str, bool]:
    """status -> (code, retryable). 미정의 status 는 4xx=비재시도 / 5xx=재시도 기본."""
    if status_code in _STATUS_MAP:
        return _STATUS_MAP[status_code]
    if 500 <= status_code < 600:
        return ("internal_error", True)
    return _DEFAULT


def error_body(status_code: int, detail: Any) -> dict[str, Any]:
    """예외 핸들러가 반환할 정규화된 본문.

    detail 이 dict 이고 code/retryable 을 이미 담고 있으면 그 값을 우선 존중한다(핸들러가
    명시적으로 지정한 경우). 아니면 status 기준 기본값을 채운다.
    """
    if isinstance(detail, dict) and "detail" in detail:
        code = str(detail.get("code") or error_meta(status_code)[0])
        retryable = bool(detail.get("retryable", error_meta(status_code)[1]))
        return {"detail": detail.get("detail"), "code": code, "retryable": retryable}
    code, retryable = error_meta(status_code)
    return {"detail": detail, "code": code, "retryable": retryable}
