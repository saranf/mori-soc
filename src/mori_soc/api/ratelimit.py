"""경량 IP 기반 rate limiting(#12) — 남용 가능 엔드포인트 보호.

단일 인스턴스 인메모리 슬라이딩 윈도우(세션·로그인잠금과 동일 전제). 다중 인스턴스는
공유 저장소(Redis 등)가 필요 — 백로그. 기본값은 정상 사용/CI 를 막지 않을 만큼 넉넉하고,
대량 남용(수백 req/분)만 429 로 끊는다. env 로 조정·비활성 가능.

  MORI_RATELIMIT_ENABLED         기본 true. false 면 완전 비활성.
  MORI_RATELIMIT_WINDOW_SECONDS  윈도우 초(기본 60)
  MORI_RATELIMIT_INGEST_MAX      /ingest/* 창당 IP 허용(기본 300)
  MORI_RATELIMIT_LOGIN_MAX       /auth/login 창당 IP 허용(기본 60)
"""
from __future__ import annotations

import os
import time
from typing import Any

# path prefix -> (env 이름, 기본 상한)
_LIMITED = (
    ("/ingest/", "MORI_RATELIMIT_INGEST_MAX", 300),
    ("/auth/login", "MORI_RATELIMIT_LOGIN_MAX", 60),
)


def _enabled() -> bool:
    return os.environ.get("MORI_RATELIMIT_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")


def _window() -> int:
    try:
        return max(1, int(os.environ.get("MORI_RATELIMIT_WINDOW_SECONDS", "60")))
    except ValueError:
        return 60


def _limit_for(path: str) -> tuple[str, int] | None:
    for prefix, env_name, default in _LIMITED:
        if path.startswith(prefix):
            try:
                cap = max(1, int(os.environ.get(env_name, str(default))))
            except ValueError:
                cap = default
            return prefix, cap
    return None


def _client_ip(request: Any) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    client = getattr(request, "client", None)
    return getattr(client, "host", "?") or "?"


def build_rate_limit_middleware():
    """(prefix, ip) 별 슬라이딩 윈도우 카운터로 초과 시 429 를 반환하는 미들웨어."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response as _Response

    hits: dict[str, list[float]] = {}

    class _RateLimitMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):  # type: ignore[override]
            if not _enabled():
                return await call_next(request)
            limit = _limit_for(request.url.path)
            if limit is None:
                return await call_next(request)
            prefix, cap = limit
            window = _window()
            now = time.time()
            key = f"{prefix}|{_client_ip(request)}"
            recent = [t for t in hits.get(key, []) if now - t < window]
            if len(recent) >= cap:
                recent.append(now)
                hits[key] = recent
                retry = int(window - (now - min(recent))) + 1
                return _Response(
                    status_code=429,
                    content='{"detail":"rate limit exceeded"}',
                    media_type="application/json",
                    headers={"Retry-After": str(max(1, retry))},
                )
            recent.append(now)
            hits[key] = recent
            return await call_next(request)

    return _RateLimitMiddleware
