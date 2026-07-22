"""쿼리 서비스 조회 캐시(수정계획 F1) — 요청당 풀스냅샷 비용 완화.

프로덕션에서 ``get_query_service()`` 는 매 호출 ``repository.snapshot()`` 로 DB 전체를
메모리로 로드한다(대시보드 1회에 여러 번). 실규모서 지연/부하가 크다.

여기서는 **옵트인 짧은 TTL 캐시**를 제공한다. ``MORI_QUERY_CACHE_TTL`` 초 동안 동일
스냅샷을 재사용해 버스트(대시보드 렌더의 N회 호출)를 1회로 흡수한다.

안전(모리다움):
* **기본 0 = 비활성 = 현행 동작**(매 호출 스냅샷). 운영자가 명시적으로 켤 때만 캐시.
* 캐시 대상은 **읽기 스냅샷**뿐 — UI 쓰기(자산 소유자·트리아지 등)는 별도 인메모리
  스토어라 read-after-write 에 영향 없음. 최대 staleness = TTL(대시보드엔 무해).
* ``fixed service``(테스트/주입)면 캐시를 타지 않고 그대로 반환.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable, Optional


def make_service_getter(
    service: Optional[Any],
    service_factory: Optional[Callable[[], Any]],
    create_default: Callable[[], Any],
    *,
    ttl_env: str = "MORI_QUERY_CACHE_TTL",
    clock: Callable[[], float] = time.monotonic,
) -> Callable[[], Any]:
    """``get_query_service`` 로 쓸 콜러블을 만든다(옵트인 TTL 캐시 포함)."""
    cache: dict[str, Any] = {}
    lock = threading.Lock()

    def _ttl() -> float:
        try:
            return max(0.0, float(os.getenv(ttl_env, "0")))
        except (ValueError, TypeError):
            return 0.0

    def get() -> Any:
        if service is not None:          # 고정 주입(테스트 등) — 캐시 불필요
            return service
        if service_factory is None:      # 팩토리 없음 — 기본 생성
            return create_default()
        ttl = _ttl()
        if ttl <= 0:                     # 비활성(기본) — 현행: 매 호출 스냅샷
            return service_factory()
        now = clock()
        with lock:
            svc = cache.get("svc")
            if svc is not None and (now - float(cache.get("ts", 0.0))) < ttl:
                return svc
        # 락 밖에서 스냅샷(느린 작업) — 동시 요청이 각자 계산할 수 있으나(작은 herd) 안전.
        fresh = service_factory()
        with lock:
            cache["svc"] = fresh
            cache["ts"] = now
        return fresh

    return get


__all__ = ["make_service_getter"]
