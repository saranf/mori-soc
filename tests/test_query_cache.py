"""쿼리 서비스 조회 캐시(F1) — 옵트인 TTL 캐시 동작 검증."""
from __future__ import annotations

import os
import unittest
from contextlib import contextmanager

from mori_soc.api.query_cache import make_service_getter


@contextmanager
def env(**kv):
    saved = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        yield
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class QueryCacheTest(unittest.TestCase):
    def _counting_factory(self):
        state = {"n": 0}
        def factory():
            state["n"] += 1
            return f"svc-{state['n']}"
        return factory, state

    def test_disabled_by_default_calls_every_time(self) -> None:
        factory, state = self._counting_factory()
        with env(MORI_QUERY_CACHE_TTL=None):
            get = make_service_getter(None, factory, lambda: "default")
            a, b = get(), get()
        self.assertNotEqual(a, b)          # 매번 새 스냅샷
        self.assertEqual(state["n"], 2)

    def test_ttl_caches_within_window(self) -> None:
        factory, state = self._counting_factory()
        t = {"v": 100.0}
        with env(MORI_QUERY_CACHE_TTL="2"):
            get = make_service_getter(None, factory, lambda: "d", clock=lambda: t["v"])
            a = get()                       # 계산(n=1)
            b = get()                       # 캐시(같은 시각)
            self.assertEqual(a, b)
            self.assertEqual(state["n"], 1)
            t["v"] = 103.0                  # TTL(2s) 경과
            c = get()                       # 재계산(n=2)
            self.assertNotEqual(a, c)
            self.assertEqual(state["n"], 2)

    def test_fixed_service_bypasses_cache(self) -> None:
        get = make_service_getter("FIXED", None, lambda: "d")
        self.assertEqual(get(), "FIXED")

    def test_no_factory_uses_default(self) -> None:
        get = make_service_getter(None, None, lambda: "DEFAULT")
        self.assertEqual(get(), "DEFAULT")

    def test_invalid_ttl_falls_back_to_disabled(self) -> None:
        factory, state = self._counting_factory()
        with env(MORI_QUERY_CACHE_TTL="not-a-number"):
            get = make_service_getter(None, factory, lambda: "d")
            get(); get()
        self.assertEqual(state["n"], 2)     # 파싱 실패 → 0(비활성)


if __name__ == "__main__":
    unittest.main()
