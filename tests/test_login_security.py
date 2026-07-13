"""로그인 브루트포스 잠금(#14) + 세션 idle/absolute 수명(#13) 검증."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class LoginLockoutTests(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def setUp(self) -> None:
        from mori_soc.api.routes.auth import _LOGIN_FAILURES
        _LOGIN_FAILURES.clear()   # 테스트 간 실패 카운터 격리

    def test_lockout_after_max_failures(self) -> None:
        # env 를 요청 시점까지 유지(잠금 판정은 요청 처리 중에 읽는다).
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1",
                                     "MORI_LOGIN_MAX_FAILURES": "3",
                                     "MORI_LOGIN_LOCKOUT_SECONDS": "900"}, clear=False):
            c = self._client()
            for _ in range(3):
                r = c.post("/auth/login", json={"username": "admin", "password": "wrong"})
                self.assertEqual(r.status_code, 401)
            # 임계 초과 → 잠금(429), 올바른 비번이어도 잠금 유지
            r = c.post("/auth/login", json={"username": "admin", "password": "1234"})
            self.assertEqual(r.status_code, 429)

    def test_success_clears_failures(self) -> None:
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1",
                                     "MORI_LOGIN_MAX_FAILURES": "3"}, clear=False):
            c = self._client()
            c.post("/auth/login", json={"username": "admin", "password": "wrong"})
            c.post("/auth/login", json={"username": "admin", "password": "wrong"})
            ok = c.post("/auth/login", json={"username": "admin", "password": "1234"})
            self.assertEqual(ok.status_code, 200, ok.text)   # 2회 실패 후 성공
            # 성공으로 카운터 리셋 → 다시 2회 실패해도 잠기지 않음
            c.post("/auth/login", json={"username": "admin", "password": "wrong"})
            r = c.post("/auth/login", json={"username": "admin", "password": "1234"})
            self.assertEqual(r.status_code, 200)


class SessionTtlUnitTests(unittest.TestCase):
    def test_session_expired_idle_and_absolute(self) -> None:
        from datetime import datetime, timedelta, timezone

        from mori_soc.api.auth import _session_expired
        now = datetime.now(tz=timezone.utc)
        now_ts = now.timestamp()
        fresh = {"created_at": now.isoformat(), "last_seen": now.isoformat()}
        self.assertFalse(_session_expired(fresh, now_ts))
        with patch.dict(os.environ, {"MORI_SESSION_IDLE_SECONDS": "60"}, clear=False):
            idle = {"created_at": now.isoformat(),
                    "last_seen": (now - timedelta(seconds=120)).isoformat()}
            self.assertTrue(_session_expired(idle, now_ts))    # idle 초과
        with patch.dict(os.environ, {"MORI_SESSION_ABSOLUTE_SECONDS": "60"}, clear=False):
            old = {"created_at": (now - timedelta(seconds=120)).isoformat(),
                   "last_seen": now.isoformat()}
            self.assertTrue(_session_expired(old, now_ts))     # absolute 초과


if __name__ == "__main__":
    unittest.main()
