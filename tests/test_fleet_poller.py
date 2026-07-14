"""FleetPoller 배선(F2) 테스트 — env 게이트.

핵심 불변식: **설정이 없으면 기존과 똑같이 아무 일도 하지 않는다**(collector=None).
설정이 갖춰졌을 때만 FleetApiCollector 를 만든다.
"""
from __future__ import annotations

import os
import unittest
from contextlib import contextmanager

from mori_soc.collectors.fleet_api import FleetApiCollector
from mori_soc.pollers.fleet import FleetPoller

_FLEET_ENV = (
    "MORI_ENABLE_FLEET",
    "MORI_FLEET_API_URL",
    "MORI_FLEET_API_TOKEN",
    "MORI_FLEET_INCLUDE_SOFTWARE",
    "MORI_FLEET_INSECURE_TLS",
    "MORI_FLEET_HOST_LIMIT",
)


@contextmanager
def _env(**values: str):
    saved = {k: os.environ.get(k) for k in _FLEET_ENV}
    for k in _FLEET_ENV:
        os.environ.pop(k, None)
    os.environ.update(values)
    try:
        yield
    finally:
        for k in _FLEET_ENV:
            os.environ.pop(k, None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


class FleetPollerGateTest(unittest.TestCase):
    def test_source_name(self) -> None:
        self.assertEqual(FleetPoller().source_name, "fleet")

    def test_disabled_by_default(self) -> None:
        with _env():
            self.assertIsNone(FleetPoller().build_collector())

    def test_enabled_but_missing_url_or_token_is_none(self) -> None:
        with _env(MORI_ENABLE_FLEET="true", MORI_FLEET_API_TOKEN="t"):
            self.assertIsNone(FleetPoller().build_collector())      # URL 없음
        with _env(MORI_ENABLE_FLEET="true", MORI_FLEET_API_URL="http://fleet:1337"):
            self.assertIsNone(FleetPoller().build_collector())      # 토큰 없음

    def test_configured_but_disabled_is_none(self) -> None:
        with _env(MORI_ENABLE_FLEET="false", MORI_FLEET_API_URL="http://fleet:1337",
                  MORI_FLEET_API_TOKEN="t"):
            self.assertIsNone(FleetPoller().build_collector())

    def test_builds_collector_when_configured(self) -> None:
        with _env(MORI_ENABLE_FLEET="true", MORI_FLEET_API_URL="http://fleet:1337/",
                  MORI_FLEET_API_TOKEN="secret-token", MORI_FLEET_HOST_LIMIT="42"):
            collector = FleetPoller().build_collector()
        self.assertIsInstance(collector, FleetApiCollector)
        assert collector is not None
        self.assertEqual(collector.source_name, "fleet")
        self.assertEqual(collector._api_url, "http://fleet:1337")   # 끝 슬래시 정리
        self.assertEqual(collector._host_limit, 42)
        self.assertTrue(collector._include_software)
        self.assertTrue(collector._verify_tls)                      # 기본은 TLS 검증함

    def test_optional_flags(self) -> None:
        with _env(MORI_ENABLE_FLEET="true", MORI_FLEET_API_URL="https://fleet.corp",
                  MORI_FLEET_API_TOKEN="t", MORI_FLEET_INCLUDE_SOFTWARE="false",
                  MORI_FLEET_INSECURE_TLS="true"):
            collector = FleetPoller().build_collector()
        assert collector is not None
        self.assertFalse(collector._include_software)
        self.assertFalse(collector._verify_tls)

    def test_token_is_masked_in_logs(self) -> None:
        """토큰이 로그로 새지 않도록 시크릿 마스킹 목록에 등록돼 있어야 한다."""
        from mori_soc.api.server import _SECRET_ENV_NAMES

        self.assertIn("MORI_FLEET_API_TOKEN", _SECRET_ENV_NAMES)


if __name__ == "__main__":
    unittest.main()
