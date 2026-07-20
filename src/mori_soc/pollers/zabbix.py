"""Zabbix-specific poller service (서버 자산).

기준값 (docs/collection-standards.md):
  poll_interval   : 30 s  (서버는 30초 주기)
  stale_threshold : 300 s (5분 — 30초 주기이므로)
  max_retries     : 3
  retry_backoff   : 10 s
"""

from __future__ import annotations

import os

from mori_soc.collectors import ZabbixEventCollector
from mori_soc.collectors.base import BaseCollector

from .base import BasePollerService, _env_flag


class ZabbixPoller(BasePollerService):
    """Reads ``MORI_ZABBIX_*`` env-vars and creates a :class:`ZabbixEventCollector`.

    기준값은 docs/collection-standards.md 참고.
    환경변수 MORI_ZABBIX_INTERVAL_SECONDS / MORI_ZABBIX_STALE_SECONDS 로 재정의 가능.
    """

    # ── 수집 기준값 (collection-standards.md 기준) ─────────────────
    DEFAULT_POLL_INTERVAL: int = 30       # 서버: 30초 주기
    DEFAULT_STALE_THRESHOLD: int = 300    # 5분 (30초 주기 × 10)
    DEFAULT_MAX_RETRIES: int = 3
    DEFAULT_RETRY_BACKOFF: int = 10

    @property
    def source_name(self) -> str:
        return "zabbix"





    def build_collector(self) -> BaseCollector | None:
        if not _env_flag("MORI_ENABLE_ZABBIX", default=True):
            return None
        api_url = os.getenv("MORI_ZABBIX_API_URL", "").strip()
        token = os.getenv("MORI_ZABBIX_API_TOKEN", "").strip() or None
        username = os.getenv("MORI_ZABBIX_USER", "").strip() or None
        password = os.getenv("MORI_ZABBIX_PASSWORD", "").strip() or None
        if not api_url or not (token or (username and password)):
            return None
        return ZabbixEventCollector(
            api_url=api_url,
            username=username,
            password=password,
            token=token,
            request_timeout=int(os.getenv("MORI_ZABBIX_TIMEOUT_SECONDS", "10")),
            host_limit=int(os.getenv("MORI_ZABBIX_HOST_LIMIT", "500")),
            problem_limit=int(os.getenv("MORI_ZABBIX_PROBLEM_LIMIT", "500")),
        )


if __name__ == "__main__":
    ZabbixPoller().run_forever()

