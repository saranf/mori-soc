"""Zabbix-specific poller service."""

from __future__ import annotations

import os

from mori_soc.collectors import ZabbixEventCollector
from mori_soc.collectors.base import BaseCollector

from .base import BasePollerService, _env_flag


class ZabbixPoller(BasePollerService):
    """Reads ``MORI_ZABBIX_*`` env-vars and creates a :class:`ZabbixEventCollector`."""

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

