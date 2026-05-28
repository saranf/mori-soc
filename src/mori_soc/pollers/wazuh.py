"""Wazuh-specific poller service (미연결 스텁).

기준값 (docs/collection-standards.md):
  poll_interval   : 60 s
  stale_threshold : 600 s (10분)
  max_retries     : 3
  retry_backoff   : 10 s
  연동 상태       : 🔲 미연결 (Phase 3 REST API 연동 예정)
"""

from __future__ import annotations

import os

from mori_soc.collectors.base import BaseCollector

from .base import BasePollerService


class WazuhPoller(BasePollerService):
    """Wazuh REST API 폴러 — 현재 미연결 스텁.

    ``MORI_ENABLE_WAZUH=true`` 설정 시에도 ``build_collector()`` 는 *None* 을
    반환합니다. Phase 3 에서 WazuhCollector 구현 후 연결 예정.

    기준값은 docs/collection-standards.md 참고.
    """

    # ── 수집 기준값 (collection-standards.md 기준) ─────────────────
    _DEFAULT_POLL_INTERVAL: int = 60
    _DEFAULT_STALE_THRESHOLD: int = 600    # 10분
    _DEFAULT_MAX_RETRIES: int = 3
    _DEFAULT_RETRY_BACKOFF: int = 10

    @property
    def source_name(self) -> str:
        return "wazuh"

    @property
    def poll_interval_seconds(self) -> int:
        return max(1, int(os.getenv("MORI_WAZUH_INTERVAL_SECONDS", str(self._DEFAULT_POLL_INTERVAL))))

    @property
    def stale_threshold_seconds(self) -> int:
        return max(1, int(os.getenv("MORI_WAZUH_STALE_SECONDS", str(self._DEFAULT_STALE_THRESHOLD))))

    @property
    def max_retries(self) -> int:
        return max(0, int(os.getenv("MORI_WAZUH_MAX_RETRIES", str(self._DEFAULT_MAX_RETRIES))))

    @property
    def retry_backoff_seconds(self) -> int:
        return max(0, int(os.getenv("MORI_WAZUH_RETRY_BACKOFF_SECONDS", str(self._DEFAULT_RETRY_BACKOFF))))

    def build_collector(self) -> BaseCollector | None:
        # Phase 3: WazuhCollector 구현 후 여기서 인스턴스 반환
        # if not _env_flag("MORI_ENABLE_WAZUH", default=False):
        #     return None
        return None


if __name__ == "__main__":
    WazuhPoller().run_forever()

