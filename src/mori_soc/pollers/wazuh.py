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
    DEFAULT_POLL_INTERVAL: int = 60
    DEFAULT_STALE_THRESHOLD: int = 600    # 10분
    DEFAULT_MAX_RETRIES: int = 3
    DEFAULT_RETRY_BACKOFF: int = 10

    @property
    def source_name(self) -> str:
        return "wazuh"





    def build_collector(self) -> BaseCollector | None:
        # Phase 3: WazuhCollector 구현 후 여기서 인스턴스 반환
        # if not _env_flag("MORI_ENABLE_WAZUH", default=False):
        #     return None
        return None


if __name__ == "__main__":
    WazuhPoller().run_forever()

