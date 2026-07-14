"""Fleet-specific poller service (PC/노트북 자산 — REST API 연결).

기준값 (docs/collection-standards.md):
  poll_interval   : 86400 s (하루 1회)
  stale_threshold : 864000 s (10일)
  max_retries     : 3
  retry_backoff   : 15 s
  참고            : 사용자가 새로고침 시 on-demand 수집 가능
"""

from __future__ import annotations

import os

from mori_soc.collectors.base import BaseCollector
from mori_soc.collectors.fleet_api import FleetApiCollector

from .base import BasePollerService, _env_flag


class FleetPoller(BasePollerService):
    """``MORI_FLEET_*`` env 를 읽어 :class:`FleetApiCollector` 를 만든다.

    ``MORI_ENABLE_FLEET=false`` 이거나 API URL/토큰이 없으면 *None* 을 반환한다
    (= 수집을 건너뛴다). 즉 **설정이 없으면 기존과 똑같이 아무 일도 하지 않는다.**

    기준값은 docs/collection-standards.md 참고.
    """

    # ── 수집 기준값 (collection-standards.md 기준) ─────────────────
    _DEFAULT_POLL_INTERVAL: int = 86400      # 하루 1회 (24h)
    _DEFAULT_STALE_THRESHOLD: int = 864000   # 10일
    _DEFAULT_MAX_RETRIES: int = 3
    _DEFAULT_RETRY_BACKOFF: int = 15

    @property
    def source_name(self) -> str:
        return "fleet"

    @property
    def poll_interval_seconds(self) -> int:
        return max(1, int(os.getenv("MORI_FLEET_INTERVAL_SECONDS", str(self._DEFAULT_POLL_INTERVAL))))

    @property
    def stale_threshold_seconds(self) -> int:
        return max(1, int(os.getenv("MORI_FLEET_STALE_SECONDS", str(self._DEFAULT_STALE_THRESHOLD))))

    @property
    def max_retries(self) -> int:
        return max(0, int(os.getenv("MORI_FLEET_MAX_RETRIES", str(self._DEFAULT_MAX_RETRIES))))

    @property
    def retry_backoff_seconds(self) -> int:
        return max(0, int(os.getenv("MORI_FLEET_RETRY_BACKOFF_SECONDS", str(self._DEFAULT_RETRY_BACKOFF))))

    def build_collector(self) -> BaseCollector | None:
        if not _env_flag("MORI_ENABLE_FLEET", default=False):
            return None
        api_url = os.getenv("MORI_FLEET_API_URL", "").strip()
        token = os.getenv("MORI_FLEET_API_TOKEN", "").strip()
        if not api_url or not token:
            return None
        return FleetApiCollector(
            api_url=api_url,
            token=token,
            request_timeout=int(os.getenv("MORI_FLEET_TIMEOUT_SECONDS", "10")),
            host_limit=int(os.getenv("MORI_FLEET_HOST_LIMIT", "500")),
            # 호스트별 상세를 추가 조회해 취약점을 뽑는다(호스트 수만큼 요청 증가).
            include_software=_env_flag("MORI_FLEET_INCLUDE_SOFTWARE", default=True),
            # 자체서명 인증서를 쓰는 사내 Fleet 은 명시적으로 검증을 끌 수 있다(옵트인).
            verify_tls=not _env_flag("MORI_FLEET_INSECURE_TLS", default=False),
        )


if __name__ == "__main__":
    FleetPoller().run_forever()

