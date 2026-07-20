"""Trivy-specific poller service.

기준값 (docs/collection-standards.md):
  poll_interval   : 86400 s (24h) — batch 방식
  stale_threshold : 604800 s (7일)
  max_retries     : 2
  retry_backoff   : 30 s
"""

from __future__ import annotations

import glob
import os

from mori_soc.collectors import TrivyCollector
from mori_soc.collectors.base import BaseCollector

from .base import BasePollerService, _env_flag


def _split_csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


class TrivyPoller(BasePollerService):
    """Reads ``MORI_TRIVY_*`` env-vars and creates a :class:`TrivyCollector`.

    기준값은 docs/collection-standards.md 참고.
    """

    # ── 수집 기준값 (collection-standards.md 기준) ─────────────────
    DEFAULT_POLL_INTERVAL: int = 86400   # 24h (batch)
    DEFAULT_STALE_THRESHOLD: int = 604800  # 7일
    DEFAULT_MAX_RETRIES: int = 2
    DEFAULT_RETRY_BACKOFF: int = 30

    @property
    def source_name(self) -> str:
        return "trivy"





    def build_collector(self) -> BaseCollector | None:
        if not _env_flag("MORI_ENABLE_TRIVY", default=False):
            return None
        report_glob = os.getenv("MORI_TRIVY_REPORT_GLOB", "reports/trivy/*.json").strip() or "reports/trivy/*.json"
        return TrivyCollector(
            report_paths=sorted(glob.glob(report_glob)),
            host_aliases=_split_csv_env("MORI_TRIVY_HOST_ALIASES"),
            hostname=os.getenv("MORI_TRIVY_HOSTNAME", "").strip() or None,
        )


if __name__ == "__main__":
    TrivyPoller().run_forever()

