"""LDAP/AD directory-sync poller service.

기준값 (docs/collection-standards.md):
  poll_interval   : 3600 s (1h)
  stale_threshold : 28800 s (8h)
  max_retries     : 3
  retry_backoff   : 30 s
"""

from __future__ import annotations

import os

from mori_soc.collectors import LDAP3_AVAILABLE, LdapDirectoryCollector
from mori_soc.collectors.base import BaseCollector

from .base import BasePollerService, _env_flag


class LdapSyncPoller(BasePollerService):
    """Reads ``MORI_LDAP_SYNC_*`` env-vars and creates an :class:`LdapDirectoryCollector`.

    기준값은 docs/collection-standards.md 참고.
    """

    # ── 수집 기준값 (collection-standards.md 기준) ─────────────────
    _DEFAULT_POLL_INTERVAL: int = 3600    # 1h
    _DEFAULT_STALE_THRESHOLD: int = 28800  # 8h
    _DEFAULT_MAX_RETRIES: int = 3
    _DEFAULT_RETRY_BACKOFF: int = 30

    @property
    def source_name(self) -> str:
        return "ldap"

    @property
    def poll_interval_seconds(self) -> int:
        return max(1, int(os.getenv("MORI_LDAP_INTERVAL_SECONDS", str(self._DEFAULT_POLL_INTERVAL))))

    @property
    def stale_threshold_seconds(self) -> int:
        return max(1, int(os.getenv("MORI_LDAP_STALE_SECONDS", str(self._DEFAULT_STALE_THRESHOLD))))

    @property
    def max_retries(self) -> int:
        return max(0, int(os.getenv("MORI_LDAP_MAX_RETRIES", str(self._DEFAULT_MAX_RETRIES))))

    @property
    def retry_backoff_seconds(self) -> int:
        return max(0, int(os.getenv("MORI_LDAP_RETRY_BACKOFF_SECONDS", str(self._DEFAULT_RETRY_BACKOFF))))

    def build_collector(self) -> BaseCollector | None:
        if not _env_flag("MORI_ENABLE_LDAP_SYNC", default=False):
            return None
        if not LDAP3_AVAILABLE:
            return None
        ldap_url = os.getenv("MORI_LDAP_URL", "").strip()
        bind_dn = os.getenv("MORI_LDAP_BIND_DN", "").strip()
        bind_pw = os.getenv("MORI_LDAP_BIND_PASSWORD", "").strip()
        base_dn = os.getenv("MORI_LDAP_SYNC_BASE_DN", os.getenv("MORI_LDAP_BASE_DN", "")).strip()
        if not ldap_url or not bind_dn or not base_dn:
            return None
        return LdapDirectoryCollector(
            ldap_url=ldap_url,
            bind_dn=bind_dn,
            bind_pw=bind_pw,
            base_dn=base_dn,
            user_filter=os.getenv("MORI_LDAP_SYNC_USER_FILTER", "(objectClass=user)").strip(),
            group_filter=os.getenv("MORI_LDAP_SYNC_GROUP_FILTER", "(objectClass=group)").strip(),
            connect_timeout=int(os.getenv("MORI_LDAP_SYNC_TIMEOUT_SECONDS", "10")),
        )


if __name__ == "__main__":
    LdapSyncPoller().run_forever()

