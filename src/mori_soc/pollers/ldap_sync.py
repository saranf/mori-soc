"""LDAP/AD directory-sync poller service."""

from __future__ import annotations

import os

from mori_soc.collectors import LDAP3_AVAILABLE, LdapDirectoryCollector
from mori_soc.collectors.base import BaseCollector

from .base import BasePollerService, _env_flag


class LdapSyncPoller(BasePollerService):
    """Reads ``MORI_LDAP_SYNC_*`` env-vars and creates an :class:`LdapDirectoryCollector`."""

    @property
    def source_name(self) -> str:
        return "ldap"

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

