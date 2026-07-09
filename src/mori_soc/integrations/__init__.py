"""External-system write-back integrations.

Unlike ``collectors`` / ``pollers`` (which *read* from external systems into
MORI), this package holds clients that *write* MORI decisions back out — e.g.
posting triage comments onto Zabbix problem events.

Write-back is opt-in and defaults to disabled; see :mod:`zabbix_writeback`.
"""

from .zabbix_writeback import (
    ZabbixWritebackClient,
    ZabbixWritebackConfig,
    build_zabbix_writeback_client,
)

__all__ = [
    "ZabbixWritebackClient",
    "ZabbixWritebackConfig",
    "build_zabbix_writeback_client",
]
