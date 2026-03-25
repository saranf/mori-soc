"""Collector contracts for Fleet, Wazuh, Zabbix, Trivy, LDAP/AD, and host logs."""

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope
from .fleet_logs import FleetLogCollector
from .ldap_directory import LDAP3_AVAILABLE, LdapDirectoryCollector
from .trivy import TrivyCollector
from .wazuh_alerts import WazuhAlertCollector
from .zabbix_events import ZabbixEventCollector

__all__ = [
    "BaseCollector",
    "CollectorRecord",
    "NormalizedEnvelope",
    "FleetLogCollector",
    "LdapDirectoryCollector",
    "LDAP3_AVAILABLE",
    "TrivyCollector",
    "WazuhAlertCollector",
    "ZabbixEventCollector",
]