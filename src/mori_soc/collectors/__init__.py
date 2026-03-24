"""Collector contracts for Fleet, Wazuh, Zabbix, Trivy, and host logs."""

from .base import BaseCollector, CollectorRecord, NormalizedEnvelope
from .fleet_logs import FleetLogCollector
from .trivy import TrivyCollector
from .wazuh_alerts import WazuhAlertCollector
from .zabbix_events import ZabbixEventCollector

__all__ = [
    "BaseCollector",
    "CollectorRecord",
    "NormalizedEnvelope",
    "FleetLogCollector",
    "TrivyCollector",
    "WazuhAlertCollector",
    "ZabbixEventCollector",
]