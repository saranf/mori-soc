"""Data models aligned with Phase 1 schema design."""

from .entities import Alert, Host, HostAlias, HostObservation, QueryResult, Vulnerability

__all__ = ["Host", "HostAlias", "Alert", "Vulnerability", "QueryResult", "HostObservation"]