from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from mori_soc.models import Alert, Host, HostAlias, HostObservation, QueryResult, SourceSync, Vulnerability


@dataclass(slots=True)
class RepositorySnapshot:
    hosts: list[Host] = field(default_factory=list)
    host_aliases: list[HostAlias] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)
    observations: list[HostObservation] = field(default_factory=list)
    source_syncs: list[SourceSync] = field(default_factory=list)


class BaseRepository(ABC):
    """Persistence contract for normalized Phase 1 entities."""

    @abstractmethod
    def save(self, entity: object) -> None:
        raise NotImplementedError

    @abstractmethod
    def snapshot(self) -> RepositorySnapshot:
        raise NotImplementedError