from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from mori_soc.models import (
    AccountObservation,
    Alert,
    ControlCheckResult,
    DirectoryAccount,
    GroupMembership,
    Host,
    HostAlias,
    HostObservation,
    PrivilegeBinding,
    QueryResult,
    SourceSync,
    Vulnerability,
)


@dataclass(slots=True)
class RepositorySnapshot:
    hosts: list[Host] = field(default_factory=list)
    host_aliases: list[HostAlias] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)
    observations: list[HostObservation] = field(default_factory=list)
    source_syncs: list[SourceSync] = field(default_factory=list)
    # Phase 2
    control_checks: list[ControlCheckResult] = field(default_factory=list)
    directory_accounts: list[DirectoryAccount] = field(default_factory=list)
    privilege_bindings: list[PrivilegeBinding] = field(default_factory=list)
    group_memberships: list[GroupMembership] = field(default_factory=list)
    account_observations: list[AccountObservation] = field(default_factory=list)


class BaseRepository(ABC):
    """Persistence contract for normalized Phase 1 entities."""

    @abstractmethod
    def save(self, entity: object) -> None:
        raise NotImplementedError

    @abstractmethod
    def snapshot(self) -> RepositorySnapshot:
        raise NotImplementedError

    def source_syncs(self) -> "list[Any]":
        """폴 사이클용 경량 접근자(M3) — source_syncs 만 필요할 때 전체 snapshot() 을 피한다.

        기본은 snapshot() 폴백(호환). Postgres 등은 해당 테이블만 조회하도록 오버라이드.
        """
        return list(self.snapshot().source_syncs)