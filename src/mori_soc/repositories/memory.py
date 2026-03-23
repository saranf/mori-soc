from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from mori_soc.models import Alert, Host, HostAlias, HostObservation, QueryResult, Vulnerability

from .base import BaseRepository, RepositorySnapshot

if TYPE_CHECKING:
    from mori_soc.services.risk_score import RiskScoreCalculator


class InMemoryRepository(BaseRepository):
    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}
        self._host_aliases: dict[str, HostAlias] = {}
        self._alerts: dict[str, Alert] = {}
        self._vulnerabilities: dict[str, Vulnerability] = {}
        self._query_results: dict[str, QueryResult] = {}
        self._observations: dict[str, HostObservation] = {}

    def save(self, entity: object) -> None:
        if isinstance(entity, Host):
            self._save_host(entity)
            return
        if isinstance(entity, HostAlias):
            self._host_aliases[entity.alias_id] = entity
            return
        if isinstance(entity, Alert):
            self._alerts[entity.alert_id] = entity
            return
        if isinstance(entity, Vulnerability):
            self._vulnerabilities[entity.vuln_id] = entity
            return
        if isinstance(entity, QueryResult):
            self._query_results[entity.query_result_id] = entity
            return
        if isinstance(entity, HostObservation):
            self._observations[entity.observation_id] = entity
            return
        raise TypeError(f"Unsupported entity type: {type(entity)!r}")

    def snapshot(self) -> RepositorySnapshot:
        return RepositorySnapshot(
            hosts=list(self._hosts.values()),
            host_aliases=list(self._host_aliases.values()),
            alerts=list(self._alerts.values()),
            vulnerabilities=list(self._vulnerabilities.values()),
            query_results=list(self._query_results.values()),
            observations=list(self._observations.values()),
        )

    def apply_risk_scores(self, scores: dict[str, int]) -> None:
        """호스트별 위험 점수를 직접 갱신한다.

        RiskScoreCalculator.recalculate_hosts() 결과를 적용하거나
        scores dict를 직접 전달해서 host.risk_score를 업데이트한다.
        """
        for host_id, score in scores.items():
            if host_id in self._hosts:
                self._hosts[host_id] = replace(self._hosts[host_id], risk_score=score)

    def recalculate_risk_scores(self, calculator: RiskScoreCalculator) -> dict[str, int]:
        """RiskScoreCalculator를 사용해 모든 호스트 위험 점수를 재계산하고 저장한다."""
        snapshot = self.snapshot()
        updated = calculator.recalculate_hosts(snapshot.hosts, snapshot.alerts, snapshot.vulnerabilities)
        scores = {h.host_id: h.risk_score for h in updated}
        self.apply_risk_scores(scores)
        return scores

    def to_query_store(self):
        from mori_soc.services.query_service import InMemoryQueryStore

        snapshot = self.snapshot()
        return InMemoryQueryStore(
            hosts=snapshot.hosts,
            alerts=snapshot.alerts,
            vulnerabilities=snapshot.vulnerabilities,
            query_results=snapshot.query_results,
            observations=snapshot.observations,
            host_aliases=snapshot.host_aliases,
        )

    def _save_host(self, incoming: Host) -> None:
        existing = self._hosts.get(incoming.host_id)
        if existing is None:
            self._hosts[incoming.host_id] = incoming
            return
        merged = replace(
            existing,
            hostname=incoming.hostname or existing.hostname,
            platform=incoming.platform or existing.platform,
            primary_ip=incoming.primary_ip or existing.primary_ip,
            status=incoming.status if incoming.status != "unknown" else existing.status,
            risk_score=max(existing.risk_score, incoming.risk_score),
            first_seen_at=_min_dt(existing.first_seen_at, incoming.first_seen_at),
            last_seen_at=_max_dt(existing.last_seen_at, incoming.last_seen_at),
        )
        self._hosts[incoming.host_id] = merged


def _min_dt(left, right):
    if left is None:
        return right
    if right is None:
        return left
    return left if left <= right else right


def _max_dt(left, right):
    if left is None:
        return right
    if right is None:
        return left
    return left if left >= right else right