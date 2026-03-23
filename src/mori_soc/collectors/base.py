from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


@dataclass(slots=True)
class CollectorRecord:
    source: str
    record_type: str
    observed_at: datetime
    external_id: str | None = None
    host_aliases: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedEnvelope:
    entity_type: str
    entity_id: str
    observed_at: datetime
    source: str
    raw_ref: str | None = None
    normalized: dict[str, Any] = field(default_factory=dict)
    raw_payload: dict[str, Any] = field(default_factory=dict)


class BaseCollector(ABC):
    """Base contract for source-specific collectors."""

    @property
    @abstractmethod
    def source_name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def collect(self) -> Iterable[CollectorRecord]:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, record: CollectorRecord) -> Iterable[NormalizedEnvelope]:
        raise NotImplementedError