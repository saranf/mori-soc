from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class QueryScope:
    time_range: str = "24h"
    host_id: str | None = None
    hostname: str | None = None
    severity: str | None = None
    source: str | None = None


@dataclass(slots=True)
class QueryRequest:
    intent: str
    scope: QueryScope = field(default_factory=QueryScope)
    filters: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceRef:
    source: str
    record_id: str | None = None
    raw_ref: str | None = None
    summary: str | None = None


@dataclass(slots=True)
class QueryResponse:
    summary: str
    filters: dict[str, Any]
    evidence: list[EvidenceRef]
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.setdefault("meta", {})["generated_at"] = datetime.utcnow().isoformat() + "Z"
        return payload