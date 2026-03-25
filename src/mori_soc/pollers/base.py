"""Abstract base for source-specific poller services.

Each poller owns:
* env-var parsing → collector construction
* single-source ingestion cycle with SourceSync bookkeeping
* standalone ``run_forever`` entry point so it can run as a separate process
"""

from __future__ import annotations

import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

from mori_soc.collectors.base import BaseCollector
from mori_soc.models import SourceSync
from mori_soc.repositories import BaseRepository, InMemoryRepository, PostgresRepository
from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper, IngestionReport

logger = logging.getLogger("mori.poller")


@dataclass(slots=True)
class PollerCycleResult:
    """Outcome of a single poller cycle."""
    source: str
    status: str
    report: IngestionReport | None = None
    message: str | None = None


class BasePollerService(ABC):
    """Lifecycle wrapper around a single :class:`BaseCollector`.

    Subclasses must implement :meth:`build_collector` (reads env-vars and
    returns a ready-to-use collector) and :attr:`source_name`.
    """

    # ── abstract contract ──────────────────────────────────────────

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Unique source identifier (e.g. ``zabbix``, ``trivy``, ``ldap``)."""

    @abstractmethod
    def build_collector(self) -> BaseCollector | None:
        """Parse env-vars and return a collector, or *None* if disabled/misconfigured."""

    # ── public API ─────────────────────────────────────────────────

    def run_cycle(
        self,
        repository: BaseRepository,
        mapper: EnvelopeEntityMapper,
        *,
        started_at: datetime | None = None,
    ) -> PollerCycleResult:
        """Execute one collect → normalize → save cycle."""
        collector = self.build_collector()
        if collector is None:
            return PollerCycleResult(source=self.source_name, status="skipped", message="collector disabled or misconfigured")

        service = CollectorIngestionService(mapper, repository)
        cycle_started_at = started_at or datetime.now(tz=timezone.utc)
        existing_syncs = {s.source: s for s in repository.snapshot().source_syncs}
        previous_sync = existing_syncs.get(self.source_name)

        try:
            report = service.ingest_collector(collector)
            sync = SourceSync(
                source=self.source_name,  # type: ignore[arg-type]
                status="success",
                last_sync_at=cycle_started_at,
                last_success_at=cycle_started_at,
                last_error_at=previous_sync.last_error_at if previous_sync else None,
                message=f"ok: {report.records_collected} records",
                records_collected=report.records_collected,
                envelopes_normalized=report.envelopes_normalized,
                entities_saved=report.entities_saved,
            )
            repository.save(sync)
            logger.info("[%s] cycle OK — %d records, %d entities", self.source_name, report.records_collected, report.entities_saved)
            return PollerCycleResult(source=self.source_name, status="success", report=report, message=sync.message)
        except Exception as exc:
            message = _truncate(f"{type(exc).__name__}: {exc}")
            sync = SourceSync(
                source=self.source_name,  # type: ignore[arg-type]
                status="error",
                last_sync_at=cycle_started_at,
                last_success_at=previous_sync.last_success_at if previous_sync else None,
                last_error_at=cycle_started_at,
                message=message,
                records_collected=previous_sync.records_collected if previous_sync else 0,
                envelopes_normalized=previous_sync.envelopes_normalized if previous_sync else 0,
                entities_saved=previous_sync.entities_saved if previous_sync else 0,
            )
            repository.save(sync)
            logger.error("[%s] cycle FAILED — %s", self.source_name, message)
            return PollerCycleResult(source=self.source_name, status="error", message=message)

    def run_forever(self, *, repository: BaseRepository | None = None) -> None:
        """Standalone blocking loop — suitable for ``python -m mori_soc.pollers.zabbix``."""
        repo = repository or _repository_from_env()
        mapper = EnvelopeEntityMapper()
        poll_interval = max(1, int(os.getenv("MORI_WORKER_INTERVAL_SECONDS", "60")))
        run_once = _env_flag("MORI_WORKER_RUN_ONCE", default=False)

        logger.info("[%s] poller starting (interval=%ds, run_once=%s)", self.source_name, poll_interval, run_once)
        while True:
            self.run_cycle(repo, mapper)
            if run_once:
                return
            time.sleep(poll_interval)


# ── shared helpers ─────────────────────────────────────────────────

def _repository_from_env() -> BaseRepository:
    database_url = os.getenv("MORI_DATABASE_URL", "").strip()
    if database_url:
        return PostgresRepository(database_url)
    return InMemoryRepository()


def _env_flag(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _truncate(message: str, limit: int = 500) -> str:
    return message if len(message) <= limit else message[: limit - 3] + "..."

