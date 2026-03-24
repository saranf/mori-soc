from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from mori_soc.collectors import BaseCollector, ZabbixEventCollector
from mori_soc.models import SourceSync
from mori_soc.repositories import BaseRepository, InMemoryRepository, PostgresRepository
from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper, IngestionReport


@dataclass(slots=True)
class WorkerCycleResult:
    source: str
    status: str
    report: IngestionReport | None = None
    message: str | None = None


def create_repository_from_env() -> BaseRepository:
    database_url = os.getenv("MORI_DATABASE_URL", "").strip()
    if database_url:
        return PostgresRepository(database_url)
    return InMemoryRepository()


def build_collectors_from_env() -> list[BaseCollector]:
    collectors: list[BaseCollector] = []
    if _env_flag("MORI_ENABLE_ZABBIX", default=True):
        api_url = os.getenv("MORI_ZABBIX_API_URL", "").strip()
        token = os.getenv("MORI_ZABBIX_API_TOKEN", "").strip() or None
        username = os.getenv("MORI_ZABBIX_USER", "").strip() or None
        password = os.getenv("MORI_ZABBIX_PASSWORD", "").strip() or None
        if api_url and (token or (username and password)):
            collectors.append(
                ZabbixEventCollector(
                    api_url=api_url,
                    username=username,
                    password=password,
                    token=token,
                    request_timeout=int(os.getenv("MORI_ZABBIX_TIMEOUT_SECONDS", "10")),
                    host_limit=int(os.getenv("MORI_ZABBIX_HOST_LIMIT", "500")),
                    problem_limit=int(os.getenv("MORI_ZABBIX_PROBLEM_LIMIT", "500")),
                )
            )
    return collectors


def run_ingestion_cycle(
    repository: BaseRepository,
    collectors: Iterable[BaseCollector],
    *,
    mapper: EnvelopeEntityMapper | None = None,
    started_at: datetime | None = None,
) -> list[WorkerCycleResult]:
    mapper = mapper or EnvelopeEntityMapper()
    service = CollectorIngestionService(mapper, repository)
    cycle_started_at = started_at or datetime.now(tz=timezone.utc)
    results: list[WorkerCycleResult] = []

    for collector in collectors:
        try:
            report = service.ingest_collector(collector)
            sync = SourceSync(
                source=collector.source_name,  # type: ignore[arg-type]
                status="success",
                last_sync_at=cycle_started_at,
                last_success_at=cycle_started_at,
                message=f"ok: {report.records_collected} records",
                records_collected=report.records_collected,
                envelopes_normalized=report.envelopes_normalized,
                entities_saved=report.entities_saved,
            )
            repository.save(sync)
            results.append(WorkerCycleResult(source=collector.source_name, status="success", report=report, message=sync.message))
        except Exception as exc:
            message = _truncate_message(f"{type(exc).__name__}: {exc}")
            repository.save(
                SourceSync(
                    source=collector.source_name,  # type: ignore[arg-type]
                    status="error",
                    last_sync_at=cycle_started_at,
                    last_error_at=cycle_started_at,
                    message=message,
                )
            )
            results.append(WorkerCycleResult(source=collector.source_name, status="error", message=message))
    return results


def run_forever() -> None:
    repository = create_repository_from_env()
    mapper = EnvelopeEntityMapper()
    collectors = build_collectors_from_env()
    if not collectors:
        raise RuntimeError("No MORI collectors are enabled. Set MORI_ZABBIX_* environment variables.")

    poll_interval = max(1, int(os.getenv("MORI_WORKER_INTERVAL_SECONDS", "60")))
    run_once = _env_flag("MORI_WORKER_RUN_ONCE", default=False)

    while True:
        run_ingestion_cycle(repository, collectors, mapper=mapper)
        if run_once:
            return
        time.sleep(poll_interval)


def _env_flag(name: str, *, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _truncate_message(message: str, limit: int = 500) -> str:
    return message if len(message) <= limit else message[: limit - 3] + "..."


if __name__ == "__main__":
    run_forever()