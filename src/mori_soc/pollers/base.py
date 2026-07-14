"""Abstract base for source-specific poller services.

Each poller owns:
* env-var parsing → collector construction
* single-source ingestion cycle with SourceSync bookkeeping + retry
* standalone ``run_forever`` entry point so it can run as a separate process

기준값은 docs/collection-standards.md 를 참고하세요.
각 서브클래스는 poll_interval_seconds / stale_threshold_seconds /
max_retries / retry_backoff_seconds 프로퍼티를 오버라이드해 기준값을 적용합니다.
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
from mori_soc.services import (
    CollectorIngestionService,
    EnvelopeEntityMapper,
    IngestionReport,
)

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

    각 소스의 기준값은 docs/collection-standards.md 에 정의되어 있습니다.
    서브클래스는 아래 프로퍼티를 오버라이드해 소스별 기준을 적용합니다.
    """

    # ── abstract contract ──────────────────────────────────────────

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Unique source identifier (e.g. ``zabbix``, ``trivy``, ``ldap``)."""

    @abstractmethod
    def build_collector(self) -> BaseCollector | None:
        """Parse env-vars and return a collector, or *None* if disabled/misconfigured."""

    # ── 수집 기준값 (docs/collection-standards.md 기준) ───────────
    # 서브클래스에서 오버라이드해 소스별 기준값 적용

    @property
    def poll_interval_seconds(self) -> int:
        """폴링 주기(초). 환경변수 MORI_{SOURCE}_INTERVAL_SECONDS 우선."""
        env_key = f"MORI_{self.source_name.upper()}_INTERVAL_SECONDS"
        fallback = int(os.getenv("MORI_WORKER_INTERVAL_SECONDS", "60"))
        return max(1, int(os.getenv(env_key, str(fallback))))

    @property
    def stale_threshold_seconds(self) -> int:
        """last_success_at 이 이 시간(초) 이상 경과하면 stale 처리."""
        env_key = f"MORI_{self.source_name.upper()}_STALE_SECONDS"
        return max(1, int(os.getenv(env_key, "600")))

    @property
    def max_retries(self) -> int:
        """한 사이클 내 최대 재시도 횟수."""
        env_key = f"MORI_{self.source_name.upper()}_MAX_RETRIES"
        return max(0, int(os.getenv(env_key, "3")))

    @property
    def retry_backoff_seconds(self) -> int:
        """재시도 사이 대기 시간(초)."""
        env_key = f"MORI_{self.source_name.upper()}_RETRY_BACKOFF_SECONDS"
        return max(0, int(os.getenv(env_key, "10")))

    def is_stale(self, sync: SourceSync | None) -> bool:
        """마지막 성공 sync 가 stale_threshold_seconds 이상 경과했는지 확인."""
        if sync is None or sync.last_success_at is None:
            return True
        elapsed = (datetime.now(tz=timezone.utc) - sync.last_success_at).total_seconds()
        return elapsed > self.stale_threshold_seconds

    # ── public API ─────────────────────────────────────────────────

    def post_ingest(self, collector: BaseCollector) -> None:
        """수집 성공 후 부가 저장 훅(선택). 기본은 아무것도 하지 않는다.

        정규화 엔티티(host/alert/vulnerability…) 가 아니라서 매퍼·BaseRepository 를
        타지 않는 데이터를 저장할 때 쓴다 — 예: Fleet 이 가져온 로컬 계정을
        StateRepository 의 ``host_accounts`` 에 저장.
        """
        return None

    def run_cycle(
        self,
        repository: BaseRepository,
        mapper: EnvelopeEntityMapper,
        *,
        started_at: datetime | None = None,
    ) -> PollerCycleResult:
        """Execute one collect → normalize → save cycle (with retry)."""
        collector = self.build_collector()
        if collector is None:
            return PollerCycleResult(source=self.source_name, status="skipped", message="collector disabled or misconfigured")

        service = CollectorIngestionService(mapper, repository)
        cycle_started_at = started_at or datetime.now(tz=timezone.utc)
        existing_syncs = {s.source: s for s in repository.snapshot().source_syncs}
        previous_sync = existing_syncs.get(self.source_name)

        last_exc: Exception | None = None
        attempts = self.max_retries + 1  # 1 첫 시도 + max_retries 재시도
        for attempt in range(1, attempts + 1):
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
                # 정규화 엔티티가 아닌 부가 데이터(예: Fleet 로컬 계정 → host_accounts)를
                # 저장할 기회. 실패해도 수집 사이클은 성공으로 둔다(부가 저장은 비차단).
                try:
                    self.post_ingest(collector)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("[%s] post_ingest 실패(비차단) — %s", self.source_name, exc)
                if attempt > 1:
                    logger.info("[%s] cycle OK (attempt %d/%d) — %d records, %d entities",
                                self.source_name, attempt, attempts, report.records_collected, report.entities_saved)
                else:
                    logger.info("[%s] cycle OK — %d records, %d entities",
                                self.source_name, report.records_collected, report.entities_saved)
                return PollerCycleResult(source=self.source_name, status="success", report=report, message=sync.message)
            except Exception as exc:
                last_exc = exc
                logger.warning("[%s] attempt %d/%d failed — %s", self.source_name, attempt, attempts, exc)
                if attempt < attempts:
                    time.sleep(self.retry_backoff_seconds)

        # 모든 재시도 실패
        message = _truncate(f"{type(last_exc).__name__}: {last_exc}")
        sync = SourceSync(
            source=self.source_name,  # type: ignore[arg-type]
            status="error",
            last_sync_at=cycle_started_at,
            last_success_at=previous_sync.last_success_at if previous_sync else None,
            last_error_at=cycle_started_at,
            message=f"failed after {attempts} attempt(s): {message}",
            records_collected=previous_sync.records_collected if previous_sync else 0,
            envelopes_normalized=previous_sync.envelopes_normalized if previous_sync else 0,
            entities_saved=previous_sync.entities_saved if previous_sync else 0,
        )
        repository.save(sync)
        logger.error("[%s] cycle FAILED after %d attempt(s) — %s", self.source_name, attempts, message)
        return PollerCycleResult(source=self.source_name, status="error", message=sync.message)

    def run_forever(self, *, repository: BaseRepository | None = None) -> None:
        """Standalone blocking loop — suitable for ``python -m mori_soc.pollers.zabbix``."""
        repo = repository or _repository_from_env()
        mapper = EnvelopeEntityMapper()
        run_once = _env_flag("MORI_WORKER_RUN_ONCE", default=False)
        interval = self.poll_interval_seconds

        logger.info("[%s] poller starting (interval=%ds, stale=%ds, max_retries=%d, run_once=%s)",
                    self.source_name, interval, self.stale_threshold_seconds, self.max_retries, run_once)
        while True:
            self.run_cycle(repo, mapper)
            if run_once:
                return
            time.sleep(interval)


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

