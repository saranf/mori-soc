"""Unified MORI worker — delegates to source-specific :mod:`pollers`.

Backward-compatible: ``python -m mori_soc.worker`` still works.
Individual pollers can also be run standalone::

    python -m mori_soc.pollers.zabbix
    python -m mori_soc.pollers.trivy
    python -m mori_soc.pollers.ldap_sync
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Iterable

from mori_soc.collectors.base import BaseCollector
from mori_soc.models import SourceSync
from mori_soc.pollers.base import (
    BasePollerService,
    PollerCycleResult,
    _env_flag,
    _repository_from_env,
)
from mori_soc.pollers.fleet import FleetPoller
from mori_soc.pollers.ldap_sync import LdapSyncPoller
from mori_soc.pollers.trivy import TrivyPoller
from mori_soc.pollers.wazuh import WazuhPoller
from mori_soc.pollers.zabbix import ZabbixPoller
from mori_soc.repositories import BaseRepository
from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper

logger = logging.getLogger("mori.worker")

# ── backward-compatible aliases ────────────────────────────────────

# Re-export so callers that import ``from mori_soc.worker import ...``
# still work without changes.
WorkerCycleResult = PollerCycleResult
create_repository_from_env = _repository_from_env

# ── registry of all known pollers ──────────────────────────────────

ALL_POLLERS: list[type[BasePollerService]] = [
    ZabbixPoller,
    FleetPoller,
    WazuhPoller,
    TrivyPoller,
    LdapSyncPoller,
]


def build_pollers() -> list[BasePollerService]:
    """Return an instance of every registered poller."""
    return [cls() for cls in ALL_POLLERS]


def build_collectors_from_env() -> list[BaseCollector]:
    """Legacy helper — returns a flat list of collectors from all pollers.

    This is kept for backward compatibility with test code that calls
    ``run_ingestion_cycle(repo, collectors, ...)``.
    """
    collectors: list[BaseCollector] = []
    for poller in build_pollers():
        collector = poller.build_collector()
        if collector is not None:
            collectors.append(collector)
    return collectors


# ── legacy run_ingestion_cycle (delegates to poller run_cycle) ─────

def run_ingestion_cycle(
    repository: BaseRepository,
    collectors: Iterable[BaseCollector],
    *,
    mapper: EnvelopeEntityMapper | None = None,
    started_at: datetime | None = None,
) -> list[PollerCycleResult]:
    """Backward-compatible ingestion cycle.

    Kept for callers (tests, scripts) that still pass raw collectors.
    New code should use ``poller.run_cycle(...)`` directly.
    """
    mapper = mapper or EnvelopeEntityMapper()
    service = CollectorIngestionService(mapper, repository)
    cycle_started_at = started_at or datetime.now(tz=timezone.utc)
    existing_syncs = {item.source: item for item in repository.source_syncs()}
    results: list[PollerCycleResult] = []

    for collector in collectors:
        previous_sync = existing_syncs.get(collector.source_name)
        try:
            report = service.ingest_collector(collector)
            sync = SourceSync(
                source=collector.source_name,  # type: ignore[arg-type]
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
            existing_syncs[collector.source_name] = sync
            results.append(PollerCycleResult(source=collector.source_name, status="success", report=report, message=sync.message))
        except Exception as exc:
            message = _truncate_message(f"{type(exc).__name__}: {exc}")
            sync = SourceSync(
                source=collector.source_name,  # type: ignore[arg-type]
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
            existing_syncs[collector.source_name] = sync
            results.append(PollerCycleResult(source=collector.source_name, status="error", message=message))
    return results


# ── main loop ──────────────────────────────────────────────────────

# 리더 선출(#26) — 여러 worker 인스턴스가 떠도 한 번에 하나만 폴링하도록 PostgreSQL
# advisory lock 을 잡는다(중복 poll·evidence·race 방지). 리더가 죽으면 세션이 끊겨 락이
# 풀리고 standby 가 인수한다. DB 미설정(인메모리)·명시 비활성이면 락 없이 그대로 폴링.
_LEADER_LOCK_KEY = 0x4D4F5249  # "MORI"


def _worker_singleton_enabled() -> bool:
    import os
    if os.environ.get("MORI_WORKER_SINGLETON", "").strip().lower() in ("0", "false", "no", "off"):
        return False
    return bool(os.environ.get("MORI_DATABASE_URL", "").strip())


def _try_acquire_leader():
    """리더 락 획득 시도. 성공하면 (락을 쥔) 연결을 반환, 실패(다른 리더)면 None."""
    import os

    dsn = os.environ.get("MORI_DATABASE_URL", "").strip()
    try:
        import psycopg
    except Exception:
        return None
    try:
        conn = psycopg.connect(dsn)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s)", (_LEADER_LOCK_KEY,))
            got = bool(cur.fetchone()[0])
        if got:
            return conn
        conn.close()
        return None
    except Exception as exc:  # noqa: BLE001 — 락 인프라 문제로 폴링을 막지 않는다(가용성 우선)
        logger.warning("leader lock 시도 실패(락 없이 진행): %s", exc)
        raise _LockUnavailable() from exc


class _LockUnavailable(Exception):
    """advisory lock 을 쓸 수 없음(폴링은 계속)."""


def run_forever() -> None:
    """Run all enabled pollers in a single loop (unified worker mode).

    각 폴러의 ``poll_interval_seconds`` 를 존중해 소스별 다음 실행 시각을
    관리합니다.  글로벌 루프는 1 초 간격으로 돌며, 각 폴러의 예정 시각이
    도래하면 해당 폴러만 실행합니다. 여러 인스턴스가 떠도 리더 하나만 폴링합니다(#26).
    """
    repository = _repository_from_env()
    mapper = EnvelopeEntityMapper()
    pollers = build_pollers()

    # Filter to pollers that can actually produce a collector
    active = [p for p in pollers if p.build_collector() is not None]
    if not active:
        raise RuntimeError(
            "No MORI pollers are enabled. "
            "Set MORI_ENABLE_ZABBIX, MORI_ENABLE_TRIVY, or MORI_ENABLE_LDAP_SYNC environment variables."
        )

    run_once = _env_flag("MORI_WORKER_RUN_ONCE", default=False)

    # 소스별 다음 실행 시각 스케줄러 (첫 실행은 즉시)
    next_run: dict[str, float] = {p.source_name: 0.0 for p in active}

    source_info = ", ".join(f"{p.source_name}({p.poll_interval_seconds}s)" for p in active)
    logger.info("Unified worker starting — pollers=[%s]", source_info)

    lock_needed = _worker_singleton_enabled()
    leader_conn = None  # 락을 쥔 연결(프로세스 수명 동안 유지)

    while True:
        if lock_needed and leader_conn is None:
            try:
                leader_conn = _try_acquire_leader()
            except _LockUnavailable:
                lock_needed = False  # 락 인프라 불가 → 락 없이 폴링(가용성 우선)
            else:
                if leader_conn is None:
                    logger.info("worker standby — 다른 인스턴스가 리더. 5초 후 재시도.")
                    if run_once:
                        return
                    time.sleep(5)
                    continue
                logger.info("이 worker 가 리더 — 폴링 시작.")

        now = time.monotonic()
        for poller in active:
            if now >= next_run[poller.source_name]:
                poller.run_cycle(repository, mapper)
                next_run[poller.source_name] = time.monotonic() + poller.poll_interval_seconds
        if run_once:
            return
        time.sleep(1)


def _truncate_message(message: str, limit: int = 500) -> str:
    return message if len(message) <= limit else message[: limit - 3] + "..."


if __name__ == "__main__":
    run_forever()