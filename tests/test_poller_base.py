"""pollers/base.BasePollerService.run_cycle — skip·성공·재시도·error 경로(무테스트 해소)."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from mori_soc.pollers.base import BasePollerService, _env_flag
from mori_soc.repositories.memory import InMemoryRepository
from mori_soc.services.normalization import EnvelopeEntityMapper


class _StubCollector:
    source_name = "stub"

    def __init__(self, fail_times: int = 0) -> None:
        self._fail_times = fail_times
        self.calls = 0

    def collect(self):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise RuntimeError("boom")
        return []

    def normalize(self, record):  # pragma: no cover - collect returns []
        return []


class _StubPoller(BasePollerService):
    def __init__(self, collector, *, retries=0) -> None:
        self._collector = collector
        self._retries = retries

    @property
    def source_name(self) -> str:
        return "stub"

    @property
    def poll_interval_seconds(self) -> int:
        return 1

    @property
    def stale_threshold_seconds(self) -> int:
        return 10

    @property
    def max_retries(self) -> int:
        return self._retries

    @property
    def retry_backoff_seconds(self) -> int:
        return 0   # 테스트는 대기 없음

    def build_collector(self):
        return self._collector


class RunCycleTest(unittest.TestCase):
    def _repo(self):
        return InMemoryRepository()

    def test_skipped_when_no_collector(self) -> None:
        res = _StubPoller(None).run_cycle(self._repo(), EnvelopeEntityMapper())
        self.assertEqual(res.status, "skipped")

    def test_success_records_source_sync(self) -> None:
        repo = self._repo()
        res = _StubPoller(_StubCollector()).run_cycle(repo, EnvelopeEntityMapper())
        self.assertEqual(res.status, "success")
        syncs = {s.source: s for s in repo.snapshot().source_syncs}
        self.assertEqual(syncs["stub"].status, "success")

    def test_retries_then_succeeds(self) -> None:
        col = _StubCollector(fail_times=1)
        res = _StubPoller(col, retries=2).run_cycle(self._repo(), EnvelopeEntityMapper())
        self.assertEqual(res.status, "success")
        self.assertEqual(col.calls, 2)   # 1 실패 + 1 성공

    def test_all_retries_fail_records_error(self) -> None:
        repo = self._repo()
        col = _StubCollector(fail_times=5)
        res = _StubPoller(col, retries=1).run_cycle(repo, EnvelopeEntityMapper())
        self.assertEqual(res.status, "error")
        self.assertEqual(col.calls, 2)   # 첫 시도 + 1 재시도
        self.assertEqual({s.source: s for s in repo.snapshot().source_syncs}["stub"].status, "error")

    def test_env_flag(self) -> None:
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"X_FLAG": "true"}):
            self.assertTrue(_env_flag("X_FLAG", default=False))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("X_FLAG", None)
            self.assertFalse(_env_flag("X_FLAG", default=False))


if __name__ == "__main__":
    unittest.main()
