"""접속기록 소스 커버리지 대사 — 순수 집합 로직.

MORI다움: raw 로그 없이 자산 인벤토리 × 로그 소스만으로 '접속기록 미수집 서버'를
가려낸다(안전조치 제8조 / ISMS-P 2.9.4).
"""
from __future__ import annotations

import unittest

from mori_soc.api.payloads import access_record_coverage_sets


class AccessRecordCoverageTest(unittest.TestCase):
    def test_splits_covered_and_uncovered(self) -> None:
        servers = {"server-a", "server-b", "server-c"}
        log_sources = {"server-a", "server-c", "pc-x"}  # pc-x는 서버 아님 → 무시됨
        covered, uncovered = access_record_coverage_sets(servers, log_sources)
        self.assertEqual(covered, {"server-a", "server-c"})
        self.assertEqual(uncovered, {"server-b"})

    def test_all_uncovered_when_no_log_source(self) -> None:
        servers = {"server-a", "server-b"}
        covered, uncovered = access_record_coverage_sets(servers, set())
        self.assertEqual(covered, set())
        self.assertEqual(uncovered, {"server-a", "server-b"})

    def test_empty_servers(self) -> None:
        covered, uncovered = access_record_coverage_sets(set(), {"server-a"})
        self.assertEqual(covered, set())
        self.assertEqual(uncovered, set())


if __name__ == "__main__":
    unittest.main()
