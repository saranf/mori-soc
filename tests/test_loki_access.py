"""Loki 접속기록 클라이언트 — 순수 파싱 로직 + degrade 경로.

라이브 Loki 없이 검증: query_range 응답 파싱(streams/matrix), env 미설정 시 degrade,
mocked HTTP 로 access_log_summary 의 보존범위(span_days) 산출.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.services import loki_client as lc


class ParseQueryRangeTest(unittest.TestCase):
    def test_streams_count_and_oldest(self) -> None:
        payload = {"data": {"resultType": "streams", "result": [
            {"stream": {"job": "authlog"}, "values": [
                ["1700000000000000000", "Accepted password for alice"],
                ["1699000000000000000", "Failed password for bob"],  # 더 오래됨
            ]},
        ]}}
        out = lc.parse_query_range(payload)
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["oldest_ns"], 1699000000000000000)

    def test_matrix_aggregation_sum(self) -> None:
        payload = {"data": {"resultType": "matrix", "result": [
            {"metric": {}, "values": [[1700000000, "12"], [1700086400, "8"]]},
        ]}}
        out = lc.parse_query_range(payload)
        self.assertEqual(out["count"], 20)

    def test_empty(self) -> None:
        out = lc.parse_query_range({"data": {"resultType": "streams", "result": []}})
        self.assertEqual(out, {"count": 0, "oldest_ns": None})


class AccessLogSummaryTest(unittest.TestCase):
    def test_degrade_when_base_unset(self) -> None:
        out = lc.access_log_summary(365, base_url="")
        self.assertFalse(out["available"])
        self.assertIsNone(out["span_days"])

    def test_live_span_days(self) -> None:
        now = datetime(2026, 7, 11, tzinfo=timezone.utc)
        # 최古 로그 = 2024-09-01 → 약 678일 보존
        oldest_ns = int(datetime(2024, 9, 1, tzinfo=timezone.utc).timestamp() * 1e9)
        streams = {"data": {"resultType": "streams", "result": [
            {"stream": {}, "values": [[str(oldest_ns), "Accepted password for alice"]]}]}}
        acc = {"data": {"resultType": "matrix", "result": [{"metric": {}, "values": [[1, "1200"]]}]}}
        fail = {"data": {"resultType": "matrix", "result": [{"metric": {}, "values": [[1, "80"]]}]}}
        with patch.object(lc, "_http_get_json", side_effect=[streams, acc, fail]):
            out = lc.access_log_summary(365, now=now, base_url="http://loki:3100",
                                        selector='{job="authlog"}')
        self.assertTrue(out["available"])
        self.assertEqual(out["oldest"], "2024-09-01")
        self.assertEqual(out["span_days"], 678)
        self.assertEqual(out["accepted"], 1200)
        self.assertEqual(out["failed"], 80)
        self.assertEqual(out["count"], 1280)

    def test_http_error_degrades(self) -> None:
        now = datetime(2026, 7, 11, tzinfo=timezone.utc)
        with patch.object(lc, "_http_get_json", side_effect=OSError("connrefused")):
            out = lc.access_log_summary(365, now=now, base_url="http://loki:3100")
        self.assertFalse(out["available"])


class ParseAccessEntriesTest(unittest.TestCase):
    def test_parses_login_sudo_and_sorts_newest_first(self) -> None:
        payload = {"data": {"resultType": "streams", "result": [
            {"stream": {"host": "web-01"}, "values": [
                ["1700000002000000000", "sshd[12]: Accepted password for alice from 10.0.0.5 port 51234 ssh2"],
                ["1700000001000000000", "sshd[13]: Failed password for invalid user bob from 1.2.3.4 port 5 ssh2"],
                ["1700000003000000000", "sudo:    alice : TTY=pts/0 ; PWD=/h ; USER=root ; COMMAND=/bin/ls"],
                ["1700000000000000000", "some unrelated line without auth"],
            ]},
        ]}}
        rows = lc.parse_access_entries(payload)
        self.assertEqual(len(rows), 3)  # unrelated line dropped
        self.assertEqual(rows[0]["event"], "sudo")          # newest ns first
        self.assertEqual(rows[0]["user"], "alice")
        self.assertEqual(rows[0]["host"], "web-01")
        login = next(r for r in rows if r["event"] == "login" and r["result"] == "success")
        self.assertEqual(login["user"], "alice")
        self.assertEqual(login["source_ip"], "10.0.0.5")
        fail = next(r for r in rows if r["result"] == "fail")
        self.assertEqual(fail["user"], "bob")

    def test_recent_degrades_without_base(self) -> None:
        out = lc.access_log_recent(10, base_url="")
        self.assertFalse(out["available"])
        self.assertEqual(out["entries"], [])


if __name__ == "__main__":
    unittest.main()
