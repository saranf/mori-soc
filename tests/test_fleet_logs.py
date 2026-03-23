import unittest
from datetime import datetime, timezone

from mori_soc.collectors.fleet_logs import FleetLogCollector


class FleetLogCollectorTests(unittest.TestCase):
    def test_collect_and_normalize_status_record(self) -> None:
        collector = FleetLogCollector()
        records = collector.collect_lines(
            [
                '{"hostIdentifier":"mbp-01","calendarTime":"Mon Mar 11 12:34:56 2024 UTC","severity":"3","message":"schedule executed"}'
            ],
            "status",
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.host_aliases, ["mbp-01"])

        normalized = list(collector.normalize(record))[0]
        self.assertEqual(normalized.entity_type, "host_observation")
        self.assertEqual(normalized.normalized["host_id"], "mbp-01")
        self.assertEqual(normalized.normalized["severity"], "high")

    def test_collect_and_normalize_result_record(self) -> None:
        collector = FleetLogCollector()
        records = collector.collect_lines(
            [
                '{"name":"system_info","hostIdentifier":"mbp-01","unixTime":1710160500,"columns":{"hostname":"mbp-01","uuid":"abc"}}'
            ],
            "result",
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.observed_at, datetime.fromtimestamp(1710160500, tz=timezone.utc))

        normalized = list(collector.normalize(record))[0]
        self.assertEqual(normalized.entity_type, "query_result")
        self.assertEqual(normalized.normalized["query_name"], "system_info")
        self.assertEqual(normalized.normalized["result_json"]["uuid"], "abc")


if __name__ == "__main__":
    unittest.main()