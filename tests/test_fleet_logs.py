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

    def test_collect_and_normalize_nested_result_record(self) -> None:
        collector = FleetLogCollector()
        records = collector.collect_lines(
            [
                '{"name":"system_info","host_id":42,"decorations":{"hostname":"mbp-02","uuid":"fleet-uuid-2"},'
                '"unixTime":1710160500,"snapshot":[{"columns":{"hostname":"mbp-02","platform":"darwin","hardware_uuid":"hw-123"}}]}'
            ],
            "result",
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertIn("42", record.host_aliases)
        self.assertIn("fleet-uuid-2", record.host_aliases)
        self.assertIn("hw-123", record.host_aliases)

        normalized = list(collector.normalize(record))[0]
        self.assertEqual(normalized.normalized["hostname"], "mbp-02")
        self.assertEqual(normalized.normalized["platform"], "darwin")
        self.assertEqual(normalized.normalized["result_json"]["row_count"], 1)
        self.assertEqual(normalized.normalized["result_json"]["rows"][0]["hardware_uuid"], "hw-123")

    def test_collect_and_normalize_data_container_result_record(self) -> None:
        collector = FleetLogCollector()
        records = collector.collect_lines(
            [
                '{"name":"os_version","hostIdentifier":"mbp-03","unixTime":1710160500,'
                '"data":{"hostname":"mbp-03","platform":"darwin","host_uuid":"fleet-uuid-3"}}'
            ],
            "result",
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertIn("mbp-03", record.host_aliases)
        self.assertIn("fleet-uuid-3", record.host_aliases)

        normalized = list(collector.normalize(record))[0]
        self.assertEqual(normalized.normalized["hostname"], "mbp-03")
        self.assertEqual(normalized.normalized["platform"], "darwin")
        self.assertEqual(normalized.normalized["result_json"]["host_uuid"], "fleet-uuid-3")


if __name__ == "__main__":
    unittest.main()