import unittest
from datetime import datetime, timezone

from mori_soc.collectors import WazuhAlertCollector


class WazuhAlertCollectorTests(unittest.TestCase):
    def test_collect_and_normalize_alert_record(self) -> None:
        collector = WazuhAlertCollector()
        records = collector.collect_lines(
            [
                '{"id":"1742800000.12345","timestamp":"2026-03-24T10:15:30Z",'
                '"agent":{"id":"001","name":"mbp-01","ip":"10.0.0.15"},'
                '"rule":{"id":"5710","level":13,"description":"Multiple authentication failures"},'
                '"full_log":"sshd: Failed password for invalid user"}'
            ]
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.external_id, "1742800000.12345")
        self.assertEqual(record.host_aliases, ["mbp-01", "001"])
        self.assertEqual(record.observed_at, datetime(2026, 3, 24, 10, 15, 30, tzinfo=timezone.utc))

        normalized = list(collector.normalize(record))[0]
        self.assertEqual(normalized.entity_type, "alert")
        self.assertEqual(normalized.source, "wazuh")
        self.assertEqual(normalized.raw_ref, "wazuh:1742800000.12345")
        self.assertEqual(normalized.normalized["host_id"], "mbp-01")
        self.assertEqual(normalized.normalized["hostname"], "mbp-01")
        self.assertEqual(normalized.normalized["primary_ip"], "10.0.0.15")
        self.assertEqual(normalized.normalized["severity"], "critical")
        self.assertEqual(normalized.normalized["original_severity"], "13")
        self.assertEqual(normalized.normalized["rule_id"], "5710")
        self.assertEqual(normalized.normalized["message"], "Multiple authentication failures")

    def test_collect_lines_uses_generated_id_and_full_log_fallback(self) -> None:
        collector = WazuhAlertCollector()
        records = collector.collect_lines(
            [
                '{"timestamp":"2026-03-24T10:16:00+0000",'
                '"agent":{"id":"002","name":"srv-01"},'
                '"rule":{"id":"100001","level":11},'
                '"full_log":"wazuh agent reported repeated scan errors"}'
            ]
        )

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.external_id, "wazuh-0")
        self.assertEqual(record.host_aliases, ["srv-01", "002"])

        normalized = list(collector.normalize(record))[0]
        self.assertEqual(normalized.normalized["severity"], "high")
        self.assertEqual(normalized.normalized["message"], "wazuh agent reported repeated scan errors")

    def test_normalize_severity_thresholds(self) -> None:
        collector = WazuhAlertCollector()

        cases = [
            (13, "critical"),
            (11, "high"),
            (8, "medium"),
            (4, "low"),
            (3, "info"),
            (None, "info"),
            ("bad", "info"),
        ]
        for level, expected in cases:
            with self.subTest(level=level):
                self.assertEqual(collector._normalize_severity(level), expected)


if __name__ == "__main__":
    unittest.main()