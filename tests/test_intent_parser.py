import unittest

from mori_soc.services.intent_parser import NaturalLanguageQueryParser


class NaturalLanguageQueryParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = NaturalLanguageQueryParser()

    def test_offline_hosts_question_maps_to_offline_intent(self) -> None:
        result = self.parser.interpret("오프라인 호스트 보여줘")
        self.assertEqual(result.request.intent, "offline_hosts")
        self.assertEqual(result.request.scope.time_range, "1h")

    def test_timeline_question_extracts_host_id(self) -> None:
        result = self.parser.interpret("host-1 타임라인 보여줘")
        self.assertEqual(result.request.intent, "host_timeline")
        self.assertEqual(result.request.scope.host_id, "host-1")

    def test_wazuh_alert_summary_extracts_source_and_severity(self) -> None:
        result = self.parser.interpret("최근 24시간 wazuh high alert 요약")
        self.assertEqual(result.request.intent, "alert_summary")
        self.assertEqual(result.request.scope.source, "wazuh")
        self.assertEqual(result.request.scope.severity, "high")

    def test_top_vulnerability_question_extracts_limit(self) -> None:
        result = self.parser.interpret("취약점 많은 호스트 top 5")
        self.assertEqual(result.request.intent, "top_vulnerable_hosts")
        self.assertEqual(result.request.filters["limit"], 5)

    def test_empty_question_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.parser.interpret("   ")