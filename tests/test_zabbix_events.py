import json
import unittest
from unittest.mock import patch

from mori_soc.collectors import ZabbixEventCollector


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class ZabbixEventCollectorApiTests(unittest.TestCase):
    def test_collect_problem_lines_prefers_nested_host_aliases_over_problem_name(self) -> None:
        collector = ZabbixEventCollector(
            problem_lines=[
                '{"eventid":"12345","clock":"1710160500","hosts":[{"hostid":"10001","name":"mbp-01"}],'
                '"name":"Agent timeout","severity":"4","triggerid":"99001"}'
            ]
        )

        record = collector.collect_problem_lines(collector._problem_lines)[0]
        normalized = list(collector.normalize(record))[0]

        self.assertEqual(record.host_aliases[0], "mbp-01")
        self.assertNotIn("Agent timeout", record.host_aliases)
        self.assertEqual(normalized.normalized["host_id"], "mbp-01")

    def test_collect_api_fetches_problem_hosts_via_trigger_get(self) -> None:
        collector = ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="api-token")
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_api_call(method: str, params: dict[str, object], *, auth: str | None = None):
            self.assertEqual(auth, "api-token")
            calls.append((method, params))
            if method == "host.get":
                return [{"hostid": "20084", "host": "srv-01", "name": "srv-01", "status": "0", "interfaces": []}]
            if method == "problem.get":
                return [{"eventid": "30001", "clock": "1710160500", "name": "CPU load high", "severity": "4", "objectid": "99001"}]
            if method == "trigger.get":
                return [{"triggerid": "99001", "hosts": [{"hostid": "20084", "host": "srv-01", "name": "srv-01"}]}]
            raise AssertionError(f"unexpected method: {method}")

        with patch.object(collector, "_api_call", side_effect=fake_api_call):
            records = collector._collect_api()

        self.assertEqual([method for method, _ in calls], ["host.get", "problem.get", "trigger.get"])
        self.assertNotIn("selectHosts", calls[1][1])
        self.assertEqual(calls[2][1]["triggerids"], ["99001"])
        self.assertEqual(calls[2][1]["selectHosts"], ["hostid", "host", "name"])
        self.assertEqual(records[1].record_type, "problem")
        self.assertEqual(records[1].host_aliases[0], "srv-01")
        self.assertIn("srv-01", records[1].host_aliases)
        self.assertIn("20084", records[1].host_aliases)
        self.assertNotIn("CPU load high", records[1].host_aliases)
        self.assertEqual(records[1].payload["triggerid"], "99001")

    def test_api_call_uses_bearer_header_for_token_auth(self) -> None:
        collector = ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="api-token")
        captured_requests = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured_requests.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": [{"hostid": "20084"}], "id": 1})

        with patch("mori_soc.collectors.zabbix_events.request.urlopen", side_effect=fake_urlopen):
            result = collector._api_call("host.get", {"output": ["hostid"]}, auth="api-token")

        self.assertEqual(result, [{"hostid": "20084"}])
        payload = json.loads(captured_requests[0].data.decode("utf-8"))
        headers = {key.lower(): value for key, value in captured_requests[0].header_items()}
        self.assertNotIn("auth", payload)
        self.assertEqual(headers["authorization"], "Bearer api-token")

    def test_api_call_retries_with_header_when_body_auth_is_rejected(self) -> None:
        collector = ZabbixEventCollector(
            api_url="http://zabbix.example/api_jsonrpc.php",
            username="Admin",
            password="secret",
        )
        captured_requests = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured_requests.append(req)
            if len(captured_requests) == 1:
                return _FakeResponse(
                    {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Invalid request.",
                            "data": 'Invalid parameter "/": unexpected parameter "auth".',
                        },
                        "id": 1,
                    }
                )
            return _FakeResponse({"jsonrpc": "2.0", "result": [{"eventid": "12345"}], "id": 1})

        with patch("mori_soc.collectors.zabbix_events.request.urlopen", side_effect=fake_urlopen):
            result = collector._api_call("problem.get", {"output": ["eventid"]}, auth="session-token")

        self.assertEqual(result, [{"eventid": "12345"}])
        self.assertEqual(len(captured_requests), 2)

        first_payload = json.loads(captured_requests[0].data.decode("utf-8"))
        first_headers = {key.lower(): value for key, value in captured_requests[0].header_items()}
        self.assertEqual(first_payload["auth"], "session-token")
        self.assertNotIn("authorization", first_headers)

        second_payload = json.loads(captured_requests[1].data.decode("utf-8"))
        second_headers = {key.lower(): value for key, value in captured_requests[1].header_items()}
        self.assertNotIn("auth", second_payload)
        self.assertEqual(second_headers["authorization"], "Bearer session-token")


if __name__ == "__main__":
    unittest.main()