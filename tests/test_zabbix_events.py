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

    def test_severity_mapping_zabbix_to_normalized(self) -> None:
        # Zabbix priority 0~5 → MORI severity 매핑 (0/1=info, 2=low, 3=medium, 4=high, 5=critical)
        expected = {"0": "info", "1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
        for zsev, want in expected.items():
            collector = ZabbixEventCollector(
                problem_lines=['{"eventid":"1","clock":"1710160500","name":"P","severity":"%s","triggerid":"9"}' % zsev]
            )
            record = collector.collect_problem_lines(collector._problem_lines)[0]
            normalized = list(collector.normalize(record))[0]
            self.assertEqual(normalized.normalized["severity"], want, f"zabbix severity {zsev}")

    def test_active_problem_has_no_resolved_at(self) -> None:
        collector = ZabbixEventCollector(
            problem_lines=['{"eventid":"1","clock":"1710160500","name":"CPU high","severity":"4",'
                           '"triggerid":"9","r_eventid":"0"}']
        )
        record = collector.collect_problem_lines(collector._problem_lines)[0]
        normalized = list(collector.normalize(record))[0]
        self.assertIsNone(normalized.normalized["resolved_at"])

    def test_resolved_problem_sets_resolved_at_from_r_clock(self) -> None:
        from datetime import datetime, timezone
        collector = ZabbixEventCollector(
            problem_lines=['{"eventid":"1","clock":"1710160500","name":"CPU high","severity":"4",'
                           '"triggerid":"9","r_eventid":"555","r_clock":"1710164100"}']
        )
        record = collector.collect_problem_lines(collector._problem_lines)[0]
        normalized = list(collector.normalize(record))[0]
        resolved = normalized.normalized["resolved_at"]
        self.assertEqual(resolved, datetime.fromtimestamp(1710164100, tz=timezone.utc))
        # 매퍼를 통과하면 Alert.resolved_at 로 전달된다
        from mori_soc.services.normalization import EnvelopeEntityMapper
        entities = EnvelopeEntityMapper().map_envelope(normalized)
        alert = [e for e in entities if e.__class__.__name__ == "Alert"][0]
        self.assertEqual(alert.resolved_at, resolved)

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

class ZabbixSharedIpIdentityTests(unittest.TestCase):
    """공유 IP(컨테이너·NAT)가 서로 다른 호스트를 한 host_id 로 병합시키던 회귀 방지."""

    def _collector(self):
        return ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="t")

    def test_shared_interface_ip_is_not_used_as_identity_alias(self) -> None:
        collector = self._collector()
        # sim-app-01/02/03 이 전부 172.19.0.1 을 공유 (도커 게이트웨이)
        hosts = [
            {"hostid": "101", "host": "sim-app-01", "name": "sim-app-01",
             "interfaces": [{"ip": "172.19.0.1"}]},
            {"hostid": "102", "host": "sim-app-02", "name": "sim-app-02",
             "interfaces": [{"ip": "172.19.0.1"}]},
            {"hostid": "103", "host": "sim-app-03", "name": "sim-app-03",
             "interfaces": [{"ip": "172.19.0.1"}]},
        ]

        def fake_api_call(method, params, *, auth=None):
            if method == "host.get":
                return hosts
            if method == "problem.get":
                return []
            raise AssertionError(method)

        with patch.object(collector, "_api_call", side_effect=fake_api_call):
            records = collector._collect_api()

        host_records = [r for r in records if r.record_type == "host"]
        self.assertEqual(len(host_records), 3)
        for record in host_records:
            self.assertNotIn("172.19.0.1", record.host_aliases,
                             "공유 IP 는 신원 별칭에서 제외돼야 한다(병합 방지)")
        # 별칭이 서로 겹치지 않아야 세 호스트가 각각 별개로 남는다
        alias_sets = [set(r.host_aliases) for r in host_records]
        self.assertFalse(alias_sets[0] & alias_sets[1])
        self.assertFalse(alias_sets[1] & alias_sets[2])

    def test_unique_interface_ip_is_still_an_identity_alias(self) -> None:
        collector = self._collector()
        hosts = [
            {"hostid": "201", "host": "srv-a", "name": "srv-a", "interfaces": [{"ip": "10.0.0.1"}]},
            {"hostid": "202", "host": "srv-b", "name": "srv-b", "interfaces": [{"ip": "10.0.0.2"}]},
        ]

        def fake_api_call(method, params, *, auth=None):
            if method == "host.get":
                return hosts
            if method == "problem.get":
                return []
            raise AssertionError(method)

        with patch.object(collector, "_api_call", side_effect=fake_api_call):
            records = collector._collect_api()

        host_records = [r for r in records if r.record_type == "host"]
        self.assertIn("10.0.0.1", host_records[0].host_aliases)
        self.assertIn("10.0.0.2", host_records[1].host_aliases)
