import json
import unittest
from unittest.mock import patch

from mori_soc.integrations.zabbix_transport import ZabbixApiError, ZabbixTransport
from mori_soc.integrations.zabbix_writeback import (
    ACK_ACTION_ADD_MESSAGE,
    ZabbixWritebackClient,
    ZabbixWritebackConfig,
    build_zabbix_writeback_client,
)


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def _transport() -> ZabbixTransport:
    return ZabbixTransport("http://zabbix.example/api_jsonrpc.php", token="api-token")


class ZabbixWritebackClientTests(unittest.TestCase):
    def test_add_comment_calls_event_acknowledge_with_message_action(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {"eventids": ["12345"]}, "id": 1})

        client = ZabbixWritebackClient(_transport(), prefix="[MORI]")
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            result = client.add_comment("12345", "DB backup 때문에 CPU spike")

        self.assertEqual(result, {"eventids": ["12345"]})
        payload = json.loads(captured[0].data.decode("utf-8"))
        self.assertEqual(payload["method"], "event.acknowledge")
        self.assertEqual(payload["params"]["eventids"], "12345")
        self.assertEqual(payload["params"]["action"], ACK_ACTION_ADD_MESSAGE)
        self.assertEqual(payload["params"]["message"], "[MORI] DB backup 때문에 CPU spike")
        # token auth → Bearer header, no body auth param
        headers = {k.lower(): v for k, v in captured[0].header_items()}
        self.assertEqual(headers["authorization"], "Bearer api-token")
        self.assertNotIn("auth", payload)

    def test_prefix_not_duplicated_when_already_present(self) -> None:
        client = ZabbixWritebackClient(_transport(), prefix="[MORI]")
        self.assertEqual(client._decorate("[MORI] already"), "[MORI] already")
        self.assertEqual(client._decorate("plain"), "[MORI] plain")

    def test_blank_event_id_rejected(self) -> None:
        client = ZabbixWritebackClient(_transport())
        with self.assertRaises(ZabbixApiError):
            client.add_comment("  ", "note")

    def test_api_error_surfaces_for_audit(self) -> None:
        def fake_urlopen(req, timeout=0):
            del timeout
            return _FakeResponse(
                {"jsonrpc": "2.0", "error": {"code": -32500, "message": "No permissions", "data": ""}, "id": 1}
            )

        client = ZabbixWritebackClient(_transport())
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            with self.assertRaises(ZabbixApiError):
                client.add_comment("12345", "note")


class ZabbixWritebackConfigTests(unittest.TestCase):
    def test_disabled_by_default(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            cfg = ZabbixWritebackConfig.from_env()
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.is_operational)
        self.assertIsNone(build_zabbix_writeback_client(cfg))

    def test_enabled_needs_credentials(self) -> None:
        env = {"MORI_ZABBIX_WRITEBACK_ENABLED": "true"}
        with patch.dict("os.environ", env, clear=True):
            cfg = ZabbixWritebackConfig.from_env()
        self.assertTrue(cfg.enabled)
        self.assertFalse(cfg.has_credentials)
        self.assertFalse(cfg.is_operational)
        self.assertIsNone(build_zabbix_writeback_client(cfg))

    def test_operational_when_enabled_with_token(self) -> None:
        env = {
            "MORI_ZABBIX_WRITEBACK_ENABLED": "1",
            "MORI_ZABBIX_API_URL": "http://zabbix.example/api_jsonrpc.php",
            "MORI_ZABBIX_API_TOKEN": "api-token",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = ZabbixWritebackConfig.from_env()
        self.assertTrue(cfg.is_operational)
        self.assertIsInstance(build_zabbix_writeback_client(cfg), ZabbixWritebackClient)

    def test_unsupported_mode_stays_read_only(self) -> None:
        env = {
            "MORI_ZABBIX_WRITEBACK_ENABLED": "1",
            "MORI_ZABBIX_WRITEBACK_MODE": "manual_close",
            "MORI_ZABBIX_API_URL": "http://zabbix.example/api_jsonrpc.php",
            "MORI_ZABBIX_API_TOKEN": "api-token",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = ZabbixWritebackConfig.from_env()
        self.assertFalse(cfg.is_operational)
        self.assertIsNone(build_zabbix_writeback_client(cfg))


if __name__ == "__main__":
    unittest.main()
