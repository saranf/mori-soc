import json
import unittest
from unittest.mock import patch

from mori_soc.integrations.zabbix_transport import ZabbixApiError, ZabbixTransport
from mori_soc.integrations.zabbix_writeback import (
    ACK_ACTION_ACK_WITH_MESSAGE,
    ACK_ACTION_ADD_MESSAGE,
    ACK_ACTION_SUPPRESS_WITH_MESSAGE,
    ACK_ACTION_UNSUPPRESS_WITH_MESSAGE,
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

    def test_acknowledge_uses_ack_plus_message_action(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {"eventids": ["12345"]}, "id": 1})

        client = ZabbixWritebackClient(_transport(), prefix="[MORI]")
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            client.acknowledge("12345", "검토 착수")

        payload = json.loads(captured[0].data.decode("utf-8"))
        self.assertEqual(payload["method"], "event.acknowledge")
        self.assertEqual(payload["params"]["action"], ACK_ACTION_ACK_WITH_MESSAGE)  # 2|4 == 6
        self.assertEqual(payload["params"]["action"], 6)
        self.assertEqual(payload["params"]["message"], "[MORI] 검토 착수")

    def test_suppress_uses_suppress_action_with_until(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {"eventids": ["12345"]}, "id": 1})

        client = ZabbixWritebackClient(_transport(), prefix="[MORI]")
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            client.suppress("12345", "점검창 예외", until=1752000000)

        params = json.loads(captured[0].data.decode("utf-8"))["params"]
        self.assertEqual(params["action"], ACK_ACTION_SUPPRESS_WITH_MESSAGE)  # 32|4 == 36
        self.assertEqual(params["action"], 36)
        self.assertEqual(params["suppress_until"], 1752000000)
        self.assertEqual(params["message"], "[MORI] 점검창 예외")

    def test_suppress_indefinite_defaults_until_zero(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {}, "id": 1})

        client = ZabbixWritebackClient(_transport())
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            client.suppress("12345", "무기한")

        params = json.loads(captured[0].data.decode("utf-8"))["params"]
        self.assertEqual(params["suppress_until"], 0)

    def test_unsuppress_uses_unsuppress_action(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {}, "id": 1})

        client = ZabbixWritebackClient(_transport())
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            client.unsuppress("12345", "예외 철회")

        params = json.loads(captured[0].data.decode("utf-8"))["params"]
        self.assertEqual(params["action"], ACK_ACTION_UNSUPPRESS_WITH_MESSAGE)  # 64|4 == 68
        self.assertEqual(params["action"], 68)
        self.assertNotIn("suppress_until", params)

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

    def test_ack_comment_mode_operational(self) -> None:
        env = {
            "MORI_ZABBIX_WRITEBACK_ENABLED": "1",
            "MORI_ZABBIX_WRITEBACK_MODE": "ack_comment",
            "MORI_ZABBIX_API_URL": "http://zabbix.example/api_jsonrpc.php",
            "MORI_ZABBIX_API_TOKEN": "api-token",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = ZabbixWritebackConfig.from_env()
        self.assertTrue(cfg.is_operational)
        self.assertTrue(cfg.is_ack_mode)
        self.assertFalse(cfg.can_suppress)  # ack_comment 는 suppress 권한 없음
        self.assertIsInstance(build_zabbix_writeback_client(cfg), ZabbixWritebackClient)

    def test_suppress_mode_unlocks_suppress_and_ack(self) -> None:
        env = {
            "MORI_ZABBIX_WRITEBACK_ENABLED": "1",
            "MORI_ZABBIX_WRITEBACK_MODE": "suppress",
            "MORI_ZABBIX_API_URL": "http://zabbix.example/api_jsonrpc.php",
            "MORI_ZABBIX_API_TOKEN": "api-token",
        }
        with patch.dict("os.environ", env, clear=True):
            cfg = ZabbixWritebackConfig.from_env()
        self.assertTrue(cfg.is_operational)
        self.assertTrue(cfg.can_suppress)
        self.assertTrue(cfg.is_ack_mode)  # suppress 는 ack 도 포함(상위 레벨)

    def test_lower_modes_cannot_suppress(self) -> None:
        for mode in ("comment_only", "ack_comment"):
            cfg = ZabbixWritebackConfig(enabled=True, mode=mode, api_url="http://x", token="t")
            self.assertFalse(cfg.can_suppress, mode)


class ShouldAcknowledgeTests(unittest.TestCase):
    def _cfg(self, mode: str) -> ZabbixWritebackConfig:
        return ZabbixWritebackConfig(enabled=True, mode=mode, api_url="http://x", token="t")

    def test_comment_only_never_acknowledges(self) -> None:
        cfg = self._cfg("comment_only")
        self.assertFalse(cfg.should_acknowledge("resolved"))
        self.assertFalse(cfg.should_acknowledge("reviewing", explicit=True))  # override ignored off-mode

    def test_ack_mode_status_driven(self) -> None:
        cfg = self._cfg("ack_comment")
        self.assertTrue(cfg.should_acknowledge("reviewing"))
        self.assertTrue(cfg.should_acknowledge("resolved"))
        self.assertFalse(cfg.should_acknowledge("pending"))

    def test_ack_mode_explicit_override_wins(self) -> None:
        cfg = self._cfg("ack_comment")
        self.assertTrue(cfg.should_acknowledge("pending", explicit=True))    # 버튼 강제 ack
        self.assertFalse(cfg.should_acknowledge("resolved", explicit=False))  # 강제 comment-only


class SuppressEndpointTests(unittest.TestCase):
    """POST /alerts/{id}/zabbix/(un)suppress — route + helper + mode gating."""

    def _client(self, mode: str):
        from datetime import datetime, timezone

        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.models.entities import Alert, Host
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService

        now = datetime.now(tz=timezone.utc)
        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-z", hostname="srv-01", status="online", last_seen_at=now)],
            alerts=[Alert(alert_id="alert-z", source="zabbix", host_id="host-z", observed_at=now,
                          message="CPU high", severity="high", source_event_id="12345")],
        )
        env = {
            "MORI_DEMO_SEED": "0",
            "MORI_AUTH_ENABLED": "",   # auth off → role gate bypassed for happy-path
            "MORI_LDAP_ENABLED": "",   # LDAP 도 auth 를 강제하므로 함께 비활성
            "MORI_ZABBIX_WRITEBACK_ENABLED": "1",
            "MORI_ZABBIX_WRITEBACK_MODE": mode,
            "MORI_ZABBIX_API_URL": "http://zabbix.example/api_jsonrpc.php",
            "MORI_ZABBIX_API_TOKEN": "api-token",
        }
        with patch.dict("os.environ", env, clear=False):
            return TestClient(create_app(QueryService(store)))

    def test_suppress_calls_zabbix_and_returns_ok(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {"eventids": ["12345"]}, "id": 1})

        client = self._client("suppress")
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            resp = client.post("/alerts/alert-z/zabbix/suppress", json={"minutes": 30, "reason": "점검창"})

        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["action"], "suppress")
        self.assertGreater(body["suppress_until"], 0)  # 30분 → 미래 타임스탬프
        params = json.loads(captured[0].data.decode("utf-8"))["params"]
        self.assertEqual(params["action"], 36)
        self.assertIn("suppress_until", params)

    def test_unsuppress_calls_zabbix(self) -> None:
        captured = []

        def fake_urlopen(req, timeout=0):
            del timeout
            captured.append(req)
            return _FakeResponse({"jsonrpc": "2.0", "result": {}, "id": 1})

        client = self._client("suppress")
        with patch("mori_soc.integrations.zabbix_transport.request.urlopen", side_effect=fake_urlopen):
            resp = client.post("/alerts/alert-z/zabbix/unsuppress", json={"reason": "철회"})

        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["action"], "unsuppress")
        self.assertEqual(json.loads(captured[0].data.decode("utf-8"))["params"]["action"], 68)

    def test_suppress_rejected_when_mode_is_comment_only(self) -> None:
        client = self._client("comment_only")
        resp = client.post("/alerts/alert-z/zabbix/suppress", json={"minutes": 10})
        self.assertEqual(resp.status_code, 409, resp.text)  # not enabled for suppress

    def test_suppress_404_for_unknown_alert(self) -> None:
        client = self._client("suppress")
        resp = client.post("/alerts/nope/zabbix/suppress", json={})
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
