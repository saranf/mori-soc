import importlib.util
import os
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from mori_soc.api.server import (
    DEFAULT_UI_PAYLOAD,
    build_query_request,
    create_app,
    create_query_service,
    create_query_service_from_env,
    interpret_query_text,
    render_query_console_html,
)
from mori_soc.models import Host
from mori_soc.services.query_service import InMemoryQueryStore, QueryService

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


class QueryRequestBuilderTests(unittest.TestCase):
    def test_build_query_request_with_scope_and_filters(self) -> None:
        request = build_query_request(
            {
                "intent": "host_timeline",
                "scope": {"time_range": "7d", "host_id": "host-1", "severity": "high,critical"},
                "filters": {"limit": 10},
            }
        )
        self.assertEqual(request.intent, "host_timeline")
        self.assertEqual(request.scope.time_range, "7d")
        self.assertEqual(request.scope.host_id, "host-1")
        self.assertEqual(request.scope.severity, "high,critical")
        self.assertEqual(request.filters["limit"], 10)

    def test_build_query_request_rejects_missing_intent(self) -> None:
        with self.assertRaises(ValueError):
            build_query_request({"scope": {"time_range": "24h"}})

    def test_create_app_requires_fastapi_when_missing(self) -> None:
        if FASTAPI_AVAILABLE:
            self.skipTest("fastapi is installed in this environment")
        with self.assertRaises(RuntimeError):
            create_app()

    def test_create_query_service_uses_in_memory_by_default(self) -> None:
        service = create_query_service()
        self.assertIsInstance(service.store, InMemoryQueryStore)

    def test_create_query_service_from_env_rejects_unknown_backend(self) -> None:
        with patch.dict(os.environ, {"MORI_QUERY_BACKEND": "wat"}, clear=False):
            with self.assertRaises(RuntimeError):
                create_query_service_from_env()

    def test_create_query_service_from_env_requires_database_url_for_postgres(self) -> None:
        with patch.dict(os.environ, {"MORI_QUERY_BACKEND": "postgres"}, clear=True):
            with self.assertRaises(RuntimeError):
                create_query_service_from_env()

    def test_render_query_console_html_contains_expected_links(self) -> None:
        html = render_query_console_html()
        self.assertIn("MORI Query Console", html)
        self.assertIn("/docs", html)
        self.assertIn("/query", html)
        self.assertIn("/interpret", html)
        self.assertIn(DEFAULT_UI_PAYLOAD["intent"], html)

    def test_interpret_query_text_returns_structured_request(self) -> None:
        interpretation = interpret_query_text("최근 24시간 wazuh high alert 요약")
        self.assertEqual(interpretation["intent"], "alert_summary")
        self.assertEqual(interpretation["scope"]["time_range"], "24h")
        self.assertEqual(interpretation["scope"]["source"], "wazuh")
        self.assertEqual(interpretation["scope"]["severity"], "high")


@unittest.skipUnless(FASTAPI_AVAILABLE, "fastapi is not installed")
class FastAPIAppTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-1", hostname="mbp-01", status="online", last_seen_at=datetime.now(tz=timezone.utc))]
        )
        self.client = TestClient(create_app(QueryService(store)))

    def test_health_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_query_endpoint(self) -> None:
        response = self.client.post("/query", json={"intent": "offline_hosts", "scope": {"time_range": "24h"}})
        self.assertEqual(response.status_code, 200)
        self.assertIn("summary", response.json())

    def test_ui_endpoint(self) -> None:
        response = self.client.get("/ui")
        self.assertEqual(response.status_code, 200)
        self.assertIn("MORI Query Console", response.text)

    def test_root_redirects_to_ui(self) -> None:
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/ui")