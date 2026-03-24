import importlib.util
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.api.server import (
    DEFAULT_UI_PAYLOAD,
    build_dashboard_payload,
    build_query_request,
    create_app,
    create_query_service,
    create_query_service_from_env,
    interpret_query_text,
    render_query_console_html,
    render_user_dashboard_html,
)
from mori_soc.models import Alert, Host, HostAlias, HostObservation, QueryResult, SourceSync, Vulnerability
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

    def test_render_query_console_html_contains_expected_admin_features(self) -> None:
        html = render_query_console_html()
        self.assertIn("MORI Admin Console", html)
        self.assertIn("http://mori.rmstudio.co.kr:37854/", html)
        self.assertIn("/query", html)
        self.assertIn("/query?format=csv", html)
        self.assertIn("/interpret", html)
        self.assertIn("/dashboard/summary", html)
        self.assertIn("/dashboard/preferences", html)
        self.assertIn("Open User Dashboard", html)
        self.assertIn("User Dashboard Controls", html)
        self.assertIn("Natural Language Query", html)
        self.assertIn("Structured Query Builder", html)
        self.assertIn("Query Guide", html)
        self.assertIn("오프라인 호스트 보여줘", html)
        self.assertIn(DEFAULT_UI_PAYLOAD["intent"], html)
        self.assertIn("overview_modal", html)
        self.assertIn("resolvePayloadForRun", html)
        self.assertIn("queryMode = 'natural'", html)
        self.assertIn("extractFilename", html)
        self.assertIn("downloadTextFile", html)

    def test_render_user_dashboard_html_hides_query_console_controls(self) -> None:
        html = render_user_dashboard_html()
        self.assertIn("MORI Security Dashboard", html)
        self.assertIn("http://mori.rmstudio.co.kr:37854/", html)
        self.assertIn("/dashboard/summary", html)
        self.assertIn("/dashboard/preferences", html)
        self.assertIn("overview_modal", html)
        self.assertNotIn("Natural Language Query", html)
        self.assertNotIn("Structured Query Builder", html)
        self.assertNotIn("User Dashboard Controls", html)
        self.assertNotIn("Open User Dashboard", html)

    def test_interpret_query_text_returns_structured_request(self) -> None:
        interpretation = interpret_query_text("최근 24시간 wazuh high alert 요약")
        self.assertEqual(interpretation["intent"], "alert_summary")
        self.assertEqual(interpretation["scope"]["time_range"], "24h")
        self.assertEqual(interpretation["scope"]["source"], "wazuh")
        self.assertEqual(interpretation["scope"]["severity"], "high")
        self.assertTrue(interpretation["recognized"])
        self.assertGreater(len(interpretation["guide_examples"]), 0)

    def test_interpret_query_text_returns_guide_for_unrecognized_text(self) -> None:
        interpretation = interpret_query_text("안녕하세요 오늘 뭐가 좋을까요")
        self.assertEqual(interpretation["intent"], "alert_summary")
        self.assertFalse(interpretation["recognized"])
        self.assertGreater(len(interpretation["warnings"]), 0)
        self.assertGreater(len(interpretation["guide_examples"]), 0)

    def test_build_dashboard_payload_summarizes_store(self) -> None:
        now = datetime.now(tz=timezone.utc)
        store = InMemoryQueryStore(
            hosts=[
                Host(host_id="host-1", hostname="mbp-01", status="offline", risk_score=85, last_seen_at=now),
                Host(host_id="host-2", hostname="srv-01", status="online", risk_score=30, last_seen_at=now),
            ],
            host_aliases=[
                HostAlias(alias_id="a1", host_id="host-1", source="fleet", alias_type="uuid", alias_value="fleet-1"),
                HostAlias(alias_id="a2", host_id="host-2", source="zabbix", alias_type="hostid", alias_value="20084"),
                HostAlias(alias_id="a3", host_id="host-1", source="trivy", alias_type="hostname", alias_value="mbp-01"),
            ],
            alerts=[
                Alert(
                    alert_id="alert-1",
                    source="wazuh",
                    host_id="host-1",
                    observed_at=now,
                    message="sudo brute force",
                    severity="critical",
                )
            ],
            vulnerabilities=[
                Vulnerability(
                    vuln_id="vuln-1",
                    host_id="host-1",
                    detected_at=now,
                    severity="critical",
                    cve="CVE-2025-0001",
                )
            ],
            query_results=[
                QueryResult(
                    query_result_id="qr-1",
                    host_id="host-1",
                    observed_at=now,
                    result_json={"rows": 1},
                    query_name="osquery_processes",
                )
            ],
            observations=[
                HostObservation(
                    observation_id="obs-1",
                    source="zabbix",
                    host_id="host-2",
                    observation_type="metric",
                    metric_name="cpu.util",
                    metric_value="91",
                    unit="%",
                    observed_at=now,
                )
            ],
            source_syncs=[
                SourceSync(
                    source="zabbix",
                    status="success",
                    last_sync_at=now,
                    last_success_at=now,
                    message="host.get + problem.get ok",
                    records_collected=2,
                    envelopes_normalized=2,
                    entities_saved=4,
                ),
                SourceSync(
                    source="trivy",
                    status="success",
                    last_sync_at=now,
                    last_success_at=now,
                    message="report parsed",
                    records_collected=1,
                    envelopes_normalized=1,
                    entities_saved=2,
                )
            ],
        )
        payload = build_dashboard_payload(QueryService(store))
        self.assertEqual(payload["overview"]["total_hosts"], 2)
        self.assertEqual(payload["overview"]["offline_hosts"], 1)
        self.assertEqual(payload["overview"]["alerts_24h"], 1)
        self.assertEqual(payload["overview"]["critical_vulns"], 1)
        self.assertEqual(payload["source_coverage"][0]["source"], "fleet")
        zabbix_row = next(item for item in payload["source_coverage"] if item["source"] == "zabbix")
        trivy_row = next(item for item in payload["source_coverage"] if item["source"] == "trivy")
        self.assertEqual(zabbix_row["status"], "success")
        self.assertEqual(trivy_row["host_count"], 1)
        self.assertEqual(payload["overview"]["sources_healthy"], 2)
        self.assertEqual(payload["latest_status"][0]["host_id"], "host-1")
        self.assertTrue(any(item["entity_type"] == "alert" for item in payload["recent_activity"]))
        self.assertEqual(len(payload["recommended_queries"]), 4)
        self.assertIn("overview_details", payload)
        self.assertEqual(payload["overview_details"]["offline_hosts"][0]["host_id"], "host-1")
        self.assertEqual(payload["overview_details"]["alerts_24h"][0]["alert_id"], "alert-1")
        self.assertEqual(payload["overview_details"]["critical_vulns"][0]["vuln_id"], "vuln-1")
        self.assertEqual(payload["overview_details"]["ingested_records"][0]["entity_type"], "alerts")


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

    def test_query_endpoint_supports_csv_download(self) -> None:
        response = self.client.post("/query?format=csv", json={"intent": "offline_hosts", "scope": {"time_range": "24h"}})
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers["content-type"])
        self.assertIn("attachment; filename=", response.headers["content-disposition"])
        self.assertIn("query_summary", response.text)
        self.assertIn("evidence_count", response.text)

    def test_ui_endpoint(self) -> None:
        response = self.client.get("/ui")
        self.assertEqual(response.status_code, 200)
        self.assertIn("MORI Security Dashboard", response.text)
        self.assertNotIn("Natural Language Query", response.text)

    def test_admin_endpoint(self) -> None:
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertIn("MORI Admin Console", response.text)
        self.assertIn("User Dashboard Controls", response.text)

    def test_root_redirects_to_ui(self) -> None:
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers["location"], "/ui")

    def test_dashboard_summary_endpoint(self) -> None:
        response = self.client.get("/dashboard/summary")
        self.assertEqual(response.status_code, 200)
        self.assertIn("overview", response.json())
        self.assertIn("overview_details", response.json())

    def test_dashboard_preferences_get_and_update(self) -> None:
        response = self.client.get("/dashboard/preferences")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["docs_url"], "http://mori.rmstudio.co.kr:37854/")
        self.assertIn("user_dashboard", payload)
        self.assertIn("cards", payload["user_dashboard"])
        self.assertIn("sections", payload["user_dashboard"])

        update_response = self.client.post(
            "/dashboard/preferences",
            json={
                "docs_url": "http://mori.rmstudio.co.kr:37854/guide",
                "user_dashboard": {
                    "cards": {"ingested_records": True},
                    "sections": {"source_coverage": True},
                },
            },
        )
        self.assertEqual(update_response.status_code, 200)
        updated = update_response.json()
        self.assertEqual(updated["docs_url"], "http://mori.rmstudio.co.kr:37854/guide")
        self.assertTrue(updated["user_dashboard"]["cards"]["ingested_records"])
        self.assertTrue(updated["user_dashboard"]["sections"]["source_coverage"])

    def test_dashboard_preferences_reject_unknown_key(self) -> None:
        response = self.client.post(
            "/dashboard/preferences",
            json={"user_dashboard": {"cards": {"not_a_real_card": True}}},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("unknown user dashboard cards key", response.json()["detail"])

    def test_interpret_endpoint_returns_guide_metadata(self) -> None:
        response = self.client.post("/interpret", json={"text": "안녕하세요 오늘 뭐가 좋을까요"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("recognized", response.json())
        self.assertIn("guide_examples", response.json())