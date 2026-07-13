import importlib.util
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.api.server import (
    DEFAULT_UI_PAYLOAD,
    build_dashboard_payload,
    build_pdca_payload,
    build_query_request,
    create_app,
    create_query_service,
    create_query_service_from_env,
    interpret_query_text,
    render_query_console_html,
    render_user_dashboard_html,
)
from mori_soc.models import (
    Alert,
    ControlCheckResult,
    Host,
    HostAlias,
    HostObservation,
    QueryResult,
    SourceSync,
    Vulnerability,
)
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
        import pathlib

        import mori_soc.api.templates.console as _con_mod
        html = render_query_console_html()
        # P7-2: JS는 static/js/console.js 로 외부화됨 — JS 마커는 결합 문자열에서 검사
        js = (pathlib.Path(_con_mod.__file__).parent.parent / "static" / "js"
              / "console.js").read_text(encoding="utf-8")
        bundle = html + js
        # HTML 셸(서버 렌더) 마커
        self.assertIn("MORI 관리자 콘솔", html)
        self.assertIn("http://mori.rmstudio.co.kr:37854/", html)
        self.assertIn("사용자 대시보드", html)
        self.assertIn("Natural Language Query", html)
        self.assertIn("Structured Query Builder", html)
        self.assertIn("Query Guide", html)
        self.assertIn("overview_modal", html)
        # JS(외부화) 마커
        self.assertIn("/query", bundle)
        self.assertIn("/query?format=csv", bundle)
        self.assertIn("/interpret", bundle)
        self.assertIn("/dashboard/summary", bundle)
        self.assertIn("/dashboard/preferences", bundle)
        self.assertIn("사용자 대시보드 설정", bundle)
        self.assertIn("오프라인 호스트 보여줘", bundle)
        self.assertIn(DEFAULT_UI_PAYLOAD["intent"], bundle)
        self.assertIn("resolvePayloadForRun", bundle)
        self.assertIn("queryMode = 'natural'", bundle)
        self.assertIn("Download CSV", bundle)
        self.assertIn("hasQueryResults", bundle)
        self.assertIn("showNoResultsAlert", bundle)
        self.assertIn("window.alert", bundle)
        self.assertIn("extractFilename", bundle)
        self.assertIn("downloadTextFile", bundle)

    def test_render_user_dashboard_html_hides_query_console_controls(self) -> None:
        import pathlib

        import mori_soc.api.templates.dashboard as _dash_mod
        html = render_user_dashboard_html()
        # P2: JS는 static/js/dashboard.js 로 외부화됨 — JS 마커는 결합 문자열에서 검사
        js = (pathlib.Path(_dash_mod.__file__).parent.parent / "static" / "js"
              / "dashboard.js").read_text(encoding="utf-8")
        bundle = html + js
        self.assertIn("MORI 보안 점검 현황", bundle)
        self.assertIn("http://mori.rmstudio.co.kr:37854/", html)
        self.assertIn("/dashboard/summary", bundle)
        self.assertIn("/dashboard/preferences", bundle)
        self.assertIn("overview_modal", html)
        self.assertNotIn("Natural Language Query", bundle)
        self.assertNotIn("Structured Query Builder", bundle)
        self.assertNotIn("MORI 점검·통제 운영 콘솔", bundle)
        self.assertNotIn("Open User Dashboard", bundle)  # admin uses 사용자 대시보드 now
        # NLQ section present in /ui
        self.assertIn("자연어 질의 (NLQ)", html)
        self.assertIn("nlq_textarea", html)
        self.assertIn("nlq_run_btn", html)
        self.assertIn("nlq_csv_btn", html)
        self.assertIn("/interpret", bundle)
        # Grafana link and info modal
        self.assertIn("grafana_url", bundle)
        self.assertIn("info_modal", html)
        self.assertIn("showInfoModal", bundle)

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
        # grafana_url must be present in recent_activity items
        alert_item = next(item for item in payload["recent_activity"] if item["entity_type"] == "alert")
        self.assertIn("grafana_url", alert_item)
        self.assertIsNotNone(alert_item["grafana_url"])
        self.assertIn("mori.rmstudio.co.kr:13000", alert_item["grafana_url"])
        # counts derived from status_rows (dedup'd) – verify online/offline counts are consistent
        self.assertEqual(payload["overview"]["online_hosts"], 1)
        self.assertEqual(payload["overview"]["unknown_hosts"], 0)


@unittest.skipUnless(FASTAPI_AVAILABLE, "fastapi is not installed")
class FastAPIAppTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-1", hostname="mbp-01", status="online", last_seen_at=datetime.now(tz=timezone.utc))]
        )
        # 데모 시드는 비활성화하여 테스트를 결정적으로 유지 (compose 기본값 MORI_DEMO_SEED=1 무력화)
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0"}, clear=False):
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
        self.assertIn("질의요약", response.text)
        self.assertIn("증거수", response.text)

    def test_ui_endpoint(self) -> None:
        response = self.client.get("/ui")
        self.assertEqual(response.status_code, 200)
        self.assertIn("MORI Security Dashboard", response.text)
        self.assertNotIn("Natural Language Query", response.text)

    def test_admin_endpoint(self) -> None:
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertIn("MORI 점검·통제 운영 콘솔", response.text)
        self.assertIn("사용자 대시보드 설정", response.text)

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

    def test_alert_triage_update_accepts_new_statuses(self) -> None:
        """pending/reviewing/resolved 상태를 허용해야 한다."""
        for status in ("pending", "reviewing", "resolved"):
            response = self.client.patch(
                "/alerts/alert-abc/triage",
                json={"status": status, "analyst": "tester"},
            )
            self.assertEqual(response.status_code, 200, f"status={status} rejected")
            data = response.json()
            self.assertEqual(data["triage"]["status"], status)

    def test_alert_triage_update_rejects_old_statuses(self) -> None:
        """new/acknowledged 같은 구 상태는 400을 반환해야 한다."""
        for status in ("new", "acknowledged", "investigating", "closed", "false_positive"):
            response = self.client.patch(
                "/alerts/alert-abc/triage",
                json={"status": status},
            )
            self.assertEqual(response.status_code, 400, f"old status={status} should be rejected")

    def test_alert_triage_history_recorded(self) -> None:
        """상태 변경 시 history 항목이 추가되어야 한다."""
        alert_id = "alert-hist-test"
        self.client.patch(f"/alerts/{alert_id}/triage", json={"status": "pending", "analyst": "a1"})
        resp = self.client.patch(f"/alerts/{alert_id}/triage", json={"status": "reviewing", "analyst": "a2"})
        self.assertEqual(resp.status_code, 200)
        triage = resp.json()["triage"]
        self.assertIn("history", triage)
        self.assertTrue(len(triage["history"]) >= 2)
        last = triage["history"][-1]
        self.assertEqual(last["from_status"], "pending")
        self.assertEqual(last["to_status"], "reviewing")

    def test_alert_triage_actor_from_payload(self) -> None:
        """payload.actor가 주어지면 entry/history에 changed_by로 기록되어야 한다."""
        alert_id = "alert-actor-test"
        resp = self.client.patch(
            f"/alerts/{alert_id}/triage",
            json={"status": "reviewing", "analyst": "a1", "actor": "alice"},
        )
        self.assertEqual(resp.status_code, 200)
        triage = resp.json()["triage"]
        self.assertEqual(triage["changed_by"], "alice")
        self.assertTrue(len(triage["history"]) >= 1)
        self.assertEqual(triage["history"][-1]["changed_by"], "alice")

    def test_alert_triage_actor_falls_back_to_unknown(self) -> None:
        """actor 미지정·세션 미인증이면 changed_by는 'unknown'이어야 한다."""
        alert_id = "alert-actor-unknown-test"
        resp = self.client.patch(
            f"/alerts/{alert_id}/triage",
            json={"status": "pending", "analyst": "a1"},
        )
        self.assertEqual(resp.status_code, 200)
        triage = resp.json()["triage"]
        self.assertEqual(triage["changed_by"], "unknown")
        self.assertEqual(triage["history"][-1]["changed_by"], "unknown")

    def test_incidents_create_has_history(self) -> None:
        """인시던트 생성 시 history에 created 항목이 있어야 한다."""
        resp = self.client.post("/incidents", json={"title": "테스트 인시던트", "analyst": "ops"})
        self.assertEqual(resp.status_code, 200)
        inc = resp.json()
        self.assertIn("history", inc)
        self.assertTrue(len(inc["history"]) >= 1)
        self.assertEqual(inc["history"][0]["event"], "created")

    def test_incidents_status_change_recorded_in_history(self) -> None:
        """인시던트 상태 변경 시 history에 status_changed 항목이 추가되어야 한다."""
        create_resp = self.client.post("/incidents", json={"title": "히스토리 테스트"})
        inc_id = create_resp.json()["incident_id"]
        patch_resp = self.client.patch(
            f"/incidents/{inc_id}",
            json={"status": "investigating", "analyst": "analyst1"},
        )
        self.assertEqual(patch_resp.status_code, 200)
        inc = patch_resp.json()
        history = inc.get("history", [])
        status_events = [h for h in history if h.get("event") == "status_changed"]
        self.assertTrue(len(status_events) >= 1)
        self.assertEqual(status_events[-1]["to_status"], "investigating")

    def test_fleet_hosts_endpoint(self) -> None:
        """GET /fleet/hosts 는 fleet 소스 데이터를 반환해야 한다."""
        response = self.client.get("/fleet/hosts")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["source"], "fleet")
        self.assertIn("hosts", data)

    def test_zabbix_hosts_endpoint(self) -> None:
        """GET /zabbix/hosts 는 zabbix 소스 데이터를 반환해야 한다."""
        response = self.client.get("/zabbix/hosts")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["source"], "zabbix")
        self.assertIn("hosts", data)

    def test_trivy_vulnerabilities_endpoint(self) -> None:
        """GET /trivy/vulnerabilities 는 trivy 취약점 데이터를 반환해야 한다."""
        response = self.client.get("/trivy/vulnerabilities")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["source"], "trivy")
        self.assertIn("by_host", data)

    def test_trivy_vulnerabilities_rejects_invalid_severity(self) -> None:
        """유효하지 않은 severity 필터는 400을 반환해야 한다."""
        response = self.client.get("/trivy/vulnerabilities?severity=unknown_sev")
        self.assertEqual(response.status_code, 400)

    def test_login_page_returns_html(self) -> None:
        """/login 페이지는 HTML을 반환해야 한다."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("MORI SOC", response.text)
        self.assertIn("로그인", response.text)
        self.assertIn("/auth/login", response.text)
        self.assertIn("/signup-request", response.text)

    def test_signup_request_page_returns_html(self) -> None:
        """/signup-request 페이지는 HTML을 반환해야 한다."""
        response = self.client.get("/signup-request")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertIn("가입 요청", response.text)
        self.assertIn("/auth/signup-request", response.text)

    def test_auth_login_rejects_wrong_credentials(self) -> None:
        """/auth/login 에 잘못된 자격증명은 401을 반환해야 한다."""
        response = self.client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        self.assertEqual(response.status_code, 401)

    def test_auth_login_requires_username_and_password(self) -> None:
        """/auth/login 에 빈 자격증명은 400을 반환해야 한다."""
        response = self.client.post("/auth/login", json={"username": "", "password": ""})
        self.assertEqual(response.status_code, 400)

    def test_signup_request_submit_and_list(self) -> None:
        """가입 요청 제출 후 목록에서 조회 가능해야 한다."""
        resp = self.client.post("/auth/signup-request", json={
            "name": "홍길동", "email": "hong@test.com",
            "department": "보안팀", "reason": "업무 목적"
        })
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["ok"])

        list_resp = self.client.get("/auth/signup-requests")
        self.assertEqual(list_resp.status_code, 200)
        data = list_resp.json()
        self.assertIn("requests", data)
        emails = [r["email"] for r in data["requests"]]
        self.assertIn("hong@test.com", emails)

    def test_signup_request_requires_name_and_email(self) -> None:
        """이름이나 이메일 없이 가입 요청하면 400을 반환해야 한다."""
        response = self.client.post("/auth/signup-request", json={"name": "", "email": ""})
        self.assertEqual(response.status_code, 400)

    def test_signup_request_approve_and_reject(self) -> None:
        """가입 요청 승인/거절이 올바르게 동작해야 한다."""
        # 요청 생성
        resp = self.client.post("/auth/signup-request", json={"name": "테스터", "email": "tester@x.com"})
        req_id = self.client.get("/auth/signup-requests").json()["requests"][-1]["id"]

        # 승인
        approve_resp = self.client.patch(f"/auth/signup-requests/{req_id}", json={"status": "approved"})
        self.assertEqual(approve_resp.status_code, 200)
        self.assertEqual(approve_resp.json()["status"], "approved")

        # 거절로 변경
        reject_resp = self.client.patch(f"/auth/signup-requests/{req_id}", json={"status": "rejected"})
        self.assertEqual(reject_resp.status_code, 200)
        self.assertEqual(reject_resp.json()["status"], "rejected")

    def test_signup_request_rejects_invalid_status(self) -> None:
        """유효하지 않은 상태값은 400을 반환해야 한다."""
        self.client.post("/auth/signup-request", json={"name": "테스터2", "email": "t2@x.com"})
        req_id = self.client.get("/auth/signup-requests").json()["requests"][-1]["id"]
        response = self.client.patch(f"/auth/signup-requests/{req_id}", json={"status": "unknown"})
        self.assertEqual(response.status_code, 400)

    def test_user_dashboard_has_logout_link(self) -> None:
        """/ui 에 로그아웃 링크가 있어야 한다."""
        response = self.client.get("/ui")
        self.assertIn("/auth/logout", response.text)

    def test_auth_profile_requires_login(self) -> None:
        """비로그인 상태의 /auth/profile 접근은 401을 반환해야 한다."""
        self.assertEqual(self.client.get("/auth/profile").status_code, 401)
        post = self.client.post("/auth/profile", json={"display_name": "x"})
        self.assertEqual(post.status_code, 401)

    def test_auth_profile_roundtrip_and_me_merge(self) -> None:
        """로그인 후 프로필 업서트 → GET /auth/profile 및 /auth/me 에 병합 반영되어야 한다."""
        login = self.client.post("/auth/login", json={"username": "admin", "password": "1234"})
        self.assertEqual(login.status_code, 200)

        # 초기 /auth/me 에는 빈 프로필 필드가 포함된다
        me0 = self.client.get("/auth/me").json()
        self.assertEqual(me0["display_name"], "")
        self.assertEqual(me0["department"], "")
        self.assertEqual(me0["assigned_servers"], [])

        # 업서트: assigned_servers 는 줄바꿈/쉼표 혼용 문자열도 허용
        up = self.client.post(
            "/auth/profile",
            json={"display_name": "홍길동", "department": "인프라팀", "assigned_servers": "web-01\nweb-02, db-01"},
        )
        self.assertEqual(up.status_code, 200)
        self.assertTrue(up.json()["ok"])
        self.assertEqual(up.json()["assigned_servers"], ["web-01", "web-02", "db-01"])

        # GET /auth/profile 로 영속 확인
        prof = self.client.get("/auth/profile").json()
        self.assertEqual(prof["display_name"], "홍길동")
        self.assertEqual(prof["department"], "인프라팀")
        self.assertEqual(prof["assigned_servers"], ["web-01", "web-02", "db-01"])

        # /auth/me 응답에 프로필 필드 병합
        me1 = self.client.get("/auth/me").json()
        self.assertEqual(me1["display_name"], "홍길동")
        self.assertEqual(me1["assigned_servers"], ["web-01", "web-02", "db-01"])

    def test_user_dashboard_has_profile_modal_and_my_servers(self) -> None:
        """/ui 에 프로필 편집 모달과 '내 서버' 서브탭 요소가 있어야 한다."""
        response = self.client.get("/ui")
        self.assertIn("profile_modal", response.text)
        self.assertIn("assets_mine_section", response.text)
        self.assertIn("renderMyServers", response.text)

    def test_admin_has_signup_requests_tab(self) -> None:
        """/admin 어드민 콘솔에 가입 요청 탭이 있어야 한다 (Phase 2: Access Control 탭 통합)."""
        response = self.client.get("/admin")
        self.assertIn("가입 요청", response.text)
        self.assertIn("atab_access", response.text)

    def test_demo_seed_populates_stores_when_enabled(self) -> None:
        """MORI_DEMO_SEED 활성화 시 triage/owner/profile 스토어에 데모 데이터가 주입되어야 한다."""
        from fastapi.testclient import TestClient

        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-1", hostname="mbp-01", status="online", last_seen_at=datetime.now(tz=timezone.utc))]
        )
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "1"}, clear=False):
            client = TestClient(create_app(QueryService(store)))

        # asset owners 시드 확인
        owners = {o["hostname"]: o for o in client.get("/assets/owners").json()["owners"]}
        self.assertIn("web-server-01", owners)
        self.assertEqual(owners["web-server-01"]["owner"], "보안담당자")

        # user profile 시드 → /auth/me 병합 확인
        self.assertEqual(client.post("/auth/login", json={"username": "security", "password": "1234"}).status_code, 200)
        me = client.get("/auth/me").json()
        self.assertEqual(me["display_name"], "보안담당자")
        self.assertIn("web-server-01", me["assigned_servers"])


# ---------------------------------------------------------------------------
# PDCA Dashboard Tests
# ---------------------------------------------------------------------------


class BuildPdcaPayloadTests(unittest.TestCase):
    """build_pdca_payload 함수 단위 테스트."""

    def setUp(self) -> None:
        self.now = datetime.now(tz=timezone.utc)

    def _make_check(self, check_id: str, control_id: str, status: str, **kw) -> ControlCheckResult:
        return ControlCheckResult(
            check_id=check_id,
            control_id=control_id,
            entity_type=kw.get("entity_type", "host"),
            entity_id=kw.get("entity_id", "host-1"),
            status=status,
            checked_at=self.now,
            owner=kw.get("owner"),
            note=kw.get("note"),
            remediation_due_at=kw.get("remediation_due_at"),
            resolved_at=kw.get("resolved_at"),
        )

    def test_empty_store_returns_zero_counts(self) -> None:
        store = InMemoryQueryStore()
        payload = build_pdca_payload(QueryService(store))
        self.assertEqual(payload["total_checks"], 0)
        self.assertEqual(payload["pass_rate"], 0.0)
        self.assertEqual(payload["pending_count"], 0)
        self.assertEqual(payload["overdue_count"], 0)

    def test_status_counts_are_correct(self) -> None:
        checks = [
            self._make_check("c1", "A.8.1", "pass"),
            self._make_check("c2", "A.8.1", "pass"),
            self._make_check("c3", "A.8.2", "fail"),
            self._make_check("c4", "A.9.1", "warning"),
            self._make_check("c5", "A.9.2", "not_checked"),
            self._make_check("c6", "A.9.2", "not_applicable"),
        ]
        store = InMemoryQueryStore(control_checks=checks)
        payload = build_pdca_payload(QueryService(store))

        self.assertEqual(payload["total_checks"], 6)
        sc = payload["status_counts"]
        self.assertEqual(sc["pass"], 2)
        self.assertEqual(sc["fail"], 1)
        self.assertEqual(sc["warning"], 1)
        self.assertEqual(sc["not_checked"], 1)
        self.assertEqual(sc["not_applicable"], 1)

    def test_pass_rate_calculation(self) -> None:
        checks = [
            self._make_check("c1", "A.8.1", "pass"),
            self._make_check("c2", "A.8.1", "fail"),
            self._make_check("c3", "A.8.2", "pass"),
            self._make_check("c4", "A.8.3", "not_applicable"),  # 제외
        ]
        store = InMemoryQueryStore(control_checks=checks)
        payload = build_pdca_payload(QueryService(store))
        # checked = 4 - 0 (not_checked) - 1 (not_applicable) = 3
        # pass_rate = 2 / 3 * 100 = 66.7
        self.assertAlmostEqual(payload["pass_rate"], 66.7, places=1)

    def test_pdca_cycle_mapping(self) -> None:
        checks = [
            self._make_check("c1", "A.8.1", "pass"),
            self._make_check("c2", "A.8.2", "fail"),
            self._make_check("c3", "A.9.1", "warning"),
            self._make_check("c4", "A.9.2", "not_checked"),
        ]
        store = InMemoryQueryStore(control_checks=checks)
        payload = build_pdca_payload(QueryService(store))
        pdca = payload["pdca"]
        self.assertEqual(pdca["plan"], 1)   # not_checked
        self.assertEqual(pdca["do"], 2)     # fail + warning
        self.assertEqual(pdca["check"], 3)  # total - not_checked - not_applicable
        self.assertEqual(pdca["act"], 1)    # pass

    def test_categories_grouped_by_catalog_section(self) -> None:
        # 카탈로그 섹션명으로 그룹핑 + '통제 개수' 기준(트리 분모와 일치).
        # A.8.x 는 "A.8 Technological controls" 섹션. 통제당 1건으로 집계, 나머지는 미점검.
        checks = [
            self._make_check("c1", "A.8.1", "pass"),
            self._make_check("c2", "A.8.2", "fail"),
            self._make_check("c3", "A.8.1", "warning"),  # 같은 통제 두 번째 점검 → fail>warning>pass 우선순위상 A.8.1은 warning
        ]
        store = InMemoryQueryStore(control_checks=checks)
        payload = build_pdca_payload(QueryService(store))
        a8 = next(c for c in payload["categories"] if c["category"].startswith("A.8"))
        # 통제 기준 집계: A.8.1=warning, A.8.2=fail, 그 외 A.8 통제는 미점검.
        self.assertEqual(a8["fail"], 1)
        self.assertEqual(a8["warning"], 1)
        self.assertEqual(a8["pass"], 0)
        # total 은 카탈로그의 A.8 통제 개수(점검 건수 아님) → 미점검이 대부분.
        self.assertEqual(a8["total"], a8["pass"] + a8["fail"] + a8["warning"]
                         + a8["not_checked"] + a8["not_applicable"])
        self.assertGreater(a8["not_checked"], 0)
        self.assertEqual(a8["framework"], "iso27001")
        self.assertTrue(a8["domain"].startswith("A.8"))

    def test_pending_remediations_includes_fail_and_warning(self) -> None:
        from datetime import timedelta
        past = self.now - timedelta(days=7)
        checks = [
            self._make_check("c1", "A.8.1", "pass"),
            self._make_check("c2", "A.8.2", "fail", owner="보안팀", remediation_due_at=past),
            self._make_check("c3", "A.9.1", "warning", note="검토 필요"),
        ]
        store = InMemoryQueryStore(control_checks=checks)
        payload = build_pdca_payload(QueryService(store))
        self.assertEqual(payload["pending_count"], 2)
        self.assertEqual(payload["overdue_count"], 1)
        # 기한 초과 항목이 먼저 정렬
        self.assertEqual(payload["pending_remediations"][0]["check_id"], "c2")
        self.assertTrue(payload["pending_remediations"][0]["overdue"])


@unittest.skipUnless(FASTAPI_AVAILABLE, "fastapi is not installed")
class CompliancePdcaEndpointTests(unittest.TestCase):
    """GET /compliance/pdca 엔드포인트 통합 테스트."""

    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        now = datetime.now(tz=timezone.utc)
        store = InMemoryQueryStore(
            hosts=[Host(host_id="host-1", hostname="srv-01", status="online", last_seen_at=now)],
            control_checks=[
                ControlCheckResult(check_id="c1", control_id="A.8.1", entity_type="host", entity_id="host-1", status="pass", checked_at=now),
                ControlCheckResult(check_id="c2", control_id="A.8.2", entity_type="host", entity_id="host-1", status="fail", checked_at=now, owner="보안팀"),
            ],
        )
        self.client = TestClient(create_app(QueryService(store)))

    def test_pdca_endpoint_returns_200(self) -> None:
        response = self.client.get("/compliance/pdca")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_checks"], 2)
        self.assertIn("status_counts", data)
        self.assertIn("pdca", data)
        self.assertIn("categories", data)
        self.assertIn("pending_remediations", data)

    def test_pdca_endpoint_pass_rate(self) -> None:
        data = self.client.get("/compliance/pdca").json()
        self.assertAlmostEqual(data["pass_rate"], 50.0, places=1)

    def test_ui_contains_compliance_tab(self) -> None:
        response = self.client.get("/ui")
        self.assertIn("tab_compliance", response.text)
        self.assertIn("Compliance PDCA", response.text)