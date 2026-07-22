"""온보딩 순수 서비스(services.onboarding) — 커넥터 상태·체크리스트 로직.

I/O 없는 순수 함수만 검증한다(라이브 연결 테스트는 라우터·docker 통합에서).
"""
from __future__ import annotations

import unittest

from mori_soc.services.onboarding import (
    build_checklist,
    build_connectors,
    build_scan_setup,
    connector_catalog,
    is_testable,
)


class ConnectorCatalogTest(unittest.TestCase):
    def test_only_pull_verified_is_testable(self) -> None:
        # 정직함: 라이브 검증된 pull(zabbix·fleet)만 테스트 가능, 수신형은 불가.
        self.assertTrue(is_testable("zabbix"))
        self.assertTrue(is_testable("fleet"))
        self.assertFalse(is_testable("trivy"))
        self.assertFalse(is_testable("wazuh"))
        self.assertFalse(is_testable("code_review"))

    def test_catalog_is_a_copy(self) -> None:
        cat = connector_catalog()
        cat[0]["maturity"] = "MUTATED"
        self.assertNotEqual(connector_catalog()[0]["maturity"], "MUTATED")

    def test_maturity_is_honest(self) -> None:
        by_id = {c["id"]: c for c in connector_catalog()}
        self.assertEqual(by_id["zabbix"]["maturity"], "verified")
        self.assertEqual(by_id["fleet"]["maturity"], "verified")
        self.assertEqual(by_id["wazuh"]["maturity"], "scaffold")


class BuildConnectorsTest(unittest.TestCase):
    def test_pull_not_configured_lists_missing_env(self) -> None:
        cards = {c["id"]: c for c in build_connectors({}, env={})}
        z = cards["zabbix"]
        self.assertFalse(z["configured"])
        self.assertEqual(z["state"], "not_configured")
        self.assertIn("MORI_ENABLE_ZABBIX", z["missing_env"])
        self.assertIn("MORI_ZABBIX_API_URL", z["missing_env"])

    def test_zabbix_token_satisfies_credentials(self) -> None:
        env = {"MORI_ENABLE_ZABBIX": "true", "MORI_ZABBIX_API_URL": "https://z/api",
                "MORI_ZABBIX_API_TOKEN": "t"}
        z = {c["id"]: c for c in build_connectors({}, env)}["zabbix"]
        self.assertTrue(z["configured"])
        self.assertEqual(z["missing_env"], [])
        self.assertEqual(z["state"], "configured")   # 설정됐지만 아직 수집 데이터 없음

    def test_zabbix_user_password_pair_satisfies(self) -> None:
        env = {"MORI_ENABLE_ZABBIX": "1", "MORI_ZABBIX_API_URL": "https://z/api",
                "MORI_ZABBIX_USER": "u", "MORI_ZABBIX_PASSWORD": "p"}
        z = {c["id"]: c for c in build_connectors({}, env)}["zabbix"]
        self.assertTrue(z["configured"])

    def test_connected_when_coverage_has_data(self) -> None:
        env = {"MORI_ENABLE_FLEET": "true", "MORI_FLEET_API_URL": "https://f",
                "MORI_FLEET_API_TOKEN": "t"}
        cov = {"fleet": {"records_collected": 12, "last_success_at": "2026-07-20T00:00:00+00:00",
                          "is_stale": False, "status": "success"}}
        f = {c["id"]: c for c in build_connectors(cov, env)}["fleet"]
        self.assertEqual(f["state"], "connected")
        self.assertEqual(f["records_collected"], 12)

    def test_push_connector_waits_without_data(self) -> None:
        t = {c["id"]: c for c in build_connectors({}, env={})}["trivy"]
        # push 커넥터는 서버 env 필수값이 없으므로 configured=True, 데이터 없으면 waiting.
        self.assertTrue(t["configured"])
        self.assertEqual(t["state"], "waiting")
        self.assertFalse(t["testable"])


class ChecklistTest(unittest.TestCase):
    def test_all_pending_next_is_first(self) -> None:
        cl = build_checklist({})
        self.assertEqual(cl["done_count"], 0)
        self.assertEqual(cl["total"], 5)
        self.assertFalse(cl["complete"])
        self.assertEqual(cl["next_step"], "connect_source")

    def test_partial_progress_next_skips_done(self) -> None:
        cl = build_checklist({"source_connected": True, "alerts_triaged": True})
        self.assertEqual(cl["done_count"], 2)
        self.assertEqual(cl["next_step"], "link_evidence")

    def test_all_done_complete(self) -> None:
        cl = build_checklist({
            "source_connected": True, "alerts_triaged": True, "control_evidence": True,
            "privacy_scanned": True, "bundle_exported": True,
        })
        self.assertTrue(cl["complete"])
        self.assertIsNone(cl["next_step"])


class ScanSetupTest(unittest.TestCase):
    def test_free_is_default(self) -> None:
        s = build_scan_setup("", audience="mori-ingest")
        self.assertTrue(s["free"])
        self.assertEqual(s["default_scanner"], "semgrep")
        # 유료(Claude)는 선택 업그레이드로만 표기 — 기본 경로가 아니어야 한다.
        self.assertIn("paid_upgrade", s)

    def test_not_ready_without_public_url(self) -> None:
        s = build_scan_setup("")
        self.assertFalse(s["ready"])
        url_secret = next(x for x in s["github_secrets"] if x["name"] == "MORI_INGEST_URL")
        self.assertTrue(url_secret["required"])
        self.assertIsNone(url_secret["value"])

    def test_ready_with_public_url_fills_secret(self) -> None:
        s = build_scan_setup("https://mori.example", audience="aud")
        self.assertTrue(s["ready"])
        self.assertEqual(s["ingest_url"], "https://mori.example")
        self.assertEqual(s["audience"], "aud")
        url_secret = next(x for x in s["github_secrets"] if x["name"] == "MORI_INGEST_URL")
        self.assertEqual(url_secret["value"], "https://mori.example")

    def test_token_optional(self) -> None:
        s = build_scan_setup("https://m", ingest_token_configured=True)
        tok = next(x for x in s["github_secrets"] if x["name"] == "MORI_INGEST_TOKEN")
        self.assertFalse(tok["required"])
        self.assertTrue(s["ingest_token_configured"])


if __name__ == "__main__":
    unittest.main()
