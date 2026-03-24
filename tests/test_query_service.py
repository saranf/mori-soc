import csv
import io
import unittest
from datetime import datetime, timedelta, timezone

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.models import Alert, Host, HostAlias, HostObservation, QueryResult, Vulnerability
from mori_soc.services.query_service import InMemoryQueryStore, QueryService, query_response_to_csv
from mori_soc.services.views import (
    host_risk_summary_view,
    host_timeline_view,
    latest_host_status_view,
)


def _make_store(now: datetime) -> InMemoryQueryStore:
    return InMemoryQueryStore(
        hosts=[
            Host(host_id="host-1", hostname="mbp-01", status="online", risk_score=20, last_seen_at=now),
            Host(host_id="host-2", hostname="mbp-02", status="offline", risk_score=5, last_seen_at=now - timedelta(hours=3)),
            Host(host_id="host-3", hostname="srv-01", status="unknown", risk_score=0, last_seen_at=now - timedelta(hours=10)),
        ],
        alerts=[
            Alert(
                alert_id="a-1",
                source="wazuh",
                host_id="host-1",
                severity="high",
                observed_at=now - timedelta(hours=1),
                message="suspicious login attempt",
                rule_name="sshd_auth_failed",
            ),
            Alert(
                alert_id="a-2",
                source="wazuh",
                host_id="host-1",
                severity="critical",
                observed_at=now - timedelta(minutes=30),
                message="login failure spike",
                rule_name="pam_failed_login",
            ),
            Alert(
                alert_id="a-3",
                source="zabbix",
                host_id="host-2",
                severity="medium",
                observed_at=now - timedelta(hours=2),
                message="agent timeout error",
                rule_name="zabbix_agent_timeout",
            ),
        ],
        vulnerabilities=[
            Vulnerability(vuln_id="v-1", host_id="host-1", source="fleet", severity="high", detected_at=now - timedelta(days=1)),
            Vulnerability(vuln_id="v-2", host_id="host-1", source="trivy", severity="critical", detected_at=now - timedelta(hours=3)),
            Vulnerability(vuln_id="v-3", host_id="host-2", source="trivy", severity="medium", detected_at=now - timedelta(days=2)),
        ],
        query_results=[
            QueryResult(
                query_result_id="q-1",
                host_id="host-1",
                source="fleet",
                observed_at=now - timedelta(minutes=50),
                query_name="system_info",
                result_json={"hostname": "mbp-01"},
            ),
            QueryResult(
                query_result_id="q-2",
                host_id="host-1",
                source="fleet",
                observed_at=now - timedelta(minutes=20),
                query_name="disk_encryption",
                result_json={"encrypted": "1"},
            ),
        ],
        observations=[
            HostObservation(
                observation_id="o-1",
                source="fleet",
                host_id="host-1",
                observation_type="status",
                metric_name="fleet_status",
                metric_value="ok",
                observed_at=now - timedelta(minutes=30),
            ),
            HostObservation(
                observation_id="o-2",
                source="zabbix",
                host_id="host-2",
                observation_type="error",
                metric_name="agent_error",
                metric_value="timeout",
                observed_at=now - timedelta(hours=1),
            ),
        ],
        host_aliases=[
            HostAlias(alias_id="al-1", host_id="host-1", source="fleet",  alias_type="uuid",     alias_value="mbp-01"),
            HostAlias(alias_id="al-2", host_id="host-1", source="wazuh",  alias_type="agent_id", alias_value="001"),
            HostAlias(alias_id="al-3", host_id="host-2", source="zabbix", alias_type="hostname",  alias_value="mbp-02"),
            # host-3 has no aliases at all → unmapped
        ],
    )


class QueryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(tz=timezone.utc)
        self.store = _make_store(self.now)
        self.service = QueryService(self.store)

    # ------------------------------------------------------------------
    # 기존 질의 1~5
    # ------------------------------------------------------------------

    def test_alert_summary(self) -> None:
        response = self.service.execute(QueryRequest(intent="alert_summary", scope=QueryScope(time_range="24h")))
        self.assertIn("2건", response.summary)
        self.assertEqual(len(response.evidence), 2)

    def test_alert_summary_respects_source_filter(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="alert_summary", scope=QueryScope(time_range="24h", source="wazuh", severity="high"))
        )
        self.assertEqual(response.meta["count"], 1)
        self.assertTrue(all(e.source == "wazuh" for e in response.evidence))

    def test_offline_hosts(self) -> None:
        response = self.service.execute(QueryRequest(intent="offline_hosts", scope=QueryScope(time_range="1h")))
        self.assertIn("1대", response.summary)
        self.assertEqual(response.evidence[0].record_id, "host-2")

    def test_top_vulnerable_hosts_respects_limit(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="top_vulnerable_hosts", scope=QueryScope(time_range="7d"), filters={"limit": 1})
        )
        self.assertEqual(response.meta["count"], 2)
        self.assertEqual(response.meta["limit"], 1)
        self.assertEqual(len(response.evidence), 1)
        self.assertEqual(response.evidence[0].record_id, "host-1")

    def test_new_high_vulns_respects_source_filter(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="new_high_vulns", scope=QueryScope(time_range="7d", source="trivy"))
        )
        ids = [e.record_id for e in response.evidence]
        self.assertEqual(response.meta["count"], 1)
        self.assertEqual(ids, ["v-2"])

    def test_host_timeline_by_hostname(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_timeline", scope=QueryScope(time_range="24h", hostname="mbp-01"))
        )
        self.assertEqual(response.meta["host_id"], "host-1")
        self.assertGreaterEqual(len(response.evidence), 3)

    # ------------------------------------------------------------------
    # 질의 6: host_wazuh_alerts
    # ------------------------------------------------------------------

    def test_host_wazuh_alerts_found(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_wazuh_alerts", scope=QueryScope(time_range="24h", host_id="host-1"))
        )
        self.assertEqual(response.meta["count"], 2)
        self.assertTrue(all(e.source == "wazuh" for e in response.evidence))

    def test_host_wazuh_alerts_missing_host(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_wazuh_alerts", scope=QueryScope(time_range="24h"))
        )
        self.assertEqual(response.meta["count"], 0)
        self.assertEqual(response.evidence, [])

    # ------------------------------------------------------------------
    # 질의 7: host_fleet_queries
    # ------------------------------------------------------------------

    def test_host_fleet_queries_found(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_fleet_queries", scope=QueryScope(time_range="24h", host_id="host-1"))
        )
        self.assertEqual(response.meta["count"], 2)
        self.assertTrue(all(e.source == "fleet" for e in response.evidence))

    def test_host_fleet_queries_missing_host(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_fleet_queries", scope=QueryScope(time_range="24h"))
        )
        self.assertEqual(response.meta["count"], 0)

    # ------------------------------------------------------------------
    # 질의 8: new_high_vulns
    # ------------------------------------------------------------------

    def test_new_high_vulns_7d(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="new_high_vulns", scope=QueryScope(time_range="7d"))
        )
        # v-1(high, 1d ago) + v-2(critical, 3h ago) 모두 7d 안에 포함
        self.assertEqual(response.meta["count"], 2)

    def test_new_high_vulns_excludes_medium(self) -> None:
        # v-3(medium) 은 high+ 아니므로 제외
        response = self.service.execute(
            QueryRequest(intent="new_high_vulns", scope=QueryScope(time_range="7d"))
        )
        ids = [e.record_id for e in response.evidence]
        self.assertNotIn("v-3", ids)

    # ------------------------------------------------------------------
    # 질의 9: risky_hosts
    # ------------------------------------------------------------------

    def test_risky_hosts_includes_alert_and_offline(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="risky_hosts", scope=QueryScope(time_range="24h"))
        )
        ids = [e.record_id for e in response.evidence]
        self.assertIn("host-1", ids)   # high/critical alert 보유
        self.assertIn("host-2", ids)   # offline 상태
        self.assertIn("host-3", ids)   # unknown 상태

    # ------------------------------------------------------------------
    # 질의 10: unmapped_assets
    # ------------------------------------------------------------------

    def test_unmapped_assets_detects_missing_source(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="unmapped_assets", scope=QueryScope(time_range="7d"))
        )
        ids = [e.record_id for e in response.evidence]
        # host-1: fleet+wazuh만 있음 → zabbix 없으므로 미매핑
        self.assertIn("host-1", ids)
        # host-2: zabbix만 있음 → fleet+wazuh 없으므로 미매핑
        self.assertIn("host-2", ids)
        # host-3: alias 전혀 없음 → 미매핑
        self.assertIn("host-3", ids)

    # ------------------------------------------------------------------
    # 질의 11: login_failure_spike
    # ------------------------------------------------------------------

    def test_login_failure_spike_detects_keywords(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="login_failure_spike", scope=QueryScope(time_range="24h"))
        )
        # a-1(rule:sshd_auth_failed), a-2(rule:pam_failed_login) → host-1
        self.assertGreaterEqual(response.meta["count"], 1)
        ids = [e.record_id for e in response.evidence]
        self.assertIn("host-1", ids)

    # ------------------------------------------------------------------
    # 질의 12: collection_errors
    # ------------------------------------------------------------------

    def test_collection_errors_detects_error_observations(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="collection_errors", scope=QueryScope(time_range="24h"))
        )
        # o-2(observation_type="error") + a-3(rule_name 에 "timeout") → host-2
        ids = [e.record_id for e in response.evidence]
        self.assertIn("host-2", ids)

    def test_query_response_to_csv_flattens_rows(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_wazuh_alerts", scope=QueryScope(time_range="24h", host_id="host-1"))
        )
        csv_text = query_response_to_csv(response)
        rows = list(csv.DictReader(io.StringIO(csv_text)))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["filter_host_id"], "host-1")
        self.assertEqual(rows[0]["meta_host_id"], "host-1")
        self.assertEqual(rows[0]["evidence_source"], "wazuh")
        self.assertIn("호스트 host-1", rows[0]["query_summary"])

    def test_query_response_to_csv_writes_empty_evidence_row(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_wazuh_alerts", scope=QueryScope(time_range="24h"))
        )
        csv_text = query_response_to_csv(response)
        rows = list(csv.DictReader(io.StringIO(csv_text)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_source"], "")
        self.assertEqual(rows[0]["evidence_record_id"], "")


# ---------------------------------------------------------------------------
# 뷰 집계 테스트
# ---------------------------------------------------------------------------


class ViewsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(tz=timezone.utc)
        self.store = _make_store(self.now)

    def test_latest_host_status_view_returns_all_hosts(self) -> None:
        rows = latest_host_status_view(self.store)
        self.assertEqual(len(rows), 3)
        by_id = {r.host_id: r for r in rows}
        self.assertIsNotNone(by_id["host-1"].last_alert_at)
        self.assertIsNone(by_id["host-3"].last_alert_at)

    def test_host_risk_summary_view_sorted_by_risk(self) -> None:
        rows = host_risk_summary_view(self.store)
        self.assertEqual(len(rows), 3)
        # host-1 이 risk_score=20 으로 1위
        self.assertEqual(rows[0].host_id, "host-1")
        self.assertEqual(rows[0].alert_count_24h, 2)
        self.assertEqual(rows[0].vuln_count, 2)

    def test_host_timeline_view_merges_all_entity_types(self) -> None:
        entries = host_timeline_view(self.store, host_id="host-1")
        types = {e.entity_type for e in entries}
        self.assertIn("alert", types)
        self.assertIn("query_result", types)
        self.assertIn("observation", types)
        # 시간 역순 정렬 확인
        times = [e.observed_at for e in entries]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_host_timeline_view_filters_by_host(self) -> None:
        entries = host_timeline_view(self.store, host_id="host-2")
        self.assertTrue(all(e.host_id == "host-2" for e in entries))


if __name__ == "__main__":
    unittest.main()