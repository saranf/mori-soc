import unittest
from datetime import datetime, timedelta, timezone

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.models import Alert, Host, HostObservation, QueryResult, Vulnerability
from mori_soc.services.query_service import InMemoryQueryStore, QueryService


class QueryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        now = datetime.now(tz=timezone.utc)
        self.store = InMemoryQueryStore(
            hosts=[
                Host(host_id="host-1", hostname="mbp-01", status="online", last_seen_at=now),
                Host(host_id="host-2", hostname="mbp-02", status="offline", last_seen_at=now - timedelta(hours=3)),
            ],
            alerts=[
                Alert(
                    alert_id="a-1",
                    source="wazuh",
                    host_id="host-1",
                    severity="high",
                    observed_at=now - timedelta(hours=1),
                    message="suspicious login",
                )
            ],
            vulnerabilities=[
                Vulnerability(vuln_id="v-1", host_id="host-1", severity="high", detected_at=now - timedelta(days=1)),
                Vulnerability(vuln_id="v-2", host_id="host-1", severity="medium", detected_at=now - timedelta(hours=3)),
            ],
            query_results=[
                QueryResult(
                    query_result_id="q-1",
                    host_id="host-1",
                    observed_at=now - timedelta(minutes=50),
                    query_name="system_info",
                    result_json={"hostname": "mbp-01"},
                )
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
                )
            ],
        )
        self.service = QueryService(self.store)

    def test_alert_summary(self) -> None:
        response = self.service.execute(QueryRequest(intent="alert_summary", scope=QueryScope(time_range="24h")))
        self.assertIn("1건", response.summary)
        self.assertEqual(len(response.evidence), 1)
        self.assertEqual(response.evidence[0].record_id, "a-1")

    def test_offline_hosts(self) -> None:
        response = self.service.execute(QueryRequest(intent="offline_hosts", scope=QueryScope(time_range="1h")))
        self.assertIn("1대", response.summary)
        self.assertEqual(response.evidence[0].record_id, "host-2")

    def test_host_timeline_by_hostname(self) -> None:
        response = self.service.execute(
            QueryRequest(intent="host_timeline", scope=QueryScope(time_range="24h", hostname="mbp-01"))
        )
        self.assertEqual(response.meta["host_id"], "host-1")
        self.assertGreaterEqual(len(response.evidence), 3)


if __name__ == "__main__":
    unittest.main()