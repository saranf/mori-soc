import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.collectors import FleetLogCollector, WazuhAlertCollector, ZabbixEventCollector
from mori_soc.repositories import InMemoryRepository
from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper, QueryService
from mori_soc.worker import run_ingestion_cycle


class IngestionFlowTests(unittest.TestCase):
    def test_fleet_ingestion_populates_repository_and_query_store(self) -> None:
        now = datetime.now(tz=timezone.utc)
        collector = FleetLogCollector(
            status_lines=[
                '{"hostIdentifier":"mbp-01","timestamp":"'
                + now.isoformat().replace("+00:00", "Z")
                + '","severity":"2","message":"heartbeat ok"}'
            ],
            result_lines=[
                '{"name":"system_info","hostIdentifier":"mbp-01","unixTime":'
                + str(int(now.timestamp()))
                + ',"columns":{"hostname":"mbp-01","platform":"darwin","uuid":"abc"}}'
            ],
        )
        mapper = EnvelopeEntityMapper(alias_map={"mbp-01": "host-1"})
        repository = InMemoryRepository()
        service = CollectorIngestionService(mapper, repository)

        report = service.ingest_collector(collector)
        snapshot = repository.snapshot()

        self.assertEqual(report.records_collected, 2)
        self.assertEqual(report.envelopes_normalized, 2)
        self.assertEqual(len(snapshot.hosts), 1)
        self.assertEqual(snapshot.hosts[0].host_id, "host-1")
        self.assertEqual(snapshot.hosts[0].platform, "darwin")
        alias_values = {alias.alias_value for alias in snapshot.host_aliases}
        self.assertEqual(alias_values, {"mbp-01", "abc"})
        self.assertEqual(len(snapshot.observations), 1)
        self.assertEqual(len(snapshot.query_results), 1)

        query_service = QueryService(repository.to_query_store())
        response = query_service.execute(QueryRequest(intent="host_timeline", scope=QueryScope(time_range="24h", host_id="host-1")))
        self.assertEqual(response.meta["host_id"], "host-1")
        self.assertGreaterEqual(len(response.evidence), 2)

    def test_multi_source_ingestion_preserves_secondary_aliases_and_units(self) -> None:
        now = datetime.now(tz=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper(alias_map={"mbp-01": "host-1"})
        service = CollectorIngestionService(mapper, repository)

        wazuh = WazuhAlertCollector(
            alert_lines=[
                '{"id":"evt-1","timestamp":"'
                + now.isoformat().replace("+00:00", "Z")
                + '","agent":{"id":"001","name":"mbp-01","ip":"10.0.0.5"},'
                + '"rule":{"id":"5710","level":12,"description":"sshd authentication failed"},'
                + '"full_log":"Failed password for root"}'
            ]
        )
        zabbix = ZabbixEventCollector(
            problem_lines=[
                '{"eventid":"12345","clock":"'
                + str(int(now.timestamp()))
                + '","hosts":[{"hostid":"10001","name":"mbp-01"}],'
                + '"name":"Agent timeout","severity":"4","triggerid":"99001"}'
            ],
            item_lines=[
                '{"itemid":"22001","clock":"'
                + str(int(now.timestamp()))
                + '","value":"85.4","hosts":[{"hostid":"10001","name":"mbp-01"}],'
                + '"item_name":"CPU utilization","units":"%"}'
            ],
        )

        service.ingest_collector(wazuh)
        service.ingest_collector(zabbix)
        snapshot = repository.snapshot()

        alias_values = {alias.alias_value for alias in snapshot.host_aliases if alias.host_id == "host-1"}
        self.assertTrue({"mbp-01", "001", "10001"}.issubset(alias_values))
        self.assertEqual(len(snapshot.alerts), 2)
        self.assertEqual(snapshot.observations[0].unit, "%")

        query_service = QueryService(repository.to_query_store())
        wazuh_response = query_service.execute(
            QueryRequest(intent="host_wazuh_alerts", scope=QueryScope(time_range="24h", host_id="host-1"))
        )
        self.assertEqual(wazuh_response.meta["count"], 1)

        error_response = query_service.execute(
            QueryRequest(intent="collection_errors", scope=QueryScope(time_range="24h"))
        )
        self.assertIn("host-1", [e.record_id for e in error_response.evidence])

    def test_fleet_ingestion_maps_nested_snapshot_aliases(self) -> None:
        now = datetime.now(tz=timezone.utc)
        collector = FleetLogCollector(
            result_lines=[
                '{"name":"system_info","host_id":42,"decorations":{"hostname":"mbp-02","uuid":"fleet-uuid-2"},'
                '"unixTime":'
                + str(int(now.timestamp()))
                + ',"snapshot":[{"columns":{"hostname":"mbp-02","platform":"darwin","hardware_uuid":"hw-123"}}]}'
            ]
        )
        mapper = EnvelopeEntityMapper(alias_map={"fleet-uuid-2": "host-9"})
        repository = InMemoryRepository()
        service = CollectorIngestionService(mapper, repository)

        report = service.ingest_collector(collector)
        snapshot = repository.snapshot()

        self.assertEqual(report.records_collected, 1)
        self.assertEqual(len(snapshot.hosts), 1)
        self.assertEqual(snapshot.hosts[0].host_id, "host-9")
        self.assertEqual(snapshot.hosts[0].hostname, "mbp-02")
        self.assertEqual(snapshot.hosts[0].platform, "darwin")
        alias_values = {alias.alias_value for alias in snapshot.host_aliases}
        self.assertTrue({"42", "fleet-uuid-2", "hw-123", "mbp-02"}.issubset(alias_values))
        self.assertEqual(snapshot.query_results[0].result_json["rows"][0]["hardware_uuid"], "hw-123")

    def test_zabbix_api_collect_and_worker_cycle_save_source_sync(self) -> None:
        now = datetime.now(tz=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper(alias_map={"srv-01": "host-1"})
        collector = ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="token")

        with patch.object(
            collector,
            "_api_call",
            side_effect=[
                [
                    {
                        "hostid": "20084",
                        "host": "srv-01",
                        "name": "srv-01",
                        "status": "0",
                        "interfaces": [{"ip": "10.0.0.10", "available": "1"}],
                    }
                ],
                [
                    {
                        "eventid": "30001",
                        "clock": str(int(now.timestamp())),
                        "name": "CPU load high",
                        "severity": "4",
                        "objectid": "99001",
                        "hosts": [{"hostid": "20084", "host": "srv-01", "name": "srv-01"}],
                    }
                ],
            ],
        ):
            reports = run_ingestion_cycle(repository, [collector], mapper=mapper, started_at=now)

        snapshot = repository.snapshot()
        self.assertEqual(reports[0].source, "zabbix")
        self.assertEqual(snapshot.source_syncs[0].status, "success")
        self.assertEqual(snapshot.source_syncs[0].records_collected, 2)
        self.assertEqual(snapshot.hosts[0].status, "online")
        self.assertEqual(len(snapshot.alerts), 1)
        self.assertEqual(len(snapshot.observations), 1)


if __name__ == "__main__":
    unittest.main()