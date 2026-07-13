import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.collectors import (
    FleetLogCollector,
    TrivyCollector,
    WazuhAlertCollector,
    ZabbixEventCollector,
)
from mori_soc.repositories import InMemoryRepository
from mori_soc.services import (
    CollectorIngestionService,
    EnvelopeEntityMapper,
    QueryService,
)
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

    def test_asset_buckets_keep_fleet_and_server_sources_separate(self) -> None:
        now = datetime.now(tz=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper()
        service = CollectorIngestionService(mapper, repository)

        fleet = FleetLogCollector(
            result_lines=[
                '{"name":"system_info","hostIdentifier":"shared-01","unixTime":'
                + str(int(now.timestamp()))
                + ',"columns":{"hostname":"shared-01","platform":"darwin"}}'
            ]
        )
        zabbix = ZabbixEventCollector(
            item_lines=[
                '{"itemid":"22001","clock":"'
                + str(int(now.timestamp()))
                + '","value":"85.4","hosts":[{"hostid":"10001","name":"shared-01"}],'
                + '"item_name":"CPU utilization","units":"%"}'
            ]
        )
        trivy = TrivyCollector(
            reports=[
                {
                    "CreatedAt": now.isoformat().replace("+00:00", "Z"),
                    "ArtifactName": "shared-01",
                    "ArtifactType": "filesystem",
                    "Results": [
                        {
                            "Target": "/",
                            "Class": "os-pkgs",
                            "Type": "ubuntu",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-0003",
                                    "PkgName": "openssl",
                                    "InstalledVersion": "1.0.0",
                                    "FixedVersion": "1.0.1",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ],
                }
            ],
            host_aliases=["shared-01"],
            hostname="shared-01",
        )

        service.ingest_collector(fleet)
        service.ingest_collector(zabbix)
        service.ingest_collector(trivy)
        snapshot = repository.snapshot()

        host_ids = {host.host_id for host in snapshot.hosts}
        self.assertEqual(host_ids, {"pc-shared-01", "server-shared-01"})
        self.assertEqual({result.host_id for result in snapshot.query_results}, {"pc-shared-01"})
        self.assertEqual({observation.host_id for observation in snapshot.observations}, {"server-shared-01"})
        self.assertEqual({vuln.host_id for vuln in snapshot.vulnerabilities}, {"server-shared-01"})

    def test_neutral_sources_bridge_to_unique_bucket_match(self) -> None:
        now = datetime.now(tz=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper()
        service = CollectorIngestionService(mapper, repository)

        fleet = FleetLogCollector(
            status_lines=[
                '{"hostIdentifier":"shared-01","timestamp":"'
                + now.isoformat().replace("+00:00", "Z")
                + '","severity":"2","message":"heartbeat ok"}'
            ]
        )
        wazuh = WazuhAlertCollector(
            alert_lines=[
                '{"id":"evt-1","timestamp":"'
                + now.isoformat().replace("+00:00", "Z")
                + '","agent":{"id":"001","name":"shared-01"},'
                + '"rule":{"id":"5710","level":12,"description":"sshd authentication failed"},'
                + '"full_log":"Failed password for root"}'
            ]
        )

        service.ingest_collector(fleet)
        service.ingest_collector(wazuh)
        snapshot = repository.snapshot()

        self.assertEqual({host.host_id for host in snapshot.hosts}, {"pc-shared-01"})
        self.assertEqual(snapshot.alerts[0].host_id, "pc-shared-01")

    def test_neutral_sources_do_not_bridge_when_bucket_match_is_ambiguous(self) -> None:
        now = datetime.now(tz=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper()
        service = CollectorIngestionService(mapper, repository)

        fleet = FleetLogCollector(
            status_lines=[
                '{"hostIdentifier":"shared-01","timestamp":"'
                + now.isoformat().replace("+00:00", "Z")
                + '","severity":"2","message":"heartbeat ok"}'
            ]
        )
        zabbix = ZabbixEventCollector(
            item_lines=[
                '{"itemid":"22001","clock":"'
                + str(int(now.timestamp()))
                + '","value":"85.4","hosts":[{"hostid":"10001","name":"shared-01"}],'
                + '"item_name":"CPU utilization","units":"%"}'
            ]
        )
        wazuh = WazuhAlertCollector(
            alert_lines=[
                '{"id":"evt-1","timestamp":"'
                + now.isoformat().replace("+00:00", "Z")
                + '","agent":{"id":"001","name":"shared-01"},'
                + '"rule":{"id":"5710","level":12,"description":"sshd authentication failed"},'
                + '"full_log":"Failed password for root"}'
            ]
        )

        service.ingest_collector(fleet)
        service.ingest_collector(zabbix)
        service.ingest_collector(wazuh)
        snapshot = repository.snapshot()

        self.assertEqual(
            {host.host_id for host in snapshot.hosts},
            {"pc-shared-01", "server-shared-01", "neutral-shared-01"},
        )
        self.assertEqual(snapshot.alerts[0].host_id, "neutral-shared-01")

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

    def test_zabbix_metric_without_explicit_status_keeps_host_unknown(self) -> None:
        now = datetime.now(tz=timezone.utc)
        collector = ZabbixEventCollector(
            item_lines=[
                '{"itemid":"22001","clock":"'
                + str(int(now.timestamp()))
                + '","value":"85.4","hosts":[{"hostid":"10001","name":"srv-01"}],'
                + '"item_name":"CPU utilization","units":"%"}'
            ]
        )
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper(alias_map={"srv-01": "host-1"})
        service = CollectorIngestionService(mapper, repository)

        service.ingest_collector(collector)
        snapshot = repository.snapshot()

        self.assertEqual(snapshot.hosts[0].host_id, "host-1")
        self.assertEqual(snapshot.hosts[0].status, "unknown")

    def test_trivy_ingestion_does_not_override_explicit_offline_status(self) -> None:
        now = datetime(2026, 3, 24, 10, 0, tzinfo=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper(alias_map={"srv-01": "host-1"})
        service = CollectorIngestionService(mapper, repository)
        zabbix = ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="token")

        with patch.object(
            zabbix,
            "_api_call",
            side_effect=[
                [{"hostid": "20084", "host": "srv-01", "name": "srv-01", "status": "0", "active_available": "2"}],
                [],
            ],
        ):
            service.ingest_collector(zabbix)

        trivy = TrivyCollector(
            reports=[
                {
                    "CreatedAt": now.isoformat().replace("+00:00", "Z"),
                    "ArtifactName": "srv-01",
                    "ArtifactType": "filesystem",
                    "Results": [
                        {
                            "Target": "/",
                            "Class": "os-pkgs",
                            "Type": "ubuntu",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-0001",
                                    "PkgName": "openssl",
                                    "InstalledVersion": "1.0.0",
                                    "FixedVersion": "1.0.1",
                                    "Severity": "CRITICAL",
                                }
                            ],
                        }
                    ],
                }
            ],
            host_aliases=["srv-01"],
            hostname="srv-01",
        )

        service.ingest_collector(trivy)
        snapshot = repository.snapshot()

        self.assertEqual(snapshot.hosts[0].host_id, "host-1")
        self.assertEqual(snapshot.hosts[0].status, "offline")

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
                    }
                ],
                [
                    {
                        "triggerid": "99001",
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

    def test_zabbix_api_collect_uses_inventory_hosts_and_active_availability(self) -> None:
        collector = ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="token")
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_api_call(method: str, params: dict[str, object], *, auth: str | None = None):
            del auth
            calls.append((method, params))
            if method == "host.get":
                return [
                    {
                        "hostid": "20084",
                        "host": "srv-active-01",
                        "name": "srv-active-01",
                        "status": "0",
                        "active_available": "2",
                    }
                ]
            return []

        with patch.object(collector, "_api_call", side_effect=fake_api_call):
            records = list(collector.collect())

        self.assertEqual(calls[0][0], "host.get")
        self.assertIn("active_available", calls[0][1]["output"])
        self.assertNotIn("monitored_hosts", calls[0][1])
        self.assertEqual(records[0].record_type, "host")
        normalized = list(collector.normalize(records[0]))[0]
        self.assertEqual(normalized.normalized["status"], "offline")

    def test_worker_preserves_last_success_metadata_when_sync_fails(self) -> None:
        first_run_at = datetime(2026, 3, 24, 10, 0, tzinfo=timezone.utc)
        second_run_at = datetime(2026, 3, 24, 10, 5, tzinfo=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper(alias_map={"srv-01": "host-1"})
        collector = ZabbixEventCollector(api_url="http://zabbix.example/api_jsonrpc.php", token="token")

        with patch.object(
            collector,
            "_api_call",
            side_effect=[
                [{"hostid": "20084", "host": "srv-01", "name": "srv-01", "status": "0", "interfaces": []}],
                [],
            ],
        ):
            run_ingestion_cycle(repository, [collector], mapper=mapper, started_at=first_run_at)

        first_sync = repository.snapshot().source_syncs[0]

        with patch.object(collector, "_api_call", side_effect=RuntimeError("api down")):
            reports = run_ingestion_cycle(repository, [collector], mapper=mapper, started_at=second_run_at)

        snapshot = repository.snapshot()
        sync = snapshot.source_syncs[0]
        self.assertEqual(reports[0].status, "error")
        self.assertEqual(sync.status, "error")
        self.assertEqual(sync.last_success_at, first_run_at)
        self.assertEqual(sync.last_error_at, second_run_at)
        self.assertEqual(sync.records_collected, first_sync.records_collected)
        self.assertEqual(sync.entities_saved, first_sync.entities_saved)

    def test_trivy_ingestion_saves_vulnerabilities_and_source_sync(self) -> None:
        now = datetime(2026, 3, 24, 10, 0, tzinfo=timezone.utc)
        repository = InMemoryRepository()
        mapper = EnvelopeEntityMapper(alias_map={"srv-01": "host-1"})
        collector = TrivyCollector(
            reports=[
                {
                    "CreatedAt": now.isoformat().replace("+00:00", "Z"),
                    "ArtifactName": "srv-01",
                    "ArtifactType": "filesystem",
                    "Results": [
                        {
                            "Target": "/",
                            "Class": "os-pkgs",
                            "Type": "ubuntu",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2026-0001",
                                    "PkgName": "openssl",
                                    "InstalledVersion": "1.0.0",
                                    "FixedVersion": "1.0.1",
                                    "Severity": "CRITICAL",
                                },
                                {
                                    "VulnerabilityID": "CVE-2026-0002",
                                    "PkgName": "curl",
                                    "InstalledVersion": "8.0.0",
                                    "FixedVersion": "8.0.1",
                                    "Severity": "HIGH",
                                },
                            ],
                        }
                    ],
                }
            ],
            host_aliases=["srv-01", "10.0.0.10"],
            hostname="srv-01",
        )

        reports = run_ingestion_cycle(repository, [collector], mapper=mapper, started_at=now)
        snapshot = repository.snapshot()

        self.assertEqual(reports[0].source, "trivy")
        self.assertEqual(snapshot.source_syncs[0].source, "trivy")
        self.assertEqual(snapshot.source_syncs[0].status, "success")
        self.assertEqual(snapshot.source_syncs[0].records_collected, 2)
        self.assertEqual(len(snapshot.vulnerabilities), 2)
        self.assertEqual({v.source for v in snapshot.vulnerabilities}, {"trivy"})
        self.assertEqual({v.host_id for v in snapshot.vulnerabilities}, {"host-1"})
        alias_values = {alias.alias_value for alias in snapshot.host_aliases if alias.host_id == "host-1"}
        self.assertTrue({"srv-01", "10.0.0.10"}.issubset(alias_values))


if __name__ == "__main__":
    unittest.main()