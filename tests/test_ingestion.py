import unittest
from datetime import datetime, timezone

from mori_soc.api.contracts import QueryRequest, QueryScope
from mori_soc.collectors import FleetLogCollector
from mori_soc.repositories import InMemoryRepository
from mori_soc.services import CollectorIngestionService, EnvelopeEntityMapper, QueryService


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
        self.assertEqual(len(snapshot.host_aliases), 1)
        self.assertEqual(len(snapshot.observations), 1)
        self.assertEqual(len(snapshot.query_results), 1)

        query_service = QueryService(repository.to_query_store())
        response = query_service.execute(QueryRequest(intent="host_timeline", scope=QueryScope(time_range="24h", host_id="host-1")))
        self.assertEqual(response.meta["host_id"], "host-1")
        self.assertGreaterEqual(len(response.evidence), 2)


if __name__ == "__main__":
    unittest.main()