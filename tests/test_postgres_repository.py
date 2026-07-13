import importlib.util
import unittest
from datetime import datetime, timezone

from mori_soc.models import Alert, Host, SourceSync
from mori_soc.repositories import (
    PostgresRepository,
    RepositorySnapshot,
    snapshot_to_query_store,
)

PSYCOPG_AVAILABLE = importlib.util.find_spec("psycopg") is not None


class SnapshotToQueryStoreTests(unittest.TestCase):
    def test_snapshot_to_query_store_preserves_entities(self) -> None:
        now = datetime.now(tz=timezone.utc)
        snapshot = RepositorySnapshot(
            hosts=[Host(host_id="host-1", hostname="mbp-01", status="online", last_seen_at=now)],
            alerts=[Alert(alert_id="alert-1", source="wazuh", observed_at=now, message="test")],
            source_syncs=[SourceSync(source="zabbix", status="success", last_sync_at=now)],
        )
        store = snapshot_to_query_store(snapshot)
        self.assertEqual(store.hosts[0].host_id, "host-1")
        self.assertEqual(store.alerts[0].alert_id, "alert-1")
        self.assertEqual(store.source_syncs[0].source, "zabbix")


class PostgresRepositoryImportGuardTests(unittest.TestCase):
    def test_constructor_requires_psycopg_when_missing(self) -> None:
        if PSYCOPG_AVAILABLE:
            self.skipTest("psycopg is installed in this environment")
        with self.assertRaises(RuntimeError):
            PostgresRepository("postgresql://user:pass@localhost:5432/mori")