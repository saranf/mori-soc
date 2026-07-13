"""관측성 메트릭 + health liveness/readiness(#40)."""
from __future__ import annotations

import importlib.util
import os
import unittest
from unittest.mock import patch

from mori_soc.api.metrics import Metrics

FASTAPI_AVAILABLE = importlib.util.find_spec("fastapi") is not None


class MetricsUnitTests(unittest.TestCase):
    def test_render_counts_and_errors(self) -> None:
        m = Metrics()
        m.observe("GET", 200, 0.01, "/ui")
        m.observe("GET", 200, 0.02, "/ui")
        m.observe("POST", 500, 0.05, "/ingest/trivy")
        out = m.render()
        self.assertIn('mori_http_requests_total{method="GET",status="200"} 2', out)
        self.assertIn("mori_errors_total 1", out)          # 5xx 1건
        self.assertIn("mori_ingest_requests_total 1", out)  # /ingest 1건


@unittest.skipUnless(FASTAPI_AVAILABLE, "requires fastapi")
class HealthMetricsEndpointTests(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient

        from mori_soc.api.server import create_app
        from mori_soc.services.query_service import InMemoryQueryStore, QueryService
        with patch.dict(os.environ, {"MORI_DEMO_SEED": "0", "MORI_AUTH_ENABLED": "1"}, clear=False):
            return TestClient(create_app(QueryService(InMemoryQueryStore())))

    def test_liveness_always_ok_without_auth(self) -> None:
        r = self._client().get("/health/live")   # 미인증도 접근 가능
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")

    def test_metrics_public_and_prometheus_format(self) -> None:
        c = self._client()
        c.get("/health/live")
        r = c.get("/metrics")
        self.assertEqual(r.status_code, 200)
        self.assertIn("mori_http_requests_total", r.text)
        self.assertIn("text/plain", r.headers["content-type"])


if __name__ == "__main__":
    unittest.main()
