"""
Unit tests for Prometheus Metrics API Endpoint.
"""

import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from ml_engine.api.server import app

class TestPrometheusMetricsAPI(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_root_prometheus_metrics_endpoint(self):
        """Test GET /metrics returns plain text Prometheus format."""
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.headers["content-type"])
        self.assertIn("ebpf_events_ingested_total", response.text)
        self.assertIn("ebpf_telemetry_throughput_eps", response.text)

    def test_api_v1_prometheus_metrics_endpoint(self):
        """Test GET /api/v1/metrics returns plain text Prometheus format."""
        response = self.client.get("/api/v1/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/plain", response.headers["content-type"])
        self.assertIn("ebpf_active_pid_windows", response.text)

if __name__ == "__main__":
    unittest.main()
