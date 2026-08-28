"""
Unit Test Suite for Phase 4 FastAPI REST Service Endpoints.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from ml_engine.api.server import app
from ml_engine.api.routes import set_api_dependencies
from ml_engine.storage import DatabaseManager, ThreatAlertRecord, ActiveBlockRecord
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot


import tempfile
import shutil

class TestFastAPIRoutes(unittest.TestCase):
    """Unit tests for FastAPI REST endpoints using TestClient."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_api_")
        cls.duckdb_path = Path(cls.temp_dir) / "test_telemetry.db"
        cls.sqlite_path = Path(cls.temp_dir) / "test_sec_audit.db"
        cls.db_mgr = DatabaseManager(duckdb_path=cls.duckdb_path, sqlite_path=cls.sqlite_path)
        cls.copilot = LLMSecurityCopilot(api_key="", base_url="")
        set_api_dependencies(db_mgr=cls.db_mgr, copilot=cls.copilot)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.db_mgr.stop()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_health_endpoint(self):
        """Test GET /api/v1/health."""
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["duckdb_connected"])

    def test_metrics_summary_endpoint(self):
        """Test GET /api/v1/metrics/summary."""
        response = self.client.get("/api/v1/metrics/summary")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_events_ingested", data)
        self.assertIn("copilot_status", data)

    def test_alerts_endpoint(self):
        """Test GET /api/v1/alerts."""
        # Insert mock alert
        alert = ThreatAlertRecord(
            pid=5555,
            comm="test_threat",
            exe_path="/tmp/test_threat",
            threat_name="RANSOMWARE",
            confidence=0.99,
            consensus_agreed=True,
            action_taken="BLOCK_PID",
            rf_threat="RANSOMWARE",
            xgb_threat="RANSOMWARE",
            iso_anomaly=True,
        )
        self.db_mgr.sqlite.insert_alert(alert)

        response = self.client.get("/api/v1/alerts?limit=10")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("alerts", data)
        self.assertGreater(data["count"], 0)



    def test_copilot_chat_endpoint(self):
        """Test POST /api/v1/copilot/chat."""
        response = self.client.post(
            "/api/v1/copilot/chat",
            json={"prompt": "What security mitigations are active?"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("response", data)
        self.assertIn("provider", data)

    def test_duckdb_telemetry_query_endpoint(self):
        """Test POST /api/v1/telemetry/query (DuckDB SQL analytics)."""
        response = self.client.post(
            "/api/v1/telemetry/query",
            json={"sql": "SELECT COUNT(*) as total_rows FROM telemetry_events"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("rows", data)


if __name__ == "__main__":
    unittest.main()
