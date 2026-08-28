"""
Unit tests for DuckDB Materialized/Analytical Views and Export Engine.
"""

import unittest
from pathlib import Path
import tempfile
import os
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.storage.db_manager import DuckDBManager

class TestDuckDBViewsAndExport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_telemetry.db"
        self.duckdb_mgr = DuckDBManager(db_path=self.db_path)

        # Seed sample telemetry event
        events = [{
            "event_type": "SYS_EXEC",
            "timestamp_ns": 1700000000000000000,
            "pid": 1234,
            "ppid": 1,
            "uid": 1000,
            "gid": 1000,
            "comm": "curl",
            "exe_path": "/usr/bin/curl",
            "parent_comm": "bash",
            "syscall_id": 59,
            "file_path": "/etc/passwd",
            "bytes_written": 0,
            "bytes_read": 1024,
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
        }]
        self.duckdb_mgr.insert_telemetry_batch(events)

    def tearDown(self):
        self.duckdb_mgr.close()
        self.temp_dir.cleanup()

    def test_analytical_views_exist(self):
        """Verify v_top_processes and v_syscall_breakdown views work correctly."""
        res = self.duckdb_mgr.query_sql("SELECT * FROM v_top_processes")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["comm"], "curl")

    def test_export_query_csv(self):
        """Test exporting query results to CSV format."""
        out_csv = Path(self.temp_dir.name) / "export.csv"
        res_path = self.duckdb_mgr.export_query(
            sql="SELECT comm, exe_path FROM v_top_processes",
            format_type="csv",
            output_path=out_csv,
        )
        self.assertTrue(Path(res_path).exists())
        with open(res_path, "r") as f:
            content = f.read()
            self.assertIn("curl", content)

    def test_export_query_parquet(self):
        """Test exporting query results to Parquet format."""
        out_parquet = Path(self.temp_dir.name) / "export.parquet"
        res_path = self.duckdb_mgr.export_query(
            sql="SELECT * FROM telemetry_events",
            format_type="parquet",
            output_path=out_parquet,
        )
        self.assertTrue(Path(res_path).exists())

if __name__ == "__main__":
    unittest.main()
