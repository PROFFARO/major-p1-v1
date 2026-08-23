"""
Unit Test Suite for Phase 4 Dual-Engine Storage Layer (DuckDB + SQLite WAL + Async Batch Queue).
"""

import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml_engine.storage.db_manager import (
    DatabaseManager,
    DuckDBManager,
    SQLiteWALManager,
    AsyncBatchDatabaseWriter,
)
from ml_engine.storage.models import (
    TelemetryEventRecord,
    FeatureWindowRecord,
    ThreatAlertRecord,
    MitigationAuditRecord,
    ActiveBlockRecord,
    LLMChatRecord,
)


class TestDualEngineStorage(unittest.TestCase):
    """Unit tests for DuckDB, SQLite WAL, and Async Batch Queue."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_db_")
        self.duckdb_path = Path(self.temp_dir) / "test_telemetry.db"
        self.sqlite_path = Path(self.temp_dir) / "test_sec_audit.db"

        self.db_mgr = DatabaseManager(
            duckdb_path=self.duckdb_path,
            sqlite_path=self.sqlite_path,
        )

    def tearDown(self):
        self.db_mgr.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_duckdb_batch_insert_and_query(self):
        """Test DuckDB columnar table creation, 1,000 event batch insert, and fast SQL query."""
        duck_mgr = self.db_mgr.duckdb
        events = []
        for i in range(1000):
            events.append({
                "event_type": "SYS_EXEC",
                "timestamp_ns": 1700000000000 + i,
                "pid": 5000 + (i % 10),
                "ppid": 1,
                "uid": 1000,
                "gid": 1000,
                "comm": f"process_{i % 5}",
                "exe_path": f"/usr/bin/process_{i % 5}",
                "syscall_id": 59,
                "bytes_written": i * 10,
                "bytes_read": i * 5,
            })

        count = duck_mgr.insert_telemetry_batch(events)
        self.assertEqual(count, 1000)

        # SQL Query Test
        res = duck_mgr.query_sql("SELECT pid, COUNT(*) as cnt FROM telemetry_events GROUP BY pid ORDER BY pid")
        self.assertEqual(len(res), 10)
        self.assertEqual(res[0]["cnt"], 100)

    def test_duckdb_feature_window_record(self):
        """Test inserting 12-dimensional feature vector window record into DuckDB."""
        duck_mgr = self.db_mgr.duckdb
        rec = FeatureWindowRecord(
            pid=9999,
            window_start_ns=1000,
            window_end_ns=2000,
            event_count=50,
            vector=[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0],
            rf_prediction="RANSOMWARE",
            xgb_prediction="RANSOMWARE",
            iso_score=-0.85,
            agreed_threat="RANSOMWARE",
            confidence=0.98,
        )
        duck_mgr.insert_feature_window(rec)

        res = duck_mgr.query_sql("SELECT * FROM feature_windows WHERE pid = 9999")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["agreed_threat"], "RANSOMWARE")
        self.assertEqual(len(res[0]["vector"]), 12)

    def test_sqlite_wal_threat_alerts(self):
        """Test inserting and querying threat alerts in SQLite WAL database."""
        sqlite_mgr = self.db_mgr.sqlite
        alert = ThreatAlertRecord(
            pid=8888,
            comm="malware_bin",
            exe_path="/tmp/malware_bin",
            threat_name="RANSOMWARE",
            confidence=0.95,
            consensus_agreed=True,
            action_taken="BLOCK_PID",
            rf_threat="RANSOMWARE",
            xgb_threat="RANSOMWARE",
            iso_anomaly=True,
        )
        alert_id = sqlite_mgr.insert_alert(alert)
        self.assertGreater(alert_id, 0)

        alerts = sqlite_mgr.get_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["pid"], 8888)
        self.assertEqual(alerts[0]["threat_name"], "RANSOMWARE")

    def test_sqlite_wal_active_blocklist(self):
        """Test active kernel blocklist upsert and removal in SQLite WAL."""
        sqlite_mgr = self.db_mgr.sqlite
        block = ActiveBlockRecord(
            pid=7777,
            threat_name="REVERSE_SHELL",
            is_permanent=True,
            details="Manual LSM block",
        )
        sqlite_mgr.upsert_active_block(block)

        active = sqlite_mgr.get_active_blocks()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["pid"], 7777)

        # Remove block
        removed = sqlite_mgr.remove_active_block(7777)
        self.assertTrue(removed)
        active_after = sqlite_mgr.get_active_blocks()
        self.assertEqual(len(active_after), 0)

    def test_async_batch_writer(self):
        """Test AsyncBatchDatabaseWriter micro-batch flushing under high event volume."""
        self.db_mgr.start()
        writer = self.db_mgr.batch_writer

        for i in range(250):
            writer.enqueue({
                "event_type": "SYS_WRITE",
                "timestamp_ns": 1800000000000 + i,
                "pid": 6000,
                "bytes_written": 100,
            })

        # Wait briefly for worker flush
        time.sleep(0.5)
        self.db_mgr.stop()

        total = self.db_mgr.duckdb.get_event_count()
        self.assertEqual(total, 250)


if __name__ == "__main__":
    unittest.main()
