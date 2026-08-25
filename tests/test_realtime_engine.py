"""
Comprehensive Unit Tests for the Real-Time Streaming Ingestion Engine.

Verifies:
    1. Single event ingestion and throughput stats calculation
    2. StreamingExtractor window completion → ThreatDetector inference pipeline
    3. Dual-model consensus prediction integration
    4. MitigationController action trigger on threat window flush
    5. Subscriber callback registration and notification
    6. Engine start/stop lifecycle and thread safety
"""

import json
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml_engine.inference.realtime_engine import RealtimeIngestionEngine
from ml_engine.feedback.mitigator import MitigationController
from ml_engine.feedback.actions import ActionType, AuditLogger
from ml_engine.models.detector import ThreatDetector


# ─────────────────────────────────────────────────────────────
# Test Helpers & Mock Factory
# ─────────────────────────────────────────────────────────────

def create_mock_detector(rf_threat="RANSOMWARE", xgb_threat="RANSOMWARE", confidence=0.95):
    """Create a mock ThreatDetector with predict_with_consensus behavior."""
    detector = MagicMock(spec=ThreatDetector)
    detector.loaded = True

    detector.predict_with_consensus.return_value = {
        "rf_result": {"threat_id": 1, "threat_name": rf_threat, "confidence": confidence},
        "xgb_result": {"threat_id": 1, "threat_name": xgb_threat, "confidence": confidence},
        "consensus": (rf_threat == xgb_threat),
        "agreed_threat": rf_threat if rf_threat == xgb_threat else "NO_CONSENSUS",
        "anomaly_score": -0.6,
        "is_anomaly": True,
        "threat_id": 1,
        "threat_name": rf_threat if rf_threat == xgb_threat else "NO_CONSENSUS",
        "confidence": confidence,
        "probabilities": {rf_threat: confidence, "BENIGN": 1 - confidence},
        "rf_threat_name": rf_threat,
        "xgb_threat_name": xgb_threat,
    }

    return detector


def create_mock_event(pid=12345, event_type="SYS_EXEC", timestamp_ns=None, comm="test_proc", exe_path="/tmp/test"):
    """Generate a valid BPF telemetry event dictionary."""
    if timestamp_ns is None:
        timestamp_ns = int(time.time() * 1e9)

    return {
        "event_type": event_type,
        "timestamp_ns": timestamp_ns,
        "pid": pid,
        "ppid": 1,
        "uid": 1000,
        "gid": 1000,
        "comm": comm,
        "exe_path": exe_path,
        "parent_comm": "bash",
        "syscall_id": 59,
        "file_path": "/tmp/test",
        "bytes_written": 1024,
        "bytes_read": 512,
        "dst_ip": "192.168.1.100",
        "dst_port": 443,
    }


def make_controller() -> MitigationController:
    """Create a MitigationController with a temp audit log."""
    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    tmp.close()
    audit = AuditLogger(log_path=Path(tmp.name))
    return MitigationController(dry_run=True, audit_logger=audit, enable_background_sweep=False)


# ─────────────────────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────────────────────

import shutil
from ml_engine.storage.db_manager import DatabaseManager

class TestIngestionPipeline(unittest.TestCase):
    """Test telemetry ingestion, feature window extraction, and inference pipeline."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_rt_")
        self.duckdb_path = Path(self.temp_dir) / "test_telemetry.db"
        self.sqlite_path = Path(self.temp_dir) / "test_sec_audit.db"
        self.db_mgr = DatabaseManager(duckdb_path=self.duckdb_path, sqlite_path=self.sqlite_path)

    def tearDown(self):
        self.db_mgr.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_single_event_ingest_updates_stats(self):
        detector = create_mock_detector()
        mitigator = make_controller()
        engine = RealtimeIngestionEngine(detector=detector, mitigator=mitigator, db_manager=self.db_mgr, window_seconds=5.0)

        event = create_mock_event(pid=9999)
        actions = engine.ingest_event(event)

        # Single event should not complete window yet (MIN_EVENTS_PER_WINDOW=10)
        self.assertEqual(len(actions), 0)
        stats = engine.get_stats()
        self.assertEqual(stats["total_events_ingested"], 1)
        self.assertGreater(stats["events_per_second"], 0.0)

    def test_window_completion_triggers_detection_and_mitigation(self):
        detector = create_mock_detector(rf_threat="RANSOMWARE", xgb_threat="RANSOMWARE", confidence=0.95)
        mitigator = make_controller()
        engine = RealtimeIngestionEngine(detector=detector, mitigator=mitigator, db_manager=self.db_mgr, window_seconds=5.0)

        actions = []
        start_ns = int(time.time() * 1e9)
        # Emit 15 events spanning > 5.5 seconds for PID 90001
        for i in range(15):
            ts = start_ns + int(i * 0.4 * 1e9)  # 15 events over 6 seconds
            evt = create_mock_event(pid=90001, timestamp_ns=ts, comm="malware")
            actions.extend(engine.ingest_event(evt))

        # Flush any remaining windows
        actions.extend(engine.flush())

        self.assertGreater(len(actions), 0)
        stats = engine.get_stats()
        self.assertGreater(stats["total_windows_processed"], 0)
        self.assertEqual(stats["total_threats_detected"], 1)
        self.assertIn("RANSOMWARE", stats["threats_by_class"])

    def test_on_detection_callback_invoked(self):
        detector = create_mock_detector(rf_threat="REVERSE_SHELL", xgb_threat="REVERSE_SHELL")
        mitigator = make_controller()

        callback_received = []

        def subscriber_cb(action, threat_res):
            callback_received.append((action, threat_res))

        engine = RealtimeIngestionEngine(
            detector=detector,
            mitigator=mitigator,
            db_manager=self.db_mgr,
            on_detection_callback=subscriber_cb,
            window_seconds=5.0,
        )

        # Send enough events to fill and trigger window flush
        start_ns = int(time.time() * 1e9)
        for i in range(12):
            evt = create_mock_event(pid=7777, timestamp_ns=start_ns + int(i * 0.5 * 1e9), comm="nc")
            engine.ingest_event(evt)

        engine.flush()

        self.assertGreater(len(callback_received), 0)
        action, threat_res = callback_received[0]
        self.assertEqual(action.pid, 7777)
        self.assertEqual(threat_res["rf_threat_name"], "REVERSE_SHELL")


class TestWebSocketMessageHandler(unittest.TestCase):
    """Test handling of raw JSON messages from WebSocket."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_ws_")
        self.duckdb_path = Path(self.temp_dir) / "test_telemetry.db"
        self.sqlite_path = Path(self.temp_dir) / "test_sec_audit.db"
        self.db_mgr = DatabaseManager(duckdb_path=self.duckdb_path, sqlite_path=self.sqlite_path)

    def tearDown(self):
        self.db_mgr.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_json_message_ingested(self):
        detector = create_mock_detector()
        mitigator = make_controller()
        engine = RealtimeIngestionEngine(detector=detector, mitigator=mitigator, db_manager=self.db_mgr)

        event = create_mock_event(pid=5000)
        json_msg = json.dumps(event)

        engine._on_message(None, json_msg)
        stats = engine.get_stats()
        self.assertEqual(stats["total_events_ingested"], 1)

    def test_invalid_json_message_ignored(self):
        detector = create_mock_detector()
        mitigator = make_controller()
        engine = RealtimeIngestionEngine(detector=detector, mitigator=mitigator, db_manager=self.db_mgr)

        # Should not raise exception
        engine._on_message(None, "{invalid json content...")
        stats = engine.get_stats()
        self.assertEqual(stats["total_events_ingested"], 0)


class TestEngineLifecycle(unittest.TestCase):
    """Test engine background thread lifecycle methods."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_lc_")
        self.duckdb_path = Path(self.temp_dir) / "test_telemetry.db"
        self.sqlite_path = Path(self.temp_dir) / "test_sec_audit.db"
        self.db_mgr = DatabaseManager(duckdb_path=self.duckdb_path, sqlite_path=self.sqlite_path)

    def tearDown(self):
        self.db_mgr.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("ml_engine.inference.realtime_engine.websocket.WebSocketApp")
    def test_start_stop_lifecycle(self, mock_ws_app):
        detector = create_mock_detector()
        mitigator = make_controller()
        engine = RealtimeIngestionEngine(detector=detector, mitigator=mitigator, db_manager=self.db_mgr)

        self.assertFalse(engine.is_running())
        engine.start()
        self.assertTrue(engine.is_running())

        time.sleep(0.05)
        engine.stop()
        self.assertFalse(engine.is_running())


if __name__ == "__main__":
    unittest.main(verbosity=2)
