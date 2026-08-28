"""
Unit Test Suite for Falco-Style Behavioral Rules Engine & Alert Dispatcher.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml_engine.rules.behavioral_engine import BehavioralEngine
from ml_engine.detection.alert_dispatcher import AlertDispatcher
from ml_engine.storage import DatabaseManager
import tempfile
import shutil


class TestBehavioralEngine(unittest.TestCase):
    """Test Falco rule evaluation logic."""

    def setUp(self):
        self.engine = BehavioralEngine()

    def test_container_escape_nsenter(self):
        event = {
            "pid": 9999,
            "comm": "nsenter",
            "exe_path": "/usr/bin/nsenter",
            "syscall_id": 308, # setns
        }
        matches = self.engine.evaluate_event(event)
        self.assertTrue(any(m["rule_name"] == "Container Namespace Escape Attempt" for m in matches))

    def test_reverse_shell_netcat(self):
        event = {
            "pid": 8888,
            "comm": "nc",
            "event_type_str": "NET",
            "dst_port": 4444,
        }
        matches = self.engine.evaluate_event(event)
        self.assertTrue(any(m["rule_name"] == "Outbound Connection to Non-Standard Port" for m in matches))

    def test_sensitive_read_shadow(self):
        event = {
            "pid": 7777,
            "comm": "cat",
            "exe_path": "/bin/cat",
            "filename": "/etc/shadow",
            "uid": 1000,
        }
        matches = self.engine.evaluate_event(event)
        self.assertTrue(any(m["rule_name"] == "Read Sensitive System File" for m in matches))

    def test_kernel_module_insmod(self):
        event = {
            "pid": 6666,
            "comm": "insmod",
            "exe_path": "/usr/sbin/insmod",
            "syscall_id": 175, # init_module
        }
        matches = self.engine.evaluate_event(event)
        self.assertTrue(any(m["rule_name"] == "Kernel Module Load Attempt" for m in matches))

    def test_benign_ls(self):
        event = {
            "pid": 1234,
            "comm": "ls",
            "exe_path": "/bin/ls",
            "filename": "/home/user/documents",
            "uid": 1000,
        }
        matches = self.engine.evaluate_event(event)
        self.assertEqual(len(matches), 0)


class TestAlertDispatcher(unittest.TestCase):
    """Test AlertDispatcher format & database logging."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_dispatcher_")
        self.duckdb_path = Path(self.temp_dir) / "test_telemetry.db"
        self.sqlite_path = Path(self.temp_dir) / "test_sec_audit.db"
        self.db_mgr = DatabaseManager(duckdb_path=self.duckdb_path, sqlite_path=self.sqlite_path)
        self.dispatcher = AlertDispatcher(db_manager=self.db_mgr)

    def tearDown(self):
        self.db_mgr.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_dispatch_alert(self):
        event = {"pid": 5432, "comm": "nc", "exe_path": "/usr/bin/nc", "container_id": "c123"}
        alert = self.dispatcher.dispatch_alert(
            event=event,
            threat_type="REVERSE_SHELL_NETCAT",
            confidence=1.0,
            detection_source="behavioral_rule",
        )
        self.assertEqual(alert["pid"], 5432)
        self.assertEqual(alert["threat_name"], "REVERSE_SHELL_NETCAT")
        self.assertEqual(alert["detection_source"], "behavioral_rule")

        # Verify persisted in SQLite
        alerts = self.db_mgr.sqlite.get_alerts(limit=10)
        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0]["pid"], 5432)


if __name__ == "__main__":
    unittest.main()
