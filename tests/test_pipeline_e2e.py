"""
Full-Stack End-to-End Pipeline Integration Test Runner.

Verifies the entire eBPF threat streaming & defense lifecycle:
    1. BPF JSON Telemetry Event Stream
    2. RealtimeIngestionEngine (WebSocket Worker)
    3. StreamingExtractor (12-Dim Feature Extraction & Windowing)
    4. ThreatDetector (RF + XGBoost + Isolation Forest Consensus)
    5. MitigationController (6 Safety Layers & LSM Kernel Action)
    6. LLMSecurityCopilot (SOC Incident Report & Remediation Command Synthesis)
"""

import json
import time
import tempfile
import unittest
from unittest.mock import MagicMock
import numpy as np
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import shutil
from ml_engine.models.detector import ThreatDetector
from ml_engine.feedback.mitigator import MitigationController
from ml_engine.feedback.actions import AuditLogger
from ml_engine.inference.realtime_engine import RealtimeIngestionEngine
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot
from ml_engine.storage import DatabaseManager


# ─────────────────────────────────────────────────────────────
# Synthetic Telemetry Stream Generator
# ─────────────────────────────────────────────────────────────

def generate_e2e_event_stream(pid: int, comm: str, exe_path: str, threat_type: str, num_events: int = 15):
    """Generate a batch of correlated telemetry events for a process."""
    events = []
    base_ns = int(time.time() * 1e9)

    for i in range(num_events):
        ts = base_ns + int(i * 0.35 * 1e9)  # 0.35s step over ~5.25 seconds

        # Tailor event characteristics based on threat type
        if threat_type == "RANSOMWARE":
            syscall_id = 257 if i % 2 == 0 else 87  # openat / unlink
            file_path = f"/home/user/documents/file_{i}.crypto"
            bytes_written = 65536
        elif threat_type == "REVERSE_SHELL":
            syscall_id = 42 if i % 2 == 0 else 59   # connect / execve
            file_path = "/dev/tcp/192.168.1.100/4444"
            bytes_written = 128
        else:
            syscall_id = 0  # read
            file_path = "/usr/share/app.conf"
            bytes_written = 512

        evt = {
            "event_type": "SYS_EXEC",
            "timestamp_ns": ts,
            "pid": pid,
            "ppid": 1,
            "uid": 1000,
            "gid": 1000,
            "comm": comm,
            "exe_path": exe_path,
            "parent_comm": "bash",
            "syscall_id": syscall_id,
            "file_path": file_path,
            "bytes_written": bytes_written,
            "bytes_read": 1024,
            "dst_ip": "192.168.1.100" if threat_type == "REVERSE_SHELL" else "0.0.0.0",
            "dst_port": 4444 if threat_type == "REVERSE_SHELL" else 0,
        }
        events.append(evt)

    return events


# ─────────────────────────────────────────────────────────────
# E2E Test Suite
# ─────────────────────────────────────────────────────────────

class TestFullPipelineE2E(unittest.TestCase):
    """Full-stack integration test suite covering end-to-end telemetry to mitigation & LLM report."""

    def setUp(self):
        # 1. Temporary Audit Log & Isolated DatabaseManager
        self.temp_dir = tempfile.mkdtemp(prefix="ebpf_test_e2e_")
        self.duckdb_path = Path(self.temp_dir) / "test_telemetry.db"
        self.sqlite_path = Path(self.temp_dir) / "test_sec_audit.db"
        self.db_mgr = DatabaseManager(duckdb_path=self.duckdb_path, sqlite_path=self.sqlite_path)

        self.tmp_audit = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.tmp_audit.close()
        self.audit_logger = AuditLogger(log_path=Path(self.tmp_audit.name))

        # 2. Threat Detector (Loads trained joblib artifacts)
        self.detector = ThreatDetector()
        if not self.detector.loaded:
            self._setup_mock_detector()

        # 3. Mitigation Controller (Dry-run mode for test safety)
        self.mitigator = MitigationController(
            dry_run=True,
            audit_logger=self.audit_logger,
            enable_background_sweep=False,
        )

        # 4. LLM Analyst Copilot (Offline mode for fast reproducible testing)
        self.copilot = LLMSecurityCopilot(api_key="", base_url="")

        # 5. Callback sink to capture generated SOC reports
        self.captured_reports = []

        def on_detection(action, threat_res):
            # Synthesize LLM SOC report on threat detection
            metadata = {
                "pid": action.pid,
                "comm": threat_res.get("comm", "unknown"),
                "exe_path": threat_res.get("exe_path", "/tmp/malware"),
                "parent_comm": "bash",
                "dst_ip": threat_res.get("dst_ip", "0.0.0.0"),
            }
            report = self.copilot.analyze_threat(action.to_dict(), metadata)
            remediation = self.copilot.generate_remediation(action.to_dict(), metadata)
            self.captured_reports.append((report, remediation))

        # 6. Realtime Ingestion Engine
        self.engine = RealtimeIngestionEngine(
            detector=self.detector,
            mitigator=self.mitigator,
            db_manager=self.db_mgr,
            on_detection_callback=on_detection,
            window_seconds=5.0,
        )

    def _setup_mock_detector(self):
        """Create mock detector if saved model files are absent."""
        self.detector = MagicMock(spec=ThreatDetector)
        self.detector.loaded = True
        self.detector.predict_with_consensus.return_value = {
            "rf_result": {"threat_id": 1, "threat_name": "RANSOMWARE", "confidence": 0.96},
            "xgb_result": {"threat_id": 1, "threat_name": "RANSOMWARE", "confidence": 0.96},
            "consensus": True,
            "agreed_threat": "RANSOMWARE",
            "anomaly_score": -0.68,
            "is_anomaly": True,
            "threat_id": 1,
            "threat_name": "RANSOMWARE",
            "confidence": 0.96,
            "probabilities": {"RANSOMWARE": 0.96, "BENIGN": 0.04},
            "rf_threat_name": "RANSOMWARE",
            "xgb_threat_name": "RANSOMWARE",
        }

    def test_e2e_ransomware_pipeline_flow(self):
        """Test full pipeline flow for Ransomware attack detection, mitigation, and LLM report."""
        stream = generate_e2e_event_stream(
            pid=90001,
            comm="lockbit_encryptor",
            exe_path="/tmp/lockbit.sh",
            threat_type="RANSOMWARE",
            num_events=15,
        )

        actions = []
        for evt in stream:
            actions.extend(self.engine.ingest_event(evt))
        actions.extend(self.engine.flush())

        # 1. Verify detection and mitigation trigger
        self.assertGreater(len(actions), 0)
        action = actions[0]
        self.assertEqual(action.pid, 90001)

        # 2. Verify audit logger recorded the decision
        recorded_actions = self.audit_logger.read_all()
        self.assertGreater(len(recorded_actions), 0)
        self.assertEqual(recorded_actions[0].pid, 90001)

        # 3. Verify LLM Copilot report generation
        self.assertGreater(len(self.captured_reports), 0)
        report, remediation = self.captured_reports[0]
        self.assertIn("SOC Incident Report", report)
        self.assertIn("90001", report)
        self.assertIn("Containment & Remediation Guide", remediation)
        self.assertIn("kill -9 90001", remediation)

    def test_e2e_protected_pid_safety(self):
        """Verify protected PIDs (systemd PID 1) are never blocked even under attack noise."""
        stream = generate_e2e_event_stream(
            pid=1,
            comm="systemd",
            exe_path="/usr/lib/systemd/systemd",
            threat_type="RANSOMWARE",
            num_events=15,
        )

        actions = []
        for evt in stream:
            actions.extend(self.engine.ingest_event(evt))
        actions.extend(self.engine.flush())

        # PID 1 must produce action_taken == "SKIP_PROTECTED"
        self.assertGreater(len(actions), 0)
        self.assertEqual(actions[0].action_taken, "SKIP_PROTECTED")

    def tearDown(self):
        self.db_mgr.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        if Path(self.tmp_audit.name).exists():
            try:
                Path(self.tmp_audit.name).unlink()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
