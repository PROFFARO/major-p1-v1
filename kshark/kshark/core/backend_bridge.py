"""
Thread-Safe Backend Bridge connecting Qt6 GUI to the eBPF-ML Ingestion Engine.
Operates on a background QThread to prevent UI thread latency.
"""

from PyQt6.QtCore import QObject, pyqtSignal, QThread, pyqtSlot
from typing import Dict, Any, List, Optional
import threading
import time
import json
import logging
import subprocess
import os
from pathlib import Path

# Import existing backend modules
import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.config import AGENT_WS_URL, DUCKDB_PATH, SQLITE_PATH, LOGS_DIR
from ml_engine.inference.realtime_engine import RealtimeIngestionEngine
from ml_engine.storage import DatabaseManager
from ml_engine.models.detector import ThreatDetector
from ml_engine.rules.behavioral_engine import BehavioralEngine
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot

logger = logging.getLogger("kshark.backend_bridge")


class BackendWorker(QObject):
    """Worker object living on the background QThread."""

    eventReceived = pyqtSignal(dict)
    threatDetected = pyqtSignal(dict)
    statsUpdated = pyqtSignal(dict)
    connectionStateChanged = pyqtSignal(bool)
    agentLogReceived = pyqtSignal(str)
    historicalEventsLoaded = pyqtSignal(list)
    copilotResponseReceived = pyqtSignal(str, str)  # (prompt, response)

    def __init__(self, ws_url: str = AGENT_WS_URL):
        super().__init__()
        self.ws_url = ws_url
        self.is_capturing = False

        # Ingestion & Detection Engines
        self.db_mgr = DatabaseManager()
        self.detector = ThreatDetector()
        self.behavioral_engine = BehavioralEngine()
        self.copilot = LLMSecurityCopilot()

        self.engine = RealtimeIngestionEngine(
            ws_url=self.ws_url,
            detector=self.detector,
            behavioral_engine=self.behavioral_engine,
            on_detection_callback=self._handle_detection,
            db_manager=self.db_mgr,
        )

        # Intercept live events before sliding window
        self._orig_ingest_event = self.engine.ingest_event
        self.engine.ingest_event = self._intercepted_ingest_event

        self._stats_timer_running = False
        self._agent_process: Optional[subprocess.Popen] = None

    def _intercepted_ingest_event(self, event: dict) -> List[Dict[str, Any]]:
        """Intercepts raw telemetry event to emit Qt signal to UI thread."""
        self.eventReceived.emit(event)
        return self._orig_ingest_event(event)

    def _handle_detection(self, alert: dict):
        """Callback invoked when ML or Falco rule detects a threat."""
        self.threatDetected.emit(alert)

    @pyqtSlot()
    def start_capture(self, custom_ws_url: str = ""):
        """Starts real-time telemetry streaming from Go Agent."""
        if self.is_capturing:
            return
        if custom_ws_url:
            self.ws_url = custom_ws_url
            self.engine.ws_url = custom_ws_url

        logger.info("Starting KShark live capture from %s", self.ws_url)
        self.is_capturing = True
        self.engine.start()
        self.connectionStateChanged.emit(True)

        # Start periodic stats emitter
        self._stats_timer_running = True
        threading.Thread(target=self._stats_loop, daemon=True, name="kshark-stats-loop").start()

    @pyqtSlot()
    def stop_capture(self):
        """Stops live telemetry streaming."""
        if not self.is_capturing:
            return
        logger.info("Stopping KShark live capture...")
        self.is_capturing = False
        self._stats_timer_running = False
        self.engine.stop()
        self.connectionStateChanged.emit(False)

    @pyqtSlot(str)
    def load_historical_database(self, db_path: str):
        """Loads historical events from DuckDB file."""
        try:
            logger.info("Loading historical session from %s", db_path)
            target_path = Path(db_path).resolve()
            default_path = Path(self.db_mgr.duckdb.db_path).resolve()

            if target_path == default_path:
                rows = self.db_mgr.duckdb.query_sql(
                    "SELECT * FROM telemetry_events ORDER BY timestamp_ns DESC",
                    limit=50000
                )
            else:
                import duckdb
                conn = duckdb.connect(str(target_path), read_only=True)
                res = conn.execute(
                    "SELECT * FROM telemetry_events ORDER BY timestamp_ns DESC LIMIT 50000"
                ).fetchdf()
                rows = res.to_dict(orient="records")
                conn.close()

            self.historicalEventsLoaded.emit(rows)
        except Exception as e:
            logger.error("Failed to load historical capture: %s", e)



    @pyqtSlot(str)
    def query_copilot(self, prompt: str):
        """Submits security analysis context query to LLM Analyst Copilot."""
        try:
            history = self.db_mgr.sqlite.get_mitigation_audit_logs(limit=20)
            response = self.copilot.chat(user_query=prompt, audit_history=history)
            self.copilotResponseReceived.emit(prompt, response)
        except Exception as e:
            err_msg = f"LLM Analyst Copilot Error: {str(e)}"
            self.copilotResponseReceived.emit(prompt, err_msg)

    def _stats_loop(self):
        """Emits stats update every 500ms while capture is active."""
        while self._stats_timer_running and self.is_capturing:
            stats = self.engine.get_stats()
            self.statsUpdated.emit(stats)
            time.sleep(0.5)


class BackendBridge(QObject):
    """
    Main Thread wrapper managing the background worker QThread.
    Exposes clean Qt Signals and Slots for the GUI.
    """

    eventReceived = pyqtSignal(dict)
    threatDetected = pyqtSignal(dict)
    statsUpdated = pyqtSignal(dict)
    connectionStateChanged = pyqtSignal(bool)
    agentLogReceived = pyqtSignal(str)
    historicalEventsLoaded = pyqtSignal(list)
    copilotResponseReceived = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.thread = QThread()
        self.worker = BackendWorker()
        self.worker.moveToThread(self.thread)

        # Forward worker signals to bridge signals
        self.worker.eventReceived.connect(self.eventReceived)
        self.worker.threatDetected.connect(self.threatDetected)
        self.worker.statsUpdated.connect(self.statsUpdated)
        self.worker.connectionStateChanged.connect(self.connectionStateChanged)
        self.worker.agentLogReceived.connect(self.agentLogReceived)
        self.worker.historicalEventsLoaded.connect(self.historicalEventsLoaded)
        self.worker.copilotResponseReceived.connect(self.copilotResponseReceived)

        self.thread.start()

    def start_capture(self, ws_url: str = ""):
        self.worker.start_capture(ws_url)

    def stop_capture(self):
        self.worker.stop_capture()

    def load_historical_database(self, db_path: str):
        self.worker.load_historical_database(db_path)


    @staticmethod
    def is_agent_listening(host="localhost", port=8900) -> bool:
        """Checks if the eBPF Go agent is listening on port 8900."""
        import socket
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


    def query_copilot(self, prompt: str):
        self.worker.query_copilot(prompt)


    def shutdown(self):
        self.worker.stop_capture()
        self.thread.quit()
        self.thread.wait(1000)
