"""
Real-Time Streaming Ingestion Engine for the eBPF-ML Security Feedback Loop.

Ingests real-time JSON telemetry events streamed over WebSocket from the Go Agent,
feeds them into per-PID sliding window feature extractors (StreamingExtractor),
evaluates feature vectors through the dual-model ML detector (ThreatDetector),
and triggers kernel-level mitigation decisions (MitigationController).

Architecture Flow:
    Go Agent (ws://localhost:8900/ws)
    ↳ WebSocket Event JSON
      ↳ RealtimeIngestionEngine
        ↳ StreamingExtractor (per-PID sliding windows)
          ↳ 12-dim feature vector
            ↳ ThreatDetector.predict_with_consensus()
              ↳ MitigationController.evaluate_and_mitigate()
                ↳ Go Agent REST API (POST /api/block/pid, POST /api/block/ip)
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Callable, List

import numpy as np
import websocket

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml_engine.config import (
    AGENT_WS_URL,
    SLIDING_WINDOW_SECONDS,
)
from ml_engine.preprocessing.feature_extractor import StreamingExtractor
from ml_engine.models.detector import ThreatDetector
from ml_engine.rules.behavioral_engine import BehavioralEngine
from ml_engine.detection.alert_dispatcher import AlertDispatcher
from ml_engine.storage import DatabaseManager, FeatureWindowRecord

logger = logging.getLogger("ml_engine.inference.realtime_engine")


# ─────────────────────────────────────────────────────────────
# Realtime Ingestion Engine
# ─────────────────────────────────────────────────────────────

class RealtimeIngestionEngine:
    """
    Thread-safe streaming ingestion engine.

    Connects to the Go Agent WebSocket stream, processes events through
    the sliding window feature extractor, runs ML inference, evaluates
    Falco behavioral rules, and dispatches detection alerts.
    """

    def __init__(
        self,
        ws_url: str = AGENT_WS_URL,
        detector: Optional[ThreatDetector] = None,
        behavioral_engine: Optional[BehavioralEngine] = None,
        window_seconds: float = SLIDING_WINDOW_SECONDS,
        on_detection_callback: Optional[Callable[[dict], None]] = None,
        db_manager: Optional[DatabaseManager] = None,
    ):
        self.ws_url = ws_url
        self.window_seconds = window_seconds
        self.on_detection_callback = on_detection_callback

        # Components
        self.detector = detector or ThreatDetector()
        self.behavioral_engine = behavioral_engine or BehavioralEngine()
        self.extractor = StreamingExtractor(window_seconds=window_seconds)
        self.db_mgr = db_manager or DatabaseManager()
        self.dispatcher = AlertDispatcher(db_manager=self.db_mgr)

        # Threading & Control
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._ws_app: Optional[websocket.WebSocketApp] = None

        # Telemetry & Metrics
        self._stats = {
            "is_connected": False,
            "total_events_ingested": 0,
            "total_windows_processed": 0,
            "total_threats_detected": 0,
            "threats_by_class": {},
            "reconnect_count": 0,
            "last_event_time": None,
            "events_per_second": 0.0,
            "start_time": None,
        }

        # Sliding window throughput calculation (timestamps of recent 10s)
        self._event_timestamps: List[float] = []

    # ─────────────────────────────────────────────────────────
    # Lifecycle Control
    # ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background streaming worker thread and DB batch writer."""
        with self._lock:
            if self._running:
                logger.warning("RealtimeIngestionEngine is already running")
                return

            self._running = True
            self._stats["start_time"] = datetime.now(timezone.utc).isoformat()
            self.db_mgr.start()
            self._thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="ml-realtime-ingest",
            )
            self._thread.start()
            logger.info("RealtimeIngestionEngine started [ws_url=%s]", self.ws_url)

    def stop(self) -> None:
        """Gracefully stop the streaming engine and flush windows."""
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stats["is_connected"] = False

        if self._ws_app:
            try:
                self._ws_app.close()
            except Exception:
                pass

        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=0.2)
            except Exception:
                pass

        # Flush any remaining active windows & pending DB writes
        self.flush()
        self.db_mgr.stop()

        logger.info("RealtimeIngestionEngine stopped")

    def is_running(self) -> bool:
        """Check if background worker thread is running."""
        with self._lock:
            return self._running

    # ─────────────────────────────────────────────────────────
    # Main Streaming Loop with Auto-Reconnect
    # ─────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Background thread worker loop with exponential backoff reconnects."""
        backoff_seconds = 1.0
        max_backoff = 30.0

        while self._running:
            try:
                logger.info("Connecting to Go Agent WebSocket: %s", self.ws_url)

                self._ws_app = websocket.WebSocketApp(
                    self.ws_url,
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                )

                # Blocks until connection closes (generous ping interval/timeout to prevent false drops under high EPS)
                self._ws_app.run_forever(ping_interval=30, ping_timeout=20)

                # Reset backoff on clean loop iteration
                if not self._running:
                    break

                backoff_seconds = 1.0

            except Exception as e:
                logger.error("WebSocket connection error: %s", e)

            if self._running:
                with self._lock:
                    self._stats["is_connected"] = False
                    self._stats["reconnect_count"] += 1

                logger.warning(
                    "WebSocket disconnected — reconnecting in %.1fs (attempt #%d)...",
                    backoff_seconds, self._stats["reconnect_count"],
                )
                sleep_start = time.time()
                while self._running and (time.time() - sleep_start < backoff_seconds):
                    time.sleep(0.05)
                backoff_seconds = min(max_backoff, backoff_seconds * 2.0)

    # ─────────────────────────────────────────────────────────
    # WebSocket Event Handlers
    # ─────────────────────────────────────────────────────────

    def _on_open(self, ws):
        """Called when WebSocket connection is established."""
        with self._lock:
            self._stats["is_connected"] = True
        logger.info("WebSocket connected to Go Agent at %s", self.ws_url)

    def _on_close(self, ws, close_status_code, close_msg):
        """Called when WebSocket connection closes."""
        with self._lock:
            self._stats["is_connected"] = False
        logger.warning("WebSocket closed [code=%s, msg=%s]", close_status_code, close_msg)

    def _on_error(self, ws, error):
        """Called on WebSocket error."""
        logger.error("WebSocket error: %s", error)

    def _on_message(self, ws, message: str):
        """
        Called when a telemetry event JSON message arrives from the Go Agent.

        Parses JSON, feeds into StreamingExtractor, and evaluates any
        completed feature windows through the ML pipeline.
        """
        if not message:
            return

        try:
            event = json.loads(message)
            self.ingest_event(event)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed WebSocket message: %s", message[:100])
        except Exception as e:
            logger.error("Error processing telemetry event: %s", e)

    # ─────────────────────────────────────────────────────────
    # Event Ingestion & Inference Pipeline
    # ─────────────────────────────────────────────────────────

    def ingest_event(self, event: dict) -> List[Dict[str, Any]]:
        """
        Ingest a single telemetry event dictionary.

        Can be called directly for testing or batch processing.
        Returns a list of any alert dicts produced.

        Args:
            event: BPF telemetry event dictionary

        Returns:
            List of alert dictionaries produced by rules or ML model evaluation.
        """
        actions = []
        now = time.time()

        with self._lock:
            self._stats["total_events_ingested"] += 1
            self._stats["last_event_time"] = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()

            # Track throughput (sliding 10s window)
            self._event_timestamps.append(now)
            cutoff = now - 10.0
            self._event_timestamps = [t for t in self._event_timestamps if t > cutoff]
            self._stats["events_per_second"] = round(len(self._event_timestamps) / 10.0, 2)

        # Enqueue raw telemetry event into async database batch queue
        self.db_mgr.batch_writer.enqueue(event)

        # 1. Evaluate Falco behavioral rules on incoming event
        rule_matches = self.behavioral_engine.evaluate_event(event)
        for match in rule_matches:
            alert = self.dispatcher.dispatch_alert(
                event=event,
                threat_type=match["rule_name"],
                confidence=1.0,
                detection_source="behavioral_rule",
                rule_info=match,
            )
            actions.append(alert)

        # 2. Feed event into StreamingExtractor for ML sliding window feature extraction
        completed_windows = self.extractor.ingest(event)
        
        # Also check for any expired windows that reached minimum event count
        expired_windows = self.extractor.flush_expired(int(now * 1e9))
        if expired_windows:
            completed_windows.extend(expired_windows)

        for pid, vector, metadata in completed_windows:
            action = self._process_feature_window(pid, vector, metadata)
            if action:
                actions.append(action)

        return actions

    def _process_feature_window(
        self, pid: int, vector: np.ndarray, metadata: dict
    ) -> Optional[Dict[str, Any]]:
        """
        Process a completed 12-dim feature window for a PID:
        1. Run ML inference via ThreatDetector.predict_with_consensus()
        2. Dispatch alert via AlertDispatcher if threat detected
        3. Invoke subscriber callback if provided
        """
        with self._lock:
            self._stats["total_windows_processed"] += 1

        # 1. Run ML inference with consensus
        if not self.detector.loaded:
            logger.warning("ThreatDetector not loaded — skipping inference for PID %d", pid)
            return None

        threat_result = self.detector.predict_with_consensus(vector)

        rf_res = threat_result.get("rf_result", {})
        xgb_res = threat_result.get("xgb_result", {})

        rf_threat = rf_res.get("threat_name", "BENIGN") if isinstance(rf_res, dict) else "BENIGN"
        xgb_threat = xgb_res.get("threat_name", "BENIGN") if isinstance(xgb_res, dict) else "BENIGN"
        agreed_threat = threat_result.get("agreed_threat", "BENIGN")

        # Set top-level keys in threat_result dict for downstream consumers
        threat_result["threat_name"] = agreed_threat
        threat_result["rf_threat_name"] = rf_threat
        threat_result["xgb_threat_name"] = xgb_threat

        # Persist 12-dim Feature Window into DuckDB
        try:
            vec_list = vector.tolist() if isinstance(vector, np.ndarray) else list(vector)
            fw_rec = FeatureWindowRecord(
                pid=pid,
                window_start_ns=int(metadata.get("window_start_ns", 0)),
                window_end_ns=int(metadata.get("window_end_ns", 0)),
                event_count=int(metadata.get("event_count", 0)),
                vector=vec_list,
                rf_prediction=rf_threat,
                xgb_prediction=xgb_threat,
                iso_score=float(threat_result.get("iso_score", 0.0)),
                agreed_threat=agreed_threat,
                confidence=float(threat_result.get("confidence", 0.0)),
            )
            self.db_mgr.duckdb.insert_feature_window(fw_rec)
        except Exception as err:
            logger.debug("Failed to record feature window to DuckDB: %s", err)

        # 2. Dispatch ML alert if threat detected
        alert = None
        if agreed_threat != "BENIGN":
            with self._lock:
                self._stats["total_threats_detected"] += 1
                cls_count = self._stats["threats_by_class"].get(agreed_threat, 0)
                self._stats["threats_by_class"][agreed_threat] = cls_count + 1

            alert = self.dispatcher.dispatch_alert(
                event={"pid": pid, "comm": str(metadata.get("comm", "")), "exe_path": str(metadata.get("exe_path", ""))},
                threat_type=agreed_threat,
                confidence=float(threat_result.get("confidence", 0.0)),
                detection_source="ensemble_ml",
                ml_scores={"rf": rf_threat, "xgb": xgb_threat, "iso_score": float(threat_result.get("iso_score", 0.0))},
            )

        # 3. Notify external subscriber callback (if registered)
        if self.on_detection_callback and alert:
            try:
                self.on_detection_callback(alert)
            except Exception as e:
                logger.error("Subscriber callback failed: %s", e)

        return alert

    def flush(self) -> List[Dict[str, Any]]:
        """Flush all active windows in the StreamingExtractor and evaluate."""
        flushed_windows = self.extractor.flush_all()
        actions = []
        for pid, vector, metadata in flushed_windows:
            action = self._process_feature_window(pid, vector, metadata)
            if action:
                actions.append(action)
        return actions

    # ─────────────────────────────────────────────────────────
    # Telemetry & Metrics Query
    # ─────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Return engine runtime statistics."""
        with self._lock:
            stats = dict(self._stats)
            stats["active_pid_windows"] = len(self.extractor.windows)
            return stats
