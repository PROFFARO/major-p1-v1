"""
High-Performance Dual-Engine Storage Manager — DuckDB Columnar Store + SQLite WAL ACID Store.

Architecture:
    1. DuckDBManager: Ingests raw eBPF telemetry & 12-dim feature vectors into DuckDB columnar tables
       for sub-15ms analytical queries over millions of events.
    2. SQLiteWALManager: Persists structured threat alerts, LSM mitigation audit trails, active kernel
       blocklists, and LLM Copilot chat histories in transactional SQLite WAL mode.
    3. AsyncBatchDatabaseWriter: Non-blocking in-memory queue worker that micro-batches raw events
       every 200ms into DuckDB without delaying live streaming ingestion.
"""

import json
import sqlite3
import threading
import queue
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import duckdb
import numpy as np

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml_engine.config import DUCKDB_PATH, SQLITE_PATH, LOGS_DIR
from ml_engine.storage.models import (
    TelemetryEventRecord,
    FeatureWindowRecord,
    ThreatAlertRecord,
    MitigationAuditRecord,
    ActiveBlockRecord,
    LLMChatRecord,
)

logger = logging.getLogger("ml_engine.storage.db_manager")

DATA_DIR = LOGS_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────
# 1. DuckDB High-Throughput Columnar Engine
# ─────────────────────────────────────────────────────────────

class DuckDBManager:
    """Manages DuckDB columnar database for telemetry events and feature vector windows."""

    def __init__(self, db_path: Path = DUCKDB_PATH):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initialize database connection and schema tables."""
        with self._lock:
            try:
                self.conn = duckdb.connect(str(self.db_path))
            except Exception:
                try:
                    self.conn = duckdb.connect(str(self.db_path), read_only=True)
                except Exception:
                    logger.warning("DuckDB file locked — fallback to in-memory mode")
                    self.conn = duckdb.connect(":memory:")

            # Auto-upgrade table if old INT32 schema exists
            try:
                tables = self.conn.execute("SELECT table_name FROM information_schema.tables WHERE table_name = 'telemetry_events'").fetchall()
                if tables:
                    table_info = self.conn.execute("DESCRIBE telemetry_events").fetchall()
                    if any(col[1].upper() in ('INT', 'INTEGER', 'INT32') for col in table_info):
                        logger.warning("Migrating DuckDB telemetry_events schema to UBIGINT for 64-bit integer support")
                        self.conn.execute("DROP TABLE telemetry_events")
            except Exception as e:
                logger.warning("Could not check table schema migration: %s", e)

            # Create telemetry_events table with 64-bit unsigned UBIGINT types
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    event_type VARCHAR,
                    timestamp_ns UBIGINT,
                    pid UBIGINT,
                    ppid UBIGINT,
                    uid UBIGINT,
                    gid UBIGINT,
                    comm VARCHAR,
                    exe_path VARCHAR,
                    parent_comm VARCHAR,
                    syscall_id UBIGINT,
                    file_path VARCHAR,
                    bytes_written UBIGINT,
                    bytes_read UBIGINT,
                    dst_ip VARCHAR,
                    dst_port UBIGINT,
                    created_at VARCHAR
                )
            """)

            # Create feature_windows table
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS feature_windows (
                    pid UBIGINT,
                    window_start_ns UBIGINT,
                    window_end_ns UBIGINT,
                    event_count UBIGINT,
                    vector DOUBLE[],
                    rf_prediction VARCHAR,
                    xgb_prediction VARCHAR,
                    iso_score DOUBLE,
                    agreed_threat VARCHAR,
                    confidence DOUBLE,
                    created_at VARCHAR
                )
            """)
            logger.info("DuckDB Columnar Store initialized at %s", self.db_path)

    @staticmethod
    def _safe_uint64(val: Any, default: int = 0) -> int:
        """Sanitize values to fit within unsigned 64-bit integer range (0 to 18446744073709551615)."""
        if val is None:
            return default
        try:
            v = int(val)
            return v & 0xFFFFFFFFFFFFFFFF
        except (ValueError, TypeError):
            return default

    def insert_telemetry_batch(self, events: List[Dict[str, Any]]) -> int:
        """Batch insert raw telemetry event dictionaries into DuckDB."""
        if not events:
            return 0

        rows = []
        for e in events:
            rows.append((
                str(e.get("event_type", "SYS_EXEC")),
                self._safe_uint64(e.get("timestamp_ns"), 0),
                self._safe_uint64(e.get("pid"), 0),
                self._safe_uint64(e.get("ppid"), 1),
                self._safe_uint64(e.get("uid"), 1000),
                self._safe_uint64(e.get("gid"), 1000),
                str(e.get("comm", "")),
                str(e.get("exe_path", "")),
                str(e.get("parent_comm", "")),
                self._safe_uint64(e.get("syscall_id"), 0),
                str(e.get("file_path", "")),
                self._safe_uint64(e.get("bytes_written"), 0),
                self._safe_uint64(e.get("bytes_read"), 0),
                str(e.get("dst_ip", "0.0.0.0")),
                self._safe_uint64(e.get("dst_port"), 0),
                time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            ))

        with self._lock:
            self.conn.executemany("""
                INSERT INTO telemetry_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
        return len(rows)

    def insert_feature_window(self, record: FeatureWindowRecord):
        """Insert a 12-dim feature window record."""
        with self._lock:
            self.conn.execute("""
                INSERT INTO feature_windows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.pid,
                record.window_start_ns,
                record.window_end_ns,
                record.event_count,
                record.vector,
                record.rf_prediction,
                record.xgb_prediction,
                record.iso_score,
                record.agreed_threat,
                record.confidence,
                record.created_at,
            ))

    def query_sql(self, sql: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Run an arbitrary SQL query against DuckDB and return list of dict rows."""
        with self._lock:
            res = self.conn.execute(sql).fetchdf()
            if len(res) > limit:
                res = res.head(limit)
            return res.to_dict(orient="records")

    def get_event_count(self) -> int:
        """Return total telemetry event row count in DuckDB."""
        with self._lock:
            if self.conn is None:
                self.conn = duckdb.connect(str(self.db_path))
            res = self.conn.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()
            return res[0] if res else 0

    def close(self):
        """Close DuckDB connection."""
        with self._lock:
            if self.conn:
                self.conn.close()
                self.conn = None


# ─────────────────────────────────────────────────────────────
# 2. SQLite WAL Transactional Engine
# ─────────────────────────────────────────────────────────────

class SQLiteWALManager:
    """Manages SQLite database operating in WAL (Write-Ahead Logging) mode for ACID alerts & audit logs."""

    def __init__(self, db_path: Path = SQLITE_PATH):
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Open connection with WAL mode enabled."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        """Initialize tables and indexes."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # 1. Threat Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    comm TEXT,
                    exe_path TEXT,
                    threat_name TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    consensus_agreed INTEGER NOT NULL,
                    action_taken TEXT NOT NULL,
                    rf_threat TEXT,
                    xgb_threat TEXT,
                    iso_anomaly INTEGER,
                    feature_summary TEXT
                );
            """)

            # 2. Mitigation Audit Trail table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitigation_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    comm TEXT NOT NULL DEFAULT '',
                    threat_name TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    success INTEGER NOT NULL,
                    dry_run INTEGER NOT NULL,
                    details TEXT
                );
            """)
            # Migration check: ensure comm column exists if table was created previously
            cursor.execute("PRAGMA table_info(mitigation_audit)")
            cols = [info[1] for info in cursor.fetchall()]
            if "comm" not in cols:
                cursor.execute("ALTER TABLE mitigation_audit ADD COLUMN comm TEXT NOT NULL DEFAULT ''")

            # 3. Active Blocklist table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_blocks (
                    pid INTEGER PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    blocked_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_permanent INTEGER NOT NULL,
                    details TEXT
                );
            """)

            # 4. LLM Copilot Chat History table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS llm_chat_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    response TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model_name TEXT NOT NULL
                );
            """)

            conn.commit()
            conn.close()
            logger.debug("SQLite WAL Transactional Store initialized at %s", self.db_path)

    def insert_alert(self, alert: ThreatAlertRecord) -> int:
        """Insert a threat alert record and return generated ID."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            feat_json = json.dumps(alert.feature_summary) if alert.feature_summary else "{}"
            cursor.execute("""
                INSERT INTO threat_alerts (
                    timestamp, pid, comm, exe_path, threat_name, confidence,
                    consensus_agreed, action_taken, rf_threat, xgb_threat, iso_anomaly, feature_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.timestamp, alert.pid, alert.comm, alert.exe_path, alert.threat_name,
                alert.confidence, int(alert.consensus_agreed), alert.action_taken,
                alert.rf_threat, alert.xgb_threat, int(alert.iso_anomaly), feat_json
            ))
            alert_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return alert_id

    def insert_mitigation_audit(self, audit: MitigationAuditRecord) -> int:
        """Insert mitigation audit trail record."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO mitigation_audit (
                    timestamp, pid, comm, threat_name, action_taken, confidence, success, dry_run, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                audit.timestamp, audit.pid, getattr(audit, 'comm', ''), audit.threat_name, audit.action_taken,
                audit.confidence, int(audit.success), int(audit.dry_run), audit.details
            ))
            audit_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return audit_id

    def upsert_active_block(self, block: ActiveBlockRecord):
        """Insert or replace active kernel PID block entry."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO active_blocks (pid, threat_name, blocked_at, expires_at, is_permanent, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (block.pid, block.threat_name, block.blocked_at, block.expires_at, int(block.is_permanent), block.details))
            conn.commit()
            conn.close()

    def remove_active_block(self, pid: int) -> bool:
        """Remove active kernel PID block entry."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM active_blocks WHERE pid = ?", (pid,))
            affected = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return affected

    def insert_chat_message(self, record: LLMChatRecord) -> int:
        """Insert LLM Copilot chat message."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO llm_chat_history (timestamp, sender, prompt, response, provider, model_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (record.timestamp, record.sender, record.prompt, record.response, record.provider, record.model_name))
            chat_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return chat_id

    def get_alerts(self, limit: int = 50, threat_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query recent threat alerts."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if threat_name:
                cursor.execute("SELECT * FROM threat_alerts WHERE threat_name = ? ORDER BY id DESC LIMIT ?", (threat_name, limit))
            else:
                cursor.execute("SELECT * FROM threat_alerts ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_mitigation_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Query recent mitigation audit logs."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM mitigation_audit ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Query active kernel blocklist."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM active_blocks ORDER BY blocked_at DESC")
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows

    def get_chat_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Query recent LLM copilot chat history."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM llm_chat_history ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows


# ─────────────────────────────────────────────────────────────
# 3. Asynchronous Batch Database Inserter Queue
# ─────────────────────────────────────────────────────────────

class AsyncBatchDatabaseWriter:
    """Non-blocking background queue worker that micro-batches raw events into DuckDB every 200ms."""

    def __init__(self, duckdb_mgr: DuckDBManager, max_batch_size: int = 2000, flush_interval_sec: float = 0.1):
        self.duckdb_mgr = duckdb_mgr
        self.max_batch_size = max_batch_size
        self.flush_interval_sec = flush_interval_sec

        self._queue = queue.Queue(maxsize=200000)
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._dropped_count = 0
        self._last_drop_log_time = 0.0

    def start(self):
        """Start the background micro-batch worker thread."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(target=self._run_loop, daemon=True, name="db-async-writer")
        self._worker_thread.start()
        logger.info("AsyncBatchDatabaseWriter started (flush_interval=%.1fs, batch_size=%d)", self.flush_interval_sec, self.max_batch_size)

    def stop(self):
        """Stop worker thread and flush remaining items."""
        if not self._running:
            return
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        self.flush()
        logger.info("AsyncBatchDatabaseWriter stopped")

    def enqueue(self, event: Dict[str, Any]):
        """Enqueue a raw telemetry event dict without blocking."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped_count += 1
            now = time.time()
            if now - self._last_drop_log_time >= 5.0:
                logger.warning(
                    "Database insert queue full! Dropped %d events in the last 5s (current queue size: %d)",
                    self._dropped_count, self._queue.qsize()
                )
                self._dropped_count = 0
                self._last_drop_log_time = now

    def flush(self):
        """Flush all pending events in queue to DuckDB."""
        batch = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            self.duckdb_mgr.insert_telemetry_batch(batch)

    def _run_loop(self):
        """Worker loop collecting items up to max_batch_size or flush_interval_sec."""
        last_flush = time.time()

        while self._running:
            batch = []
            while len(batch) < self.max_batch_size:
                timeout = max(0.01, self.flush_interval_sec - (time.time() - last_flush))
                try:
                    item = self._queue.get(timeout=timeout)
                    batch.append(item)
                except queue.Empty:
                    break

            now = time.time()
            if batch or (now - last_flush >= self.flush_interval_sec):
                if batch:
                    try:
                        self.duckdb_mgr.insert_telemetry_batch(batch)
                    except Exception as e:
                        logger.error("Async batch DuckDB insert failed: %s", e)
                last_flush = now


# ─────────────────────────────────────────────────────────────
# Central Unified Database Manager Wrapper
# ─────────────────────────────────────────────────────────────

class DatabaseManager:
    """Unified Database Manager combining DuckDB columnar analytics and SQLite WAL ACID stores."""

    def __init__(self, duckdb_path: Path = DUCKDB_PATH, sqlite_path: Path = SQLITE_PATH):
        self.duckdb = DuckDBManager(db_path=duckdb_path)
        self.sqlite = SQLiteWALManager(db_path=sqlite_path)
        self.batch_writer = AsyncBatchDatabaseWriter(duckdb_mgr=self.duckdb)

    def start(self):
        """Start async writer worker."""
        self.batch_writer.start()

    def stop(self):
        """Stop batch writer and close connections."""
        self.batch_writer.stop()
        self.duckdb.close()
