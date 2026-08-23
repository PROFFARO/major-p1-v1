"""
Type-safe data schemas and Pydantic DTOs for eBPF-ML Storage Layer & REST API.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────
# Storage Table Record Models
# ─────────────────────────────────────────────────────────────

class TelemetryEventRecord(BaseModel):
    """Raw eBPF syscall event record for DuckDB columnar store."""
    event_type: str = "SYS_EXEC"
    timestamp_ns: int
    pid: int
    ppid: int = 1
    uid: int = 1000
    gid: int = 1000
    comm: str = ""
    exe_path: str = ""
    parent_comm: str = ""
    syscall_id: int = 0
    file_path: str = ""
    bytes_written: int = 0
    bytes_read: int = 0
    dst_ip: str = "0.0.0.0"
    dst_port: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FeatureWindowRecord(BaseModel):
    """12-Dimensional Feature Vector window record for DuckDB columnar store."""
    pid: int
    window_start_ns: int
    window_end_ns: int
    event_count: int
    vector: List[float]  # 12 floats
    rf_prediction: str = "BENIGN"
    xgb_prediction: str = "BENIGN"
    iso_score: float = 0.0
    agreed_threat: str = "BENIGN"
    confidence: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ThreatAlertRecord(BaseModel):
    """Structured threat alert record for SQLite WAL database."""
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pid: int
    comm: str
    exe_path: str
    threat_name: str
    confidence: float
    consensus_agreed: bool
    action_taken: str
    rf_threat: str
    xgb_threat: str
    iso_anomaly: bool
    feature_summary: Optional[Dict[str, float]] = None


class MitigationAuditRecord(BaseModel):
    """LSM Kernel enforcement audit trail for SQLite WAL database."""
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pid: int
    threat_name: str
    action_taken: str  # KILL_PROCESS, PAUSE_PROCESS, BLOCK_IP, LOG_ONLY
    confidence: float
    success: bool
    dry_run: bool
    details: str = ""


class ActiveBlockRecord(BaseModel):
    """Active kernel blocklist entry for SQLite WAL database."""
    pid: int
    threat_name: str
    blocked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: Optional[str] = None
    is_permanent: bool = False
    details: str = ""


class LLMChatRecord(BaseModel):
    """Analyst LLM Copilot chat message record for SQLite WAL database."""
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    sender: str  # "user" or "copilot"
    prompt: str
    response: str
    provider: str = "auto"
    model_name: str = ""


# ─────────────────────────────────────────────────────────────
# REST API Request / Response DTOs
# ─────────────────────────────────────────────────────────────

class HealthStatusResponse(BaseModel):
    status: str = "ok"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duckdb_connected: bool = True
    sqlite_connected: bool = True
    active_blocks_count: int = 0


class MetricsSummaryResponse(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_events_ingested: int = 0
    events_per_second: float = 0.0
    active_feature_windows: int = 0
    total_threats_detected: int = 0
    threats_by_class: Dict[str, int] = Field(default_factory=dict)
    active_kernel_blocks: int = 0
    copilot_status: str = "ONLINE"


class AlertsQueryRequest(BaseModel):
    limit: int = 50
    offset: int = 0
    threat_name: Optional[str] = None
    min_confidence: float = 0.0


class UnblockRequest(BaseModel):
    pid: int
    reason: str = "Analyst manual unblock"


class CopilotChatRequest(BaseModel):
    prompt: str
    pid: Optional[int] = None
    include_history: bool = True


class CopilotChatResponse(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    prompt: str
    response: str
    provider: str
    model_name: str


class DuckDBSQLQueryRequest(BaseModel):
    sql: str
    limit: int = 100
