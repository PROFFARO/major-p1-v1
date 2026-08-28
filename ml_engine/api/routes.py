"""
FastAPI REST API Routes for eBPF-ML Security Dashboard & SOC Analysts.
"""

import logging
from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, Query

from ml_engine.storage import (
    DatabaseManager,
    SQLiteWALManager,
    DuckDBManager,
    HealthStatusResponse,
    MetricsSummaryResponse,
    AlertsQueryRequest,
    UnblockRequest,
    CopilotChatRequest,
    CopilotChatResponse,
    DuckDBSQLQueryRequest,
    LLMChatRecord,
    ActiveBlockRecord,
)
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot

logger = logging.getLogger("ml_engine.api.routes")
router = APIRouter(prefix="/api/v1", tags=["eBPF-ML Security Service"])

# References injected by server lifecycle initialization
db_manager: Optional[DatabaseManager] = None
copilot_instance: Optional[LLMSecurityCopilot] = None
realtime_engine_ref = None


def set_api_dependencies(
    db_mgr: DatabaseManager,
    copilot: LLMSecurityCopilot,
    engine=None,
    mitigator=None,
    **kwargs,
):
    """Inject global application dependencies into API routes."""
    global db_manager, copilot_instance, realtime_engine_ref
    db_manager = db_mgr
    copilot_instance = copilot
    realtime_engine_ref = engine


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

from fastapi.responses import PlainTextResponse


@router.get("/health", response_model=HealthStatusResponse)
def get_health_status():
    """Return health and database connectivity status."""
    return HealthStatusResponse(
        status="ok",
        duckdb_connected=db_manager is not None and db_manager.duckdb is not None,
        sqlite_connected=True,
        active_blocks_count=0,
    )


@router.get("/metrics", response_class=PlainTextResponse)
def get_prometheus_metrics():
    """Return standard Prometheus formatted telemetry metrics."""
    stats = {}
    if realtime_engine_ref:
        stats = realtime_engine_ref.get_stats()

    lines = [
        "# HELP ebpf_events_ingested_total Total raw eBPF telemetry events ingested",
        "# TYPE ebpf_events_ingested_total counter",
        f"ebpf_events_ingested_total {stats.get('total_events_ingested', 0)}",
        "",
        "# HELP ebpf_telemetry_throughput_eps Current telemetry throughput in events per second",
        "# TYPE ebpf_telemetry_throughput_eps gauge",
        f"ebpf_telemetry_throughput_eps {stats.get('events_per_second', 0.0)}",
        "",
        "# HELP ebpf_active_pid_windows Total active sliding PID feature extraction windows",
        "# TYPE ebpf_active_pid_windows gauge",
        f"ebpf_active_pid_windows {stats.get('active_pid_windows', 0)}",
        "",
        "# HELP ebpf_threats_detected_total Total security threat detections by class",
        "# TYPE ebpf_threats_detected_total counter",
        f"ebpf_threats_detected_total {stats.get('total_threats_detected', 0)}",
    ]

    threats_by_class = stats.get("threats_by_class", {})
    for threat_class, count in threats_by_class.items():
        lines.append(f'ebpf_threat_detections_by_class{{threat_class="{threat_class}"}} {count}')

    lines.append("")
    return "\n".join(lines)


@router.get("/metrics/summary", response_model=MetricsSummaryResponse)
def get_metrics_summary():
    """Return live system telemetry, throughput rates, threat counts, and engine status."""
    stats = {}
    if realtime_engine_ref:
        stats = realtime_engine_ref.get_stats()

    copilot_mode = "ONLINE"
    if copilot_instance:
        copilot_mode = "ONLINE" if copilot_instance.is_available() else "OFFLINE"

    return MetricsSummaryResponse(
        total_events_ingested=stats.get("total_events_ingested", 0),
        events_per_second=stats.get("events_per_second", 0.0),
        active_feature_windows=stats.get("active_pid_windows", 0),
        total_threats_detected=stats.get("total_threats_detected", 0),
        threats_by_class=stats.get("threats_by_class", {}),
        active_kernel_blocks=0,
        copilot_status=copilot_mode,
    )


@router.get("/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=500), threat_name: Optional[str] = None):
    """Query recent threat detection alerts from SQLite WAL database."""
    sqlite_mgr = db_manager.sqlite if db_manager else SQLiteWALManager()
    alerts = sqlite_mgr.get_alerts(limit=limit, threat_name=threat_name)
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/audit/logs")
def get_audit_logs(limit: int = Query(50, ge=1, le=500)):
    """Query recent telemetry audit logs."""
    sqlite_mgr = db_manager.sqlite if db_manager else SQLiteWALManager()
    logs = sqlite_mgr.get_mitigation_audit_logs(limit=limit)
    return {"audit_logs": logs, "count": len(logs)}


@router.post("/copilot/chat", response_model=CopilotChatResponse)
def copilot_chat(req: CopilotChatRequest):
    """Query Universal LLM Security Analyst Copilot and persist interaction."""
    if not copilot_instance:
        raise HTTPException(status_code=503, detail="LLMSecurityCopilot service not initialized")

    audit_history = []
    if db_manager:
        audit_history = db_manager.sqlite.get_mitigation_audit_logs(limit=20)

    answer = copilot_instance.chat(
        user_query=req.prompt,
        audit_history=audit_history,
    )

    # Record chat in SQLite WAL
    if db_manager:
        chat_rec = LLMChatRecord(
            sender="user",
            prompt=req.prompt,
            response=answer,
            provider=copilot_instance.provider,
            model_name=copilot_instance.model_name,
        )
        db_manager.sqlite.insert_chat_message(chat_rec)

    return CopilotChatResponse(
        prompt=req.prompt,
        response=answer,
        provider=copilot_instance.provider,
        model_name=copilot_instance.model_name,
    )


@router.post("/telemetry/query")
def query_duckdb_telemetry(req: DuckDBSQLQueryRequest):
    """Execute analytical SQL queries directly against DuckDB columnar store."""
    if not db_manager or not db_manager.duckdb:
        raise HTTPException(status_code=503, detail="DuckDB storage engine not available")

    # Security check: disallow modifying queries
    sql_clean = req.sql.strip().upper()
    if not sql_clean.startswith("SELECT") and not sql_clean.startswith("WITH") and not sql_clean.startswith("SHOW"):
        raise HTTPException(status_code=400, detail="Only SELECT/WITH analytical queries are permitted")

    try:
        rows = db_manager.duckdb.query_sql(req.sql, limit=req.limit)
        return {"query": req.sql, "rows": rows, "count": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DuckDB SQL error: {str(e)}")
