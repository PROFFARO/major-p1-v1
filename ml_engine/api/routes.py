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
mitigator_ref = None


def set_api_dependencies(
    db_mgr: DatabaseManager,
    copilot: LLMSecurityCopilot,
    engine=None,
    mitigator=None,
):
    """Inject global application dependencies into API routes."""
    global db_manager, copilot_instance, realtime_engine_ref, mitigator_ref
    db_manager = db_mgr
    copilot_instance = copilot
    realtime_engine_ref = engine
    mitigator_ref = mitigator


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthStatusResponse)
def get_health_status():
    """Return health and database connectivity status."""
    sqlite_mgr = db_manager.sqlite if db_manager else SQLiteWALManager()
    active_blocks = sqlite_mgr.get_active_blocks()
    return HealthStatusResponse(
        status="ok",
        duckdb_connected=db_manager is not None and db_manager.duckdb is not None,
        sqlite_connected=True,
        active_blocks_count=len(active_blocks),
    )


@router.get("/metrics/summary", response_model=MetricsSummaryResponse)
def get_metrics_summary():
    """Return live system telemetry, throughput rates, threat counts, and active blocks."""
    stats = {}
    if realtime_engine_ref:
        stats = realtime_engine_ref.get_stats()

    active_blocks = []
    if mitigator_ref:
        active_blocks = mitigator_ref.get_active_blocks()
    elif db_manager:
        active_blocks = db_manager.sqlite.get_active_blocks()

    copilot_mode = "ONLINE"
    if copilot_instance:
        copilot_mode = "ONLINE" if copilot_instance.is_available() else "OFFLINE"

    return MetricsSummaryResponse(
        total_events_ingested=stats.get("total_events_ingested", 0),
        events_per_second=stats.get("events_per_second", 0.0),
        active_feature_windows=stats.get("active_pid_windows", 0),
        total_threats_detected=stats.get("total_threats_detected", 0),
        threats_by_class=stats.get("threats_by_class", {}),
        active_kernel_blocks=len(active_blocks),
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
    """Query recent LSM kernel mitigation audit logs."""
    sqlite_mgr = db_manager.sqlite if db_manager else SQLiteWALManager()
    logs = sqlite_mgr.get_mitigation_audit_logs(limit=limit)
    return {"audit_logs": logs, "count": len(logs)}


@router.get("/blocks/active")
def get_active_blocks():
    """List active kernel PID blocklist entries."""
    if mitigator_ref:
        blocks = mitigator_ref.get_active_blocks()
    else:
        sqlite_mgr = db_manager.sqlite if db_manager else SQLiteWALManager()
        blocks = sqlite_mgr.get_active_blocks()
    return {"active_blocks": blocks, "count": len(blocks)}


@router.post("/blocks/unblock")
def unblock_pid(req: UnblockRequest):
    """Manually unblock a PID via Go Agent REST API and remove from database."""
    success = False
    if mitigator_ref:
        success = mitigator_ref.unblock_pid(req.pid, reason=req.reason)
    else:
        sqlite_mgr = db_manager.sqlite if db_manager else SQLiteWALManager()
        success = sqlite_mgr.remove_active_block(req.pid)

    if not success:
        raise HTTPException(status_code=404, detail=f"PID {req.pid} not found in active kernel blocklist")

    return {"status": "unblocked", "pid": req.pid, "reason": req.reason}


@router.post("/copilot/chat", response_model=CopilotChatResponse)
def copilot_chat(req: CopilotChatRequest):
    """Query Universal LLM Security Analyst Copilot and persist interaction."""
    if not copilot_instance:
        raise HTTPException(status_code=503, detail="LLMSecurityCopilot service not initialized")

    active_blocks = []
    if mitigator_ref:
        active_blocks = mitigator_ref.get_active_blocks()

    audit_history = []
    if db_manager:
        audit_history = db_manager.sqlite.get_mitigation_audit_logs(limit=20)

    answer = copilot_instance.chat(
        user_query=req.prompt,
        audit_history=audit_history,
        active_blocks=active_blocks,
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
