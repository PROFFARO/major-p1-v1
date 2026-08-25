"""
Mitigation Action Types & Audit Logger for the eBPF-ML Feedback Loop.

Defines structured action records and persistent JSONL audit logging
for every mitigation decision made by the MitigationController.
"""

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ml_engine.feedback.actions")


# ─────────────────────────────────────────────────────────────
# Action Types
# ─────────────────────────────────────────────────────────────

class ActionType(str, Enum):
    """All possible outcomes of a mitigation evaluation."""

    BLOCK_PID = "BLOCK_PID"               # PID blocked via Go Agent REST API
    BLOCK_IP = "BLOCK_IP"                 # IP blocked via Go Agent REST API
    UNBLOCK_PID = "UNBLOCK_PID"           # PID unblocked (manual or auto-expire)
    UNBLOCK_IP = "UNBLOCK_IP"             # IP unblocked (manual or auto-expire)
    LOG_ONLY = "LOG_ONLY"                 # Threat detected but only logged (dry-run)
    SKIP_BENIGN = "SKIP_BENIGN"           # Prediction was BENIGN, no action needed
    SKIP_PROTECTED = "SKIP_PROTECTED"     # PID or process name is in protected allowlist
    SKIP_LOW_CONFIDENCE = "SKIP_LOW_CONFIDENCE"  # Confidence below threshold
    SKIP_NO_CONSENSUS = "SKIP_NO_CONSENSUS"      # RF and XGBoost disagreed on class
    SKIP_COOLDOWN = "SKIP_COOLDOWN"       # PID was recently blocked, in cooldown
    SKIP_MAX_BLOCKS = "SKIP_MAX_BLOCKS"   # Maximum active blocks reached


# ─────────────────────────────────────────────────────────────
# Mitigation Action Record (immutable)
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MitigationAction:
    """
    Immutable record of a single mitigation decision.

    Every evaluation by MitigationController produces exactly one
    MitigationAction, regardless of whether the process was blocked,
    skipped, or logged. This forms the forensic audit trail.
    """

    action_id: str                         # Unique UUID for this action
    timestamp: str                         # ISO 8601 timestamp
    pid: int                               # Process ID evaluated
    comm: str                              # Process command name
    exe_path: str                          # Executable path
    parent_comm: str                       # Parent process command name
    threat_id: int                         # Predicted threat class ID (0-10)
    threat_name: str                       # Predicted threat class name
    rf_threat_name: str                    # Random Forest prediction
    xgb_threat_name: str                   # XGBoost prediction
    confidence: float                      # Classifier confidence (0.0 - 1.0)
    anomaly_score: float                   # Isolation Forest anomaly score
    is_anomaly: bool                       # Whether Isolation Forest flagged it
    action_taken: str                      # ActionType value
    reason: str                            # Human-readable explanation
    agent_response: Optional[str] = None   # Go Agent HTTP response (if API called)
    is_permanent: bool = False             # Whether block is permanent (no auto-expire)
    expire_at: Optional[str] = None        # ISO 8601 expiry time (if auto-expire)

    def to_dict(self) -> dict:
        """Convert to serializable dictionary."""
        return asdict(self)


def create_action(
    pid: int,
    metadata: dict,
    threat_result: dict,
    rf_threat: str,
    xgb_threat: str,
    action_type: ActionType,
    reason: str,
    agent_response: Optional[str] = None,
    is_permanent: bool = False,
    expire_at: Optional[datetime] = None,
) -> MitigationAction:
    """Factory function to create a MitigationAction with standard fields."""
    return MitigationAction(
        action_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        pid=pid,
        comm=metadata.get("comm", ""),
        exe_path=metadata.get("exe_path", ""),
        parent_comm=metadata.get("parent_comm", ""),
        threat_id=threat_result.get("threat_id", 0),
        threat_name=threat_result.get("threat_name", "UNKNOWN"),
        rf_threat_name=rf_threat,
        xgb_threat_name=xgb_threat,
        confidence=threat_result.get("confidence", 0.0),
        anomaly_score=threat_result.get("anomaly_score", 0.0),
        is_anomaly=threat_result.get("is_anomaly", False),
        action_taken=action_type.value,
        reason=reason,
        agent_response=agent_response,
        is_permanent=is_permanent,
        expire_at=expire_at.isoformat() if expire_at else None,
    )


# ─────────────────────────────────────────────────────────────
# Audit Logger (append-only JSONL file)
# ─────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Persistent append-only audit logger for mitigation actions.

    Every MitigationAction is serialized as a single JSON line in
    the audit log file. This provides a complete forensic trail of
    all decisions made by the automated mitigation controller.
    """

    def __init__(self, log_path: Optional[Path] = None):
        if log_path is None:
            from ml_engine.config import AUDIT_LOG_PATH
            log_path = AUDIT_LOG_PATH
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._action_count = 0

    def record(self, action: MitigationAction) -> None:
        """Append a MitigationAction to the audit log file and SQLite WAL store."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(action.to_dict(), default=str) + "\n")
            self._action_count += 1
            logger.debug(
                "Audit [%s] PID=%d threat=%s action=%s",
                action.action_id[:8], action.pid,
                action.threat_name, action.action_taken,
            )

            # Persist to SQLite WAL store
            try:
                from ml_engine.storage import SQLiteWALManager, MitigationAuditRecord
                sqlite_mgr = SQLiteWALManager()
                if isinstance(action.timestamp, (int, float)):
                    ts_str = datetime.fromtimestamp(action.timestamp, tz=timezone.utc).isoformat()
                else:
                    ts_str = str(action.timestamp)

                is_success = bool(action.agent_response or action.action_taken.startswith("SKIP") or action.action_taken == "LOG_ONLY")
                is_dry_run = bool(action.action_taken == "LOG_ONLY" or action.action_taken.startswith("SKIP"))

                rec = MitigationAuditRecord(
                    timestamp=ts_str,
                    pid=action.pid,
                    comm=action.comm,
                    threat_name=action.threat_name,
                    action_taken=action.action_taken,
                    confidence=action.confidence,
                    success=is_success,
                    dry_run=is_dry_run,
                    details=action.reason,
                )
                sqlite_mgr.insert_mitigation_audit(rec)
            except Exception as sql_err:
                logger.warning("Failed to record audit action to SQLite: %s", sql_err)

        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

    def read_all(self) -> list[MitigationAction]:
        """Read all actions from the audit log file."""
        actions = []
        if not self.log_path.exists():
            return actions
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    actions.append(MitigationAction(**data))
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning("Skipping malformed audit entry: %s", e)
        return actions

    def get_stats(self) -> dict:
        """Return summary statistics from the audit log."""
        actions = self.read_all()
        stats = {
            "total_evaluations": len(actions),
            "total_blocked": sum(1 for a in actions if a.action_taken in (ActionType.BLOCK_PID.value, ActionType.BLOCK_IP.value)),
            "total_skipped_protected": sum(1 for a in actions if a.action_taken == ActionType.SKIP_PROTECTED.value),
            "total_skipped_benign": sum(1 for a in actions if a.action_taken == ActionType.SKIP_BENIGN.value),
            "total_skipped_low_conf": sum(1 for a in actions if a.action_taken == ActionType.SKIP_LOW_CONFIDENCE.value),
            "total_skipped_no_consensus": sum(1 for a in actions if a.action_taken == ActionType.SKIP_NO_CONSENSUS.value),
            "total_skipped_cooldown": sum(1 for a in actions if a.action_taken == ActionType.SKIP_COOLDOWN.value),
            "total_log_only": sum(1 for a in actions if a.action_taken == ActionType.LOG_ONLY.value),
            "total_unblocked": sum(1 for a in actions if a.action_taken in (ActionType.UNBLOCK_PID.value, ActionType.UNBLOCK_IP.value)),
        }
        return stats

    @property
    def action_count(self) -> int:
        return self._action_count
