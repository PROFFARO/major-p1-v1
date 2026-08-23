"""
Feedback subpackage — Automated Mitigation Controller & Audit Logging.

Provides the circular feedback loop between ML threat predictions
and eBPF kernel-level enforcement via the Go Agent's REST API.
"""

from ml_engine.feedback.actions import ActionType, MitigationAction, AuditLogger
from ml_engine.feedback.mitigator import MitigationController

__all__ = [
    "ActionType",
    "MitigationAction",
    "AuditLogger",
    "MitigationController",
]
