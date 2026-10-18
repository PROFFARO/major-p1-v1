"""Telemetry event schema validation (Pydantic) — prevents bad data entering DuckDB."""
from pydantic import BaseModel, Field
from typing import Literal

class TelemetryEvent(BaseModel):
    event_id: str = Field(..., min_length=1)
    timestamp: float
    source_ip: str
    event_type: Literal["network", "process", "file", "syscall"]
    severity: float = Field(..., ge=-1.0, le=1.0)
    feature_vector: list[float] = Field(..., min_length=1)
