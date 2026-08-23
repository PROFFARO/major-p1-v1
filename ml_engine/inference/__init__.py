"""
Inference subpackage — Real-Time Streaming Ingestion Engine.

Provides real-time ingestion from Go Agent WebSocket to feature extraction,
ML inference, and automated kernel mitigation.
"""

from ml_engine.inference.realtime_engine import RealtimeIngestionEngine

__all__ = ["RealtimeIngestionEngine"]
