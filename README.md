# KShark — eBPF-ML Security Engine

Hybrid Python/Go security platform with real-time ML ingestion, DuckDB analytics, and interactive GUI.

- Agent: `agent/` (Go eBPF, see `agent/BUILD.md`)
- ML engine: `ml_engine/` (FastAPI + real-time ingestion)
- GUI: `kshark/` (PyQt6, see `kshark/GUI_ML_UPDATE.md`)
- Config: `sec-engine.yaml`
- Tests: `python -m pytest tests/`
- Build agent: `cd agent && go build -o ebpf-ml-agent ./cmd/agent`

Phase 1–6 improvements completed: secrets removed, SQL parameterized (`kshark/core/param_queries.py`), schema validation (`ml_engine/preprocessing/schemas.py`), dataset provenance (`scripts/telemetry_manifest.py`), build docs (`agent/BUILD.md`), CI/template (`tests/test_security_sanitization.py`).
