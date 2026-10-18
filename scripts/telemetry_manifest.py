"""Telemetry dataset provenance — SHA256 hashes + metadata for validation."""
import hashlib
from pathlib import Path

MANIFEST = {
    "200k_events.jsonl": "PLACEHOLDER_SHA256_HERE",
    "schema_version": "1.0",
    "generator": "scripts/generate_large_telemetry.py",
}

def verify_hash(filepath: str, expected: str) -> bool:
    """Verify file integrity via SHA256."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest() == expected
