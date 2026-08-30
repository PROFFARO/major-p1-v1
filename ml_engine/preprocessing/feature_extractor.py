"""
Feature Extractor for the eBPF-ML Security Engine.

Transforms raw kernel telemetry events (from .jsonl dataset files or live
WebSocket streams) into 12-dimensional numerical feature vectors per process
(PID) over configurable sliding time windows.

Two modes of operation:
  1. Batch mode  — reads .jsonl files and produces pandas DataFrames for
                   model training via `extract_from_dataset()`.
  2. Stream mode — accepts events one-at-a-time via `ingest()` and produces
                   feature vectors when a window closes via `flush_window()`.

Feature Dimensions:
  0  syscall_rate          Total events per second in the window.
  1  syscall_entropy       Shannon entropy of system call ID distribution.
  2  file_write_ratio      Ratio of write/unlink/rename ops to total file ops.
  3  sensitive_file_access  Count of accesses to security-critical paths.
  4  privilege_events       Count of privilege-escalation system calls.
  5  memory_rwx_count      Count of mprotect/mmap with PROT_EXEC semantics.
  6  network_outbound_rate  Outbound socket operations per second.
  7  dns_query_rate         DNS-related activity rate per second.
  8  parent_is_suspicious   Binary flag for suspicious parent processes.
  9  execution_path_depth   Directory depth of the executable path.
  10 failed_syscall_ratio   Ratio of events with negative return values.
  11 unique_syscall_count   Count of distinct system call IDs observed.
"""

import json
import math
import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml_engine.config import (
    FEATURE_COLUMNS,
    SLIDING_WINDOW_SECONDS,
    MIN_EVENTS_PER_WINDOW,
    SENSITIVE_PATHS,
    PRIV_ESCALATION_SYSCALLS,
    MEMORY_EXEC_SYSCALLS,
    MODULE_LOAD_SYSCALLS,
    SUSPICIOUS_PARENTS,
    DATASET_DIR,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Event Type Constants (mirrors agent/ebpf/event.go)
# ─────────────────────────────────────────────────────────────

EVENT_SYSCALL = 1
EVENT_EXEC    = 2
EVENT_EXIT    = 3
EVENT_FILE    = 4
EVENT_NET     = 5
EVENT_PRIV    = 6
EVENT_MEM     = 7

# File operation constants (mirrors bpf/include/common.h)
FILE_OP_OPEN    = 1
FILE_OP_READ    = 2
FILE_OP_WRITE   = 3
FILE_OP_UNLINK  = 4
FILE_OP_RENAME  = 5
FILE_OP_CHMOD   = 6
FILE_OP_CHOWN   = 7

EVENT_TYPE_MAP = {
    "SYSCALL": EVENT_SYSCALL,
    "SYS_EXEC": EVENT_EXEC,
    "EXEC": EVENT_EXEC,
    "EXIT": EVENT_EXIT,
    "FILE": EVENT_FILE,
    "NET": EVENT_NET,
    "PRIV": EVENT_PRIV,
    "MEM": EVENT_MEM,
}


# ─────────────────────────────────────────────────────────────
# Sliding Window Accumulator (per PID)
# ─────────────────────────────────────────────────────────────

class PIDWindow:
    """Accumulates raw event statistics for a single PID over a time window."""

    __slots__ = (
        "pid", "start_ns", "end_ns", "event_count",
        "syscall_ids", "file_ops", "sensitive_hits",
        "priv_count", "mem_exec_count", "net_out_count",
        "dns_count", "failed_count", "parent_comm",
        "exe_path", "comm",
    )

    def __init__(self, pid: int, start_ns: int):
        self.pid = pid
        self.start_ns = start_ns
        self.end_ns = start_ns
        self.event_count = 0

        self.syscall_ids: list[int] = []
        self.file_ops: list[int] = []
        self.sensitive_hits = 0
        self.priv_count = 0
        self.mem_exec_count = 0
        self.net_out_count = 0
        self.dns_count = 0
        self.failed_count = 0

        self.parent_comm = ""
        self.exe_path = ""
        self.comm = ""

    def ingest(self, ev: dict) -> None:
        """Incorporate a single telemetry event into this window."""
        self.event_count += 1
        ts = ev.get("timestamp_ns", 0)
        if ts > self.end_ns:
            self.end_ns = ts

        event_type = ev.get("event_type", 0)
        if isinstance(event_type, str):
            event_type = EVENT_TYPE_MAP.get(event_type.upper(), EVENT_SYSCALL)

        syscall_id = ev.get("syscall_id", 0)
        retval = ev.get("retval", 0)
        filename = ev.get("filename", "") or ev.get("file_path", "")
        file_op = ev.get("file_op", 0)
        parent = ev.get("parent_comm", "")
        exe = ev.get("exe_path", "")
        comm = ev.get("comm", "")

        # Track the latest known metadata
        if parent:
            self.parent_comm = parent
        if exe:
            self.exe_path = exe
        if comm:
            self.comm = comm

        # ── Syscall ID tracking ──
        if (event_type in (EVENT_SYSCALL, EVENT_EXEC)) and syscall_id > 0:
            self.syscall_ids.append(syscall_id)

        # ── File operation tracking ──
        if event_type == EVENT_FILE:
            self.file_ops.append(file_op)

        # ── Sensitive file access detection ──
        if filename:
            for sp in SENSITIVE_PATHS:
                if filename.startswith(sp):
                    self.sensitive_hits += 1
                    break

        # ── Privilege escalation tracking ──
        if event_type == EVENT_PRIV:
            self.priv_count += 1
        elif event_type == EVENT_SYSCALL and syscall_id in PRIV_ESCALATION_SYSCALLS:
            self.priv_count += 1

        # ── Memory execution tracking ──
        if event_type == EVENT_MEM:
            self.mem_exec_count += 1
        elif event_type == EVENT_SYSCALL and syscall_id in MEMORY_EXEC_SYSCALLS:
            self.mem_exec_count += 1

        # ── Network outbound tracking ──
        if event_type == EVENT_NET:
            self.net_out_count += 1
            dst_port = ev.get("dst_port", 0)
            if dst_port == 53:
                self.dns_count += 1

        # ── Failed syscall tracking ──
        if retval < 0:
            self.failed_count += 1

    def duration_seconds(self) -> float:
        """Return window duration in seconds."""
        delta = self.end_ns - self.start_ns
        if delta <= 0:
            return SLIDING_WINDOW_SECONDS
        return delta / 1e9

    def to_live_vector(self, min_events: int = 1) -> Optional[np.ndarray]:
        """
        Compute the 12-dimensional feature vector for real-time inference without waiting for window close.
        """
        if self.event_count < min_events:
            return None

        duration = self.duration_seconds()
        if duration <= 0:
            duration = 1.0

        syscall_rate = self.event_count / duration
        syscall_entropy = _shannon_entropy(self.syscall_ids)

        total_file_ops = len(self.file_ops)
        if total_file_ops > 0:
            write_ops = sum(
                1 for op in self.file_ops
                if op in (FILE_OP_WRITE, FILE_OP_UNLINK, FILE_OP_RENAME)
            )
            file_write_ratio = write_ops / total_file_ops
        else:
            file_write_ratio = 0.0

        sensitive_file_access = float(self.sensitive_hits)
        privilege_events = float(self.priv_count)
        memory_rwx_count = float(self.mem_exec_count)
        network_outbound_rate = self.net_out_count / duration
        dns_query_rate = self.dns_count / duration
        parent_is_suspicious = 1.0 if self.parent_comm.lower() in SUSPICIOUS_PARENTS else 0.0

        if self.exe_path:
            execution_path_depth = float(self.exe_path.count("/"))
        else:
            execution_path_depth = 0.0

        if self.event_count > 0:
            failed_syscall_ratio = self.failed_count / self.event_count
        else:
            failed_syscall_ratio = 0.0

        unique_syscall_count = float(len(set(self.syscall_ids)))

        return np.array([
            syscall_rate,
            syscall_entropy,
            file_write_ratio,
            sensitive_file_access,
            privilege_events,
            memory_rwx_count,
            network_outbound_rate,
            dns_query_rate,
            parent_is_suspicious,
            execution_path_depth,
            failed_syscall_ratio,
            unique_syscall_count,
        ], dtype=np.float64)

    def to_feature_vector(self) -> Optional[np.ndarray]:
        """
        Compute the 12-dimensional feature vector from accumulated statistics.
        Returns None if the window has insufficient data.
        """
        if self.event_count < MIN_EVENTS_PER_WINDOW:
            return None
        return self.to_live_vector(min_events=MIN_EVENTS_PER_WINDOW)

    def to_metadata(self) -> dict:
        """Return PID metadata (not used as features, but useful for labeling)."""
        return {
            "pid": self.pid,
            "comm": self.comm,
            "exe_path": self.exe_path,
            "parent_comm": self.parent_comm,
            "event_count": self.event_count,
            "window_duration_s": self.duration_seconds(),
        }


# ─────────────────────────────────────────────────────────────
# Streaming Feature Extractor (real-time per-PID sliding windows)
# ─────────────────────────────────────────────────────────────

class StreamingExtractor:
    """
    Maintains per-PID sliding windows for real-time feature extraction.

    Usage:
        extractor = StreamingExtractor()
        for event in websocket_stream:
            results = extractor.ingest(event)
            for pid, feature_vec, metadata in results:
                # feed to ML model
    """

    def __init__(self, window_seconds: float = SLIDING_WINDOW_SECONDS):
        self.window_ns = int(window_seconds * 1e9)
        self.windows: dict[int, PIDWindow] = {}

    def get_live_vector(self, pid: int) -> Optional[np.ndarray]:
        """Returns the current real-time feature vector for an active PID."""
        if pid in self.windows:
            return self.windows[pid].to_live_vector(min_events=1)
        return None


    def ingest(self, ev: dict) -> list[tuple[int, np.ndarray, dict]]:
        """
        Process a single event. Returns a list of (pid, feature_vector, metadata)
        tuples for any windows that have closed due to timestamp or event volume threshold.
        """
        pid = ev.get("pid", 0)
        ts = ev.get("timestamp_ns", 0)

        if pid == 0 or ts == 0:
            return []

        # Check if this PID has an active window
        if pid not in self.windows:
            self.windows[pid] = PIDWindow(pid, ts)

        window = self.windows[pid]

        # If window duration exceeded or event count reaches batch threshold (25 events), flush and evaluate
        results = []
        if (ts - window.start_ns > self.window_ns) or (window.event_count >= 25):
            vec = window.to_feature_vector()
            if vec is not None:
                results.append((pid, vec, window.to_metadata()))
            # Start fresh window
            self.windows[pid] = PIDWindow(pid, ts)
            window = self.windows[pid]

        window.ingest(ev)
        return results

    def process_event(self, ev: dict) -> list[tuple[int, np.ndarray, dict]]:
        """Alias for ingest() method."""
        return self.ingest(ev)

    def flush_expired(self, current_ns: int = 0) -> list[tuple[int, np.ndarray, dict]]:
        """Flush any active windows that have exceeded the sliding window duration or have pending events."""
        if current_ns <= 0:
            current_ns = int(time.time() * 1e9)
        results = []
        pids_to_remove = []
        for pid, window in list(self.windows.items()):
            if (current_ns - window.start_ns > self.window_ns) or (window.event_count >= MIN_EVENTS_PER_WINDOW):
                vec = window.to_feature_vector()
                if vec is not None:
                    results.append((pid, vec, window.to_metadata()))
                pids_to_remove.append(pid)
        for pid in pids_to_remove:
            del self.windows[pid]
        return results

    def flush_all(self) -> list[tuple[int, np.ndarray, dict]]:
        """Flush all active windows and return their feature vectors."""
        results = []
        for pid, window in self.windows.items():
            vec = window.to_feature_vector()
            if vec is not None:
                results.append((pid, vec, window.to_metadata()))
        self.windows.clear()
        return results


# ─────────────────────────────────────────────────────────────
# Batch Feature Extractor (dataset files → training DataFrame)
# ─────────────────────────────────────────────────────────────

def extract_from_dataset(
    dataset_dir: Optional[Path] = None,
    max_files: Optional[int] = None,
    window_seconds: float = SLIDING_WINDOW_SECONDS,
) -> pd.DataFrame:
    """
    Load .jsonl telemetry files, group events into per-PID time windows,
    and return a pandas DataFrame of feature vectors ready for ML training.

    Each row represents one (PID, time_window) observation with 12 features
    plus metadata columns (pid, comm, exe_path, parent_comm).

    Args:
        dataset_dir: Path to directory containing .jsonl files.
        max_files:   Maximum number of .jsonl files to process (for testing).
        window_seconds: Sliding window duration in seconds.

    Returns:
        DataFrame with columns: FEATURE_COLUMNS + metadata columns.
    """
    if dataset_dir is None:
        dataset_dir = DATASET_DIR

    dataset_dir = Path(dataset_dir)
    jsonl_files = sorted(dataset_dir.glob("*.jsonl"))

    if not jsonl_files:
        raise FileNotFoundError(f"No .jsonl files found in {dataset_dir}")

    if max_files:
        jsonl_files = jsonl_files[:max_files]

    logger.info("Processing %d .jsonl files from %s", len(jsonl_files), dataset_dir)

    # Collect all events grouped by PID
    pid_events: dict[int, list[dict]] = defaultdict(list)
    total_events = 0

    for filepath in jsonl_files:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue

                pid = ev.get("pid", 0)
                if pid == 0:
                    continue

                pid_events[pid].append(ev)
                total_events += 1

    logger.info(
        "Loaded %d events across %d unique PIDs", total_events, len(pid_events)
    )

    # Process each PID's events into time windows
    window_ns = int(window_seconds * 1e9)
    rows = []
    meta_rows = []

    for pid, events in pid_events.items():
        # Sort events by timestamp
        events.sort(key=lambda e: e.get("timestamp_ns", 0))

        # Segment into windows
        window = PIDWindow(pid, events[0].get("timestamp_ns", 0))

        for ev in events:
            ts = ev.get("timestamp_ns", 0)

            # Check if event falls outside current window
            if ts - window.start_ns > window_ns:
                vec = window.to_feature_vector()
                if vec is not None:
                    rows.append(vec)
                    meta_rows.append(window.to_metadata())
                window = PIDWindow(pid, ts)

            window.ingest(ev)

        # Flush final window for this PID
        vec = window.to_feature_vector()
        if vec is not None:
            rows.append(vec)
            meta_rows.append(window.to_metadata())

    if not rows:
        raise ValueError("No valid feature windows extracted from dataset")

    # Build DataFrame
    feature_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    meta_df = pd.DataFrame(meta_rows)

    result = pd.concat([feature_df, meta_df], axis=1)

    logger.info(
        "Extracted %d feature windows (%d features each)",
        len(result),
        len(FEATURE_COLUMNS),
    )

    return result


# ─────────────────────────────────────────────────────────────
# Helper: Shannon Entropy
# ─────────────────────────────────────────────────────────────

def _shannon_entropy(values: list[int]) -> float:
    """
    Compute the Shannon entropy of a discrete distribution.

    High entropy = diverse syscall usage (normal multi-purpose process).
    Low entropy = repetitive syscall pattern (potential shellcode, crypto miner).
    """
    if not values:
        return 0.0

    total = len(values)
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1

    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


# ─────────────────────────────────────────────────────────────
# CLI: Run feature extraction on existing dataset
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(message)s",
    )

    logger.info("Running batch feature extraction...")
    df = extract_from_dataset(max_files=5)

    print("\n" + "=" * 72)
    print(f"Feature Matrix Shape: {df[FEATURE_COLUMNS].shape}")
    print(f"Total Windows: {len(df)}")
    print(f"Unique PIDs: {df['pid'].nunique()}")
    print("=" * 72)

    print("\nFeature Statistics:")
    print(df[FEATURE_COLUMNS].describe().to_string())

    print("\nSample rows (first 5):")
    print(df.head().to_string())
