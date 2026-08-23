"""
Model Evaluation & Testing Tool for eBPF ML Engine (Local & Kaggle Cloud Compatible).

Loads serialized model artifacts from saved_models/ and evaluates them
against real eBPF kernel telemetry datasets in agent/data/ or /kaggle/input/.

Can be run locally or pasted directly into a Kaggle Notebook cell!
"""

import argparse
import json
import math
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix

# Enable relative and absolute imports from any CWD (Jupyter/Kaggle safe)
PROJECT_ROOT = Path(__file__).resolve().parent.parent if "__file__" in globals() else Path.cwd()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FEATURE_COLUMNS = [
    "syscall_rate", "syscall_entropy", "file_write_ratio", "sensitive_file_access",
    "privilege_events", "memory_rwx_count", "network_outbound_rate", "dns_query_rate",
    "parent_is_suspicious", "execution_path_depth", "failed_syscall_ratio", "unique_syscall_count",
]

THREAT_LABELS = {
    0: "BENIGN", 1: "RANSOMWARE", 2: "PRIVILEGE_ESCALATION", 3: "REVERSE_SHELL",
    4: "DATA_EXFILTRATION", 5: "KERNEL_ROOTKIT", 6: "CRYPTO_MINER",
    7: "BRUTE_FORCE", 8: "CONTAINER_ESCAPE", 9: "LOG_TAMPERING", 10: "DENIAL_OF_SERVICE",
}

SAVED_MODELS_DIR = "./saved_models"
DATASET_DIR = "/kaggle/input"

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh",
    "/etc/pam.d", "/dev/mem", "/proc/kallsyms", "/sys/kernel/debug",
]

SUSPICIOUS_PARENTS = ["bash", "sh", "nc", "python", "python3", "curl", "wget", "perl"]
PRIV_ESCALATION_SYSCALLS = [105, 106, 107, 108, 165, 166]
MEMORY_EXEC_SYSCALLS = [9, 10, 319]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("evaluate")


class PIDWindow:
    def __init__(self, pid: int, start_ns: int):
        self.pid = pid
        self.start_ns = start_ns
        self.end_ns = start_ns
        self.event_count = 0
        self.syscall_ids = []
        self.file_ops = []
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
        self.event_count += 1
        ts = ev.get("timestamp_ns", 0)
        if ts > self.end_ns:
            self.end_ns = ts

        event_type = ev.get("event_type", 0)
        syscall_id = ev.get("syscall_id", 0)
        retval = ev.get("retval", 0)
        filename = ev.get("filename", "")
        file_op = ev.get("file_op", 0)

        if ev.get("parent_comm"):
            self.parent_comm = ev["parent_comm"]
        if ev.get("exe_path"):
            self.exe_path = ev["exe_path"]
        if ev.get("comm"):
            self.comm = ev["comm"]

        if event_type == 1 and syscall_id > 0:
            self.syscall_ids.append(syscall_id)
        if event_type == 4:
            self.file_ops.append(file_op)
        if filename:
            for sp in SENSITIVE_PATHS:
                if filename.startswith(sp):
                    self.sensitive_hits += 1
                    break
        if event_type == 6 or syscall_id in PRIV_ESCALATION_SYSCALLS:
            self.priv_count += 1
        if event_type == 7 or syscall_id in MEMORY_EXEC_SYSCALLS:
            self.mem_exec_count += 1
        if event_type == 5:
            self.net_out_count += 1
            if ev.get("dst_port", 0) == 53:
                self.dns_count += 1
        if retval < 0:
            self.failed_count += 1

    def to_feature_vector(self) -> Optional[np.ndarray]:
        if self.event_count < 3:
            return None
        delta = self.end_ns - self.start_ns
        duration = 5.0 if delta <= 0 else delta / 1e9

        syscall_rate = self.event_count / duration
        syscall_entropy = self._entropy(self.syscall_ids)
        file_write_ratio = sum(1 for op in self.file_ops if op in (3, 4, 5)) / len(self.file_ops) if self.file_ops else 0.0
        sensitive_file_access = float(self.sensitive_hits)
        privilege_events = float(self.priv_count)
        memory_rwx_count = float(self.mem_exec_count)
        network_outbound_rate = self.net_out_count / duration
        dns_query_rate = self.dns_count / duration
        parent_is_suspicious = 1.0 if self.parent_comm.lower() in SUSPICIOUS_PARENTS else 0.0
        execution_path_depth = float(self.exe_path.count("/")) if self.exe_path else 0.0
        failed_syscall_ratio = self.failed_count / self.event_count if self.event_count > 0 else 0.0
        unique_syscall_count = float(len(set(self.syscall_ids)))

        return np.array([
            syscall_rate, syscall_entropy, file_write_ratio, sensitive_file_access,
            privilege_events, memory_rwx_count, network_outbound_rate, dns_query_rate,
            parent_is_suspicious, execution_path_depth, failed_syscall_ratio, unique_syscall_count,
        ], dtype=np.float64)

    @staticmethod
    def _entropy(vals: list) -> float:
        if not vals:
            return 0.0
        total = len(vals)
        counts = defaultdict(int)
        for v in vals:
            counts[v] += 1
        return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def extract_from_dataset(dataset_dir: Path, max_files: Optional[int] = None) -> pd.DataFrame:
    jsonl_files = sorted(Path(dataset_dir).rglob("*.jsonl"))
    if max_files is not None:
        jsonl_files = jsonl_files[:max_files]
    if not jsonl_files:
        logger.warning("No .jsonl dataset files found in %s", dataset_dir)
        return pd.DataFrame()

    logger.info("Found %d .jsonl dataset files in %s. Parsing raw events...", len(jsonl_files), dataset_dir)

    pid_events = defaultdict(list)
    total_events = 0

    for filepath in jsonl_files:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    pid = ev.get("pid", 0)
                    if pid > 0:
                        pid_events[pid].append(ev)
                        total_events += 1
                except json.JSONDecodeError:
                    continue

    logger.info("Successfully loaded %d raw eBPF telemetry events across %d unique PIDs.", total_events, len(pid_events))

    rows = []
    window_ns = int(5.0 * 1e9)

    for pid, events in pid_events.items():
        events.sort(key=lambda e: e.get("timestamp_ns", 0))
        window = PIDWindow(pid, events[0].get("timestamp_ns", 0))

        for ev in events:
            ts = ev.get("timestamp_ns", 0)
            if ts - window.start_ns > window_ns:
                vec = window.to_feature_vector()
                if vec is not None:
                    rows.append(vec)
                window = PIDWindow(pid, ts)
            window.ingest(ev)

        vec = window.to_feature_vector()
        if vec is not None:
            rows.append(vec)

    if not rows:
        return pd.DataFrame()

    logger.info("Extracted %d clean feature window vectors from raw dataset files.", len(rows))
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def run_evaluation():
    parser = argparse.ArgumentParser(description="Evaluate Trained eBPF Security ML Models")
    parser.add_argument("--models-dir", type=str, default="./saved_models", help="Directory containing saved .joblib models")
    parser.add_argument("--dataset-dir", type=str, default="/kaggle/input", help="Directory containing .jsonl telemetry files")
    parser.add_argument("--max-files", type=int, default=None, help="Max .jsonl files to evaluate (None for all)")

    args, _ = parser.parse_known_args()

    # 1. Resolve Models Directory
    models_dir = Path(args.models_dir)
    if not models_dir.exists():
        fallback_models = [Path("./saved_models"), Path("/kaggle/working/saved_models"), Path(SAVED_MODELS_DIR)]
        for p in fallback_models:
            if p.exists() and (p / "scaler.joblib").exists():
                models_dir = p
                break

    scaler_path = models_dir / "scaler.joblib"
    rf_path = models_dir / "random_forest.joblib"
    xgb_path = models_dir / "xgboost.joblib"
    iso_path = models_dir / "isolation_forest.joblib"

    if not (scaler_path.exists() and rf_path.exists()):
        logger.error("Model artifact files not found in %s! Ensure models are trained first.", models_dir)
        return

    logger.info("Loading saved model artifacts from %s...", models_dir)
    scaler = joblib.load(scaler_path)
    rf_clf = joblib.load(rf_path)
    xgb_clf = joblib.load(xgb_path) if xgb_path.exists() else None
    iso_forest = joblib.load(iso_path) if iso_path.exists() else None

    # 2. Resolve Telemetry Dataset Directory
    data_dir = Path(args.dataset_dir)
    jsonl_files = list(data_dir.rglob("*.jsonl")) if data_dir.exists() else []

    if not jsonl_files:
        fallback_data = [Path("/kaggle/input"), Path("./agent/data"), Path("../agent/data"), Path(DATASET_DIR)]
        for p in fallback_data:
            if p.exists():
                found = list(p.rglob("*.jsonl"))
                if found:
                    data_dir = p
                    jsonl_files = found
                    break

    if not jsonl_files:
        logger.error("No .jsonl telemetry dataset files found! Checked %s", data_dir)
        return

    logger.info("Found %d .jsonl telemetry dataset files in %s. Extracting feature vectors...", len(jsonl_files), data_dir)

    is_kaggle = Path("/kaggle").exists()
    max_files = args.max_files if args.max_files is not None else (None if is_kaggle else 10)

    # 3. Extract Feature Vectors
    X_df = extract_from_dataset(dataset_dir=data_dir, max_files=max_files)
    if X_df.empty:
        logger.error("Failed to extract feature vectors from dataset!")
        return

    logger.info("Successfully extracted %d feature window vectors across 12 dimensions.", len(X_df))

    # 4. Preprocess & Scale
    X_clean = X_df[FEATURE_COLUMNS].fillna(0).values
    X_scaled = scaler.transform(X_clean)

    # 5. Run Model Inference
    rf_preds = rf_clf.predict(X_scaled)
    rf_counts = pd.Series(rf_preds).value_counts().to_dict()

    xgb_preds = xgb_clf.predict(X_scaled) if xgb_clf else None
    xgb_counts = pd.Series(xgb_preds).value_counts().to_dict() if xgb_preds is not None else {}

    iso_anomalies = 0
    if iso_forest:
        iso_scores = iso_forest.score_samples(X_scaled)
        iso_anomalies = int((iso_scores < -0.3).sum())

    # 6. Display Evaluation & Testing Report
    print("\n" + "=" * 80)
    print("        EBPF SECURITY AGENT — KAGGLE & LOCAL MODEL TEST REPORT       ")
    print("=" * 80)
    print(f"Evaluated Dataset Path      : {data_dir}")
    print(f"Total .jsonl Files Evaluated: {len(jsonl_files)}")
    print(f"Extracted Feature Windows   : {len(X_df):,d} process observations")
    print("-" * 80)
    if iso_forest:
        print(f"ISOLATION FOREST ANOMALIES  : {iso_anomalies:,d} / {len(X_df):,d} ({iso_anomalies/len(X_df)*100:.2f}% anomaly rate)")
    print("-" * 80)

    print("\n[Random Forest] Inferred Threat Classification Distribution:")
    for label_id, name in sorted(THREAT_LABELS.items()):
        cnt = rf_counts.get(label_id, 0)
        pct = (cnt / len(X_df)) * 100
        print(f"  Class [{label_id:2d}] {name:<22}: {cnt:6,d} process windows ({pct:5.2f}%)")

    if xgb_clf:
        print("\n[XGBoost] Inferred Threat Classification Distribution:")
        for label_id, name in sorted(THREAT_LABELS.items()):
            cnt = xgb_counts.get(label_id, 0)
            pct = (cnt / len(X_df)) * 100
            print(f"  Class [{label_id:2d}] {name:<22}: {cnt:6,d} process windows ({pct:5.2f}%)")

    print("=" * 80)


if __name__ == "__main__":
    run_evaluation()
