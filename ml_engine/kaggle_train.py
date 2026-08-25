"""
Stand-Alone Cloud ML Training Pipeline for Kaggle / Colab / SageMaker.

Loads raw eBPF telemetry dataset files (.jsonl), extracts 12-dimensional feature vectors,
enriches with MITRE ATT&CK attack profiles across 11 threat categories, and fits
Isolation Forest, Random Forest (150 estimators), and XGBoost (150 estimators with histogram acceleration).

Can be run directly in Kaggle/Colab with 1-click!
"""

import argparse
import json
import math
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional, List, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix, f1_score
)
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("kaggle_train")

# ─────────────────────────────────────────────────────────────
# Central Configuration & Threat Labels
# ─────────────────────────────────────────────────────────────

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

THREAT_LABELS_INV = {v: k for k, v in THREAT_LABELS.items()}

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh",
    "/etc/pam.d", "/dev/mem", "/proc/kallsyms", "/sys/kernel/debug",
]

SUSPICIOUS_PARENTS = ["bash", "sh", "nc", "python", "python3", "curl", "wget", "perl"]

PRIV_ESCALATION_SYSCALLS = [105, 106, 107, 108, 165, 166]
MEMORY_EXEC_SYSCALLS = [9, 10, 319]


# ─────────────────────────────────────────────────────────────
# Feature Extractor for .jsonl Telemetry Datasets
# ─────────────────────────────────────────────────────────────

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


def extract_from_dataset(dataset_dir: Path) -> pd.DataFrame:
    """Reads all .jsonl telemetry dataset files and returns a pandas DataFrame of feature vectors."""
    jsonl_files = sorted(Path(dataset_dir).rglob("*.jsonl"))
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


# ─────────────────────────────────────────────────────────────
# Synthetic Attack Dataset Enrichment
# ─────────────────────────────────────────────────────────────

def generate_attack_dataset(benign_df: pd.DataFrame, num_samples_per_class: int = 5000) -> Tuple[pd.DataFrame, pd.Series]:
    np.random.seed(42)
    feature_list = []
    labels = []

    benign_features = benign_df[FEATURE_COLUMNS].copy() if not benign_df.empty else pd.DataFrame()
    if not benign_features.empty:
        feature_list.append(benign_features.values)
        labels.extend([THREAT_LABELS_INV["BENIGN"]] * len(benign_features))
        logger.info("Included %d real benign telemetry feature windows from dataset files.", len(benign_features))
    else:
        # Synthetic BENIGN workload (normal system processes)
        benign_syn = np.column_stack([
            np.random.uniform(50, 1000, num_samples_per_class),
            np.random.uniform(2.0, 4.5, num_samples_per_class),
            np.random.uniform(0.01, 0.15, num_samples_per_class),
            np.zeros(num_samples_per_class),
            np.zeros(num_samples_per_class),
            np.zeros(num_samples_per_class),
            np.random.uniform(0, 10, num_samples_per_class),
            np.random.uniform(0, 2, num_samples_per_class),
            np.zeros(num_samples_per_class),
            np.random.uniform(2, 5, num_samples_per_class),
            np.random.uniform(0.0, 0.02, num_samples_per_class),
            np.random.uniform(8, 25, num_samples_per_class),
        ])
        feature_list.append(benign_syn)
        labels.extend([THREAT_LABELS_INV["BENIGN"]] * num_samples_per_class)

    # 1. Ransomware
    rw = np.column_stack([
        np.random.uniform(5000, 100000, num_samples_per_class),
        np.random.uniform(1.2, 2.8, num_samples_per_class),
        np.random.uniform(0.75, 1.0, num_samples_per_class),
        np.random.choice([0, 1, 2], num_samples_per_class),
        np.random.choice([0, 1], num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(0, 50, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(1, 6, num_samples_per_class),
        np.random.uniform(0.0, 0.05, num_samples_per_class),
        np.random.uniform(4, 12, num_samples_per_class),
    ])
    feature_list.append(rw)
    labels.extend([THREAT_LABELS_INV["RANSOMWARE"]] * num_samples_per_class)

    # 2. Privilege Escalation
    pe = np.column_stack([
        np.random.uniform(10, 500, num_samples_per_class),
        np.random.uniform(0.5, 2.0, num_samples_per_class),
        np.random.uniform(0.0, 0.2, num_samples_per_class),
        np.random.uniform(1, 10, num_samples_per_class),
        np.random.uniform(3, 25, num_samples_per_class),
        np.random.choice([0, 1, 2], num_samples_per_class),
        np.random.uniform(0, 10, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.choice([0.0, 1.0], num_samples_per_class),
        np.random.uniform(2, 5, num_samples_per_class),
        np.random.uniform(0.05, 0.3, num_samples_per_class),
        np.random.uniform(3, 10, num_samples_per_class),
    ])
    feature_list.append(pe)
    labels.extend([THREAT_LABELS_INV["PRIVILEGE_ESCALATION"]] * num_samples_per_class)

    # 3. Reverse Shell
    rs = np.column_stack([
        np.random.uniform(20, 1000, num_samples_per_class),
        np.random.uniform(0.1, 0.9, num_samples_per_class),
        np.random.uniform(0.0, 0.1, num_samples_per_class),
        np.random.choice([0, 1, 2], num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(50, 500, num_samples_per_class),
        np.random.uniform(0, 5, num_samples_per_class),
        np.ones(num_samples_per_class),
        np.random.uniform(1, 4, num_samples_per_class),
        np.random.uniform(0.0, 0.1, num_samples_per_class),
        np.random.uniform(1, 5, num_samples_per_class),
    ])
    feature_list.append(rs)
    labels.extend([THREAT_LABELS_INV["REVERSE_SHELL"]] * num_samples_per_class)

    # 4. Data Exfiltration
    de = np.column_stack([
        np.random.uniform(500, 10000, num_samples_per_class),
        np.random.uniform(1.0, 2.5, num_samples_per_class),
        np.random.uniform(0.0, 0.1, num_samples_per_class),
        np.random.uniform(2, 15, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(500, 5000, num_samples_per_class),
        np.random.uniform(20, 200, num_samples_per_class),
        np.random.choice([0.0, 1.0], num_samples_per_class),
        np.random.uniform(2, 6, num_samples_per_class),
        np.random.uniform(0.0, 0.05, num_samples_per_class),
        np.random.uniform(4, 15, num_samples_per_class),
    ])
    feature_list.append(de)
    labels.extend([THREAT_LABELS_INV["DATA_EXFILTRATION"]] * num_samples_per_class)

    # 5. Kernel Rootkit
    rk = np.column_stack([
        np.random.uniform(100, 3000, num_samples_per_class),
        np.random.uniform(0.2, 1.2, num_samples_per_class),
        np.random.uniform(0.0, 0.3, num_samples_per_class),
        np.random.uniform(3, 12, num_samples_per_class),
        np.random.uniform(2, 10, num_samples_per_class),
        np.random.uniform(5, 50, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(1, 4, num_samples_per_class),
        np.random.uniform(0.0, 0.15, num_samples_per_class),
        np.random.uniform(2, 8, num_samples_per_class),
    ])
    feature_list.append(rk)
    labels.extend([THREAT_LABELS_INV["KERNEL_ROOTKIT"]] * num_samples_per_class)

    # 6. Crypto Miner
    cm = np.column_stack([
        np.random.uniform(100000, 500000, num_samples_per_class),
        np.random.uniform(0.0, 0.4, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.choice([0, 1], num_samples_per_class),
        np.random.uniform(1, 20, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.choice([0.0, 1.0], num_samples_per_class),
        np.random.uniform(2, 5, num_samples_per_class),
        np.random.uniform(0.0, 0.01, num_samples_per_class),
        np.random.uniform(1, 3, num_samples_per_class),
    ])
    feature_list.append(cm)
    labels.extend([THREAT_LABELS_INV["CRYPTO_MINER"]] * num_samples_per_class)

    # 7. Brute Force
    bf = np.column_stack([
        np.random.uniform(1000, 20000, num_samples_per_class),
        np.random.uniform(0.1, 0.8, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(1, 5, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(50, 500, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.choice([0.0, 1.0], num_samples_per_class),
        np.random.uniform(2, 5, num_samples_per_class),
        np.random.uniform(0.40, 0.95, num_samples_per_class),
        np.random.uniform(2, 6, num_samples_per_class),
    ])
    feature_list.append(bf)
    labels.extend([THREAT_LABELS_INV["BRUTE_FORCE"]] * num_samples_per_class)

    # 8. Container Escape
    ce = np.column_stack([
        np.random.uniform(50, 2000, num_samples_per_class),
        np.random.uniform(0.8, 2.2, num_samples_per_class),
        np.random.uniform(0.1, 0.5, num_samples_per_class),
        np.random.uniform(3, 15, num_samples_per_class),
        np.random.uniform(5, 30, num_samples_per_class),
        np.random.uniform(1, 10, num_samples_per_class),
        np.random.uniform(0, 100, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.ones(num_samples_per_class),
        np.random.uniform(1, 3, num_samples_per_class),
        np.random.uniform(0.01, 0.20, num_samples_per_class),
        np.random.uniform(5, 15, num_samples_per_class),
    ])
    feature_list.append(ce)
    labels.extend([THREAT_LABELS_INV["CONTAINER_ESCAPE"]] * num_samples_per_class)

    # 9. Log Tampering
    lt = np.column_stack([
        np.random.uniform(100, 5000, num_samples_per_class),
        np.random.uniform(0.5, 1.8, num_samples_per_class),
        np.random.uniform(0.85, 1.0, num_samples_per_class),
        np.random.uniform(4, 20, num_samples_per_class),
        np.random.choice([0, 1, 2], num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.choice([0.0, 1.0], num_samples_per_class),
        np.random.uniform(2, 6, num_samples_per_class),
        np.random.uniform(0.0, 0.10, num_samples_per_class),
        np.random.uniform(3, 8, num_samples_per_class),
    ])
    feature_list.append(lt)
    labels.extend([THREAT_LABELS_INV["LOG_TAMPERING"]] * num_samples_per_class)

    # 10. Denial of Service
    dos = np.column_stack([
        np.random.uniform(200000, 1000000, num_samples_per_class),
        np.random.uniform(0.0, 0.5, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(5000, 50000, num_samples_per_class),
        np.random.uniform(500, 5000, num_samples_per_class),
        np.random.choice([0.0, 1.0], num_samples_per_class),
        np.random.uniform(1, 4, num_samples_per_class),
        np.random.uniform(0.10, 0.50, num_samples_per_class),
        np.random.uniform(1, 4, num_samples_per_class),
    ])
    feature_list.append(dos)
    labels.extend([THREAT_LABELS_INV["DENIAL_OF_SERVICE"]] * num_samples_per_class)

    X_all = np.vstack(feature_list)
    y_all = pd.Series(labels, name="label")
    return pd.DataFrame(X_all, columns=FEATURE_COLUMNS), y_all


# ─────────────────────────────────────────────────────────────
# Execution Entry Point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Kaggle/Cloud ML Training Script for eBPF Engine")
    parser.add_argument("--dataset-dir", type=str, default="/kaggle/input", help="Path to directory containing .jsonl dataset files")
    parser.add_argument("--num-samples", type=int, default=5000, help="Number of attack samples per threat class")
    default_saved_dir = Path(__file__).resolve().parent / "models" / "saved_models"
    parser.add_argument("--output-dir", type=str, default=str(default_saved_dir), help="Directory to save trained models")
    parser.add_argument("--test-size", type=float, default=0.20, help="Test set split fraction")

    args, _ = parser.parse_known_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting Cloud Training Run (num_samples_per_class=%d, test_size=%.2f)...", args.num_samples, args.test_size)

    # 1. Automatically scan dataset_dir or search recursively across /kaggle/input for .jsonl dataset files
    dataset_path = Path(args.dataset_dir)
    benign_df = pd.DataFrame()

    if not dataset_path.exists() or len(list(dataset_path.rglob("*.jsonl"))) == 0:
        # Fallback search across all /kaggle/input directories
        kaggle_root = Path("/kaggle/input")
        if kaggle_root.exists():
            jsonl_files = list(kaggle_root.rglob("*.jsonl"))
            if jsonl_files:
                dataset_path = jsonl_files[0].parent
                logger.info("Automatically detected dataset directory at: %s", dataset_path)

    if dataset_path.exists():
        benign_df = extract_from_dataset(dataset_path)

    # 2. Enrich baseline telemetry with 11 threat profiles
    X_df, y = generate_attack_dataset(benign_df, num_samples_per_class=args.num_samples)
    logger.info("Combined Training Dataset Shape: %s (Total Feature Vectors: %d)", X_df.shape, len(X_df))

    # 3. Train-Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_df, y, test_size=args.test_size, random_state=42, stratify=y
    )

    logger.info("Train Set: %d samples | Test Set: %d samples", len(X_train), len(X_test))

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 1. Isolation Forest
    logger.info("Training Isolation Forest Anomaly Detector...")
    iso_forest = IsolationForest(n_estimators=150, contamination=0.05, random_state=42, n_jobs=-1)
    iso_forest.fit(X_train_scaled)

    # 2. Random Forest
    logger.info("Training Random Forest Classifier (150 trees)...")
    rf_clf = RandomForestClassifier(n_estimators=150, max_depth=20, class_weight="balanced", random_state=42, n_jobs=-1)
    rf_clf.fit(X_train_scaled, y_train)

    rf_preds = rf_clf.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_test, rf_preds, average="weighted")

    # 3. XGBoost
    logger.info("Training XGBoost Classifier (150 trees with histogram acceleration)...")
    xgb_clf = XGBClassifier(n_estimators=150, max_depth=8, learning_rate=0.1, tree_method="hist", eval_metric="mlogloss", random_state=42, n_jobs=-1)
    xgb_clf.fit(X_train_scaled, y_train)

    xgb_preds = xgb_clf.predict(X_test_scaled)
    xgb_acc = accuracy_score(y_test, xgb_preds)
    xgb_prec, xgb_rec, xgb_f1, _ = precision_recall_fscore_support(y_test, xgb_preds, average="weighted")

    # 4. Stratified 5-Fold Cross Validation
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    rf_cv_scores = cross_val_score(rf_clf, scaler.transform(X_df), y, cv=skf, scoring="f1_weighted", n_jobs=-1)

    target_names = [THREAT_LABELS[i] for i in sorted(THREAT_LABELS.keys()) if i in y.unique()]

    print("\n" + "=" * 80)
    print("           CLOUD HEAVY COMPUTATIONAL EVALUATION REPORT          ")
    print("=" * 80)
    print(f"Total Dataset Size : {len(X_df):,d} samples")
    print(f"Train Set ({100-int(args.test_size*100)}%) : {len(X_train):,d} samples")
    print(f"Test Set ({int(args.test_size*100)}%)  : {len(X_test):,d} samples")
    print("-" * 80)
    print(f"RANDOM FOREST  — Accuracy: {rf_acc:.4f} | Precision: {rf_prec:.4f} | Recall: {rf_rec:.4f} | F1-Score: {rf_f1:.4f}")
    print(f"XGBOOST        — Accuracy: {xgb_acc:.4f} | Precision: {xgb_prec:.4f} | Recall: {xgb_rec:.4f} | F1-Score: {xgb_f1:.4f}")
    print(f"5-FOLD CV F1   — Mean: {np.mean(rf_cv_scores):.4f} ± {np.std(rf_cv_scores):.4f}")
    print("-" * 80)
    print("\nClassification Report (Random Forest):")
    print(classification_report(y_test, rf_preds, target_names=target_names, digits=4))

    print("\nConfusion Matrix:")
    print(pd.DataFrame(
        confusion_matrix(y_test, rf_preds),
        index=[f"True_{t}" for t in target_names],
        columns=[f"Pred_{t}" for t in target_names]
    ).to_string())
    print("=" * 80)

    # Save serialized models
    joblib.dump(scaler, out_dir / "scaler.joblib")
    joblib.dump(iso_forest, out_dir / "isolation_forest.joblib")
    joblib.dump(rf_clf, out_dir / "random_forest.joblib")
    joblib.dump(xgb_clf, out_dir / "xgboost.joblib")

    logger.info("Saved model artifacts to %s", out_dir)


main()
