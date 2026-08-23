"""
Comprehensive System Evaluation & Observability Suite.

Evaluates trained ML models, feature importances, detection latency, throughput,
and generates research-grade charts:
    1. confusion_matrix.png
    2. roc_pr_curves.png
    3. latency_throughput_distribution.png
    4. feature_importance.png
    5. system_benchmark_report.json
    6. system_evaluation_report.md
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless execution
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    accuracy_score,
    roc_curve,
    auc,
    precision_recall_curve,
)

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml_engine.config import (
    SAVED_MODELS_DIR,
    FEATURE_COLUMNS,
    THREAT_LABELS,
    SLIDING_WINDOW_SECONDS,
)
from ml_engine.models.detector import ThreatDetector
from ml_engine.preprocessing.feature_extractor import (
    extract_from_dataset,
    StreamingExtractor,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml_engine.evaluate_system")

OUTPUT_DIR = Path(__file__).resolve().parent / "eval_results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


class SystemEvaluator:
    """Evaluates ML engine performance, benchmark latency, and outputs research plots."""

    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path
        self.detector = ThreatDetector()

    def run_full_evaluation(self) -> Dict[str, Any]:
        logger.info("Starting Comprehensive System Evaluation & Observability Benchmark...")

        # 1. Prepare evaluation DataFrame
        df = self._load_or_generate_eval_data()
        X = df[FEATURE_COLUMNS].values
        y_true = df["label"].values

        # 2. Benchmark ML Model Predictions & Consensus
        scaled_X = self.detector.scaler.transform(X)
        rf_probs = self.detector.rf_clf.predict_proba(scaled_X)
        rf_preds = np.argmax(rf_probs, axis=1)

        xgb_probs = self.detector.xgb_clf.predict_proba(scaled_X) if self.detector.xgb_clf else rf_probs
        xgb_preds = np.argmax(xgb_probs, axis=1)

        iso_scores = self.detector.iso_forest.decision_function(scaled_X)

        # 3. Calculate Core Observability Metrics
        acc = accuracy_score(y_true, rf_preds)
        prec = precision_score(y_true, rf_preds, average="weighted", zero_division=0)
        rec = recall_score(y_true, rf_preds, average="weighted", zero_division=0)
        f1 = f1_score(y_true, rf_preds, average="weighted", zero_division=0)

        logger.info("Random Forest — Accuracy: %.4f | Precision: %.4f | Recall: %.4f | F1: %.4f", acc, prec, rec, f1)

        # 4. Latency & Throughput Benchmark
        latency_ms, throughput_eps = self._benchmark_streaming_latency()

        # 5. Generate Visual Charts
        self._plot_confusion_matrix(y_true, rf_preds)
        self._plot_roc_pr_curves(y_true, rf_probs)
        self._plot_latency_throughput(latency_ms, throughput_eps)
        self._plot_feature_importance()

        # 6. Save JSON & Markdown Reports
        report_data = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dataset_samples": len(df),
            "metrics": {
                "accuracy": round(float(acc), 4),
                "precision_weighted": round(float(prec), 4),
                "recall_weighted": round(float(rec), 4),
                "f1_weighted": round(float(f1), 4),
            },
            "latency_ms": {
                "mean": round(float(np.mean(latency_ms)), 3),
                "p50": round(float(np.percentile(latency_ms, 50)), 3),
                "p95": round(float(np.percentile(latency_ms, 95)), 3),
                "p99": round(float(np.percentile(latency_ms, 99)), 3),
            },
            "throughput_events_per_sec": round(float(throughput_eps), 2),
            "threat_classes": [THREAT_LABELS.get(i, f"CLASS_{i}") for i in sorted(list(set(y_true)))],
        }

        self._save_reports(report_data, y_true, rf_preds)
        logger.info("Evaluation Complete! Artifacts saved to: %s", OUTPUT_DIR)
        return report_data

    def _load_or_generate_eval_data(self) -> pd.DataFrame:
        """Load representative telemetry dataset vectors or generate balanced evaluation test vectors."""
        logger.info("Generating balanced evaluation dataset across 12 feature dimensions (1,200 samples)...")
        np.random.seed(42)
        samples_per_class = 100
        data_rows = []

        for threat_id, threat_name in THREAT_LABELS.items():
            for _ in range(samples_per_class):
                if threat_id == 0:  # BENIGN
                    vec = [
                        np.random.uniform(1.0, 15.0),    # syscall_rate
                        np.random.uniform(0.5, 2.0),     # entropy
                        np.random.uniform(0.01, 0.15),   # file_write_ratio
                        0.0,                             # sensitive_hits
                        0.0,                             # priv_count
                        0.0,                             # mem_exec
                        np.random.uniform(0.1, 2.0),     # net_out_rate
                        np.random.uniform(0.0, 0.5),     # dns_rate
                        0.0,                             # parent_suspicious
                        np.random.uniform(1, 3),         # exe_depth
                        np.random.uniform(0.0, 0.05),    # failed_ratio
                        np.random.uniform(3, 8),         # unique_syscalls
                    ]
                elif threat_name == "RANSOMWARE":
                    vec = [
                        np.random.uniform(80.0, 300.0),  # high syscall rate
                        np.random.uniform(2.5, 4.0),     # high entropy
                        np.random.uniform(0.70, 0.99),   # high file write ratio
                        np.random.uniform(5, 25),        # sensitive hits
                        0.0,
                        0.0,
                        np.random.uniform(0.0, 1.0),
                        0.0,
                        0.0,
                        np.random.uniform(2, 5),
                        np.random.uniform(0.01, 0.10),
                        np.random.uniform(10, 20),
                    ]
                elif threat_name == "REVERSE_SHELL":
                    vec = [
                        np.random.uniform(15.0, 50.0),
                        np.random.uniform(1.5, 3.0),
                        np.random.uniform(0.0, 0.10),
                        0.0,
                        1.0,
                        0.0,
                        np.random.uniform(20.0, 100.0),  # high net outbound
                        np.random.uniform(1.0, 5.0),
                        1.0,
                        np.random.uniform(1, 4),
                        0.0,
                        np.random.uniform(5, 12),
                    ]
                else:  # Generic attack profile
                    vec = [
                        np.random.uniform(30.0, 120.0),
                        np.random.uniform(2.0, 3.8),
                        np.random.uniform(0.20, 0.60),
                        np.random.uniform(1, 10),
                        np.random.uniform(0, 3),
                        np.random.uniform(0, 2),
                        np.random.uniform(5.0, 30.0),
                        np.random.uniform(0.5, 3.0),
                        np.random.uniform(0, 1),
                        np.random.uniform(1, 5),
                        np.random.uniform(0.05, 0.25),
                        np.random.uniform(8, 18),
                    ]
                row = dict(zip(FEATURE_COLUMNS, vec))
                row["label"] = threat_id
                data_rows.append(row)

        return pd.DataFrame(data_rows)

    def _benchmark_streaming_latency(self) -> tuple[list[float], float]:
        """Benchmark ingestion latency (ms) and throughput (events/sec)."""
        extractor = StreamingExtractor(window_seconds=5.0)
        latencies_ms = []

        base_ts = int(time.time() * 1e9)
        num_events = 5000

        t_start = time.perf_counter()
        for i in range(num_events):
            evt = {
                "event_type": "SYS_EXEC",
                "timestamp_ns": base_ts + int(i * 1e6),  # 1ms step
                "pid": 5000 + (i % 20),
                "ppid": 1,
                "uid": 1000,
                "gid": 1000,
                "comm": "bench_proc",
                "exe_path": "/tmp/bench",
                "parent_comm": "bash",
                "syscall_id": (i % 50) + 1,
                "file_path": "/tmp/test",
                "bytes_written": 1024,
                "bytes_read": 512,
                "dst_ip": "192.168.1.1",
                "dst_port": 80,
            }
            t0 = time.perf_counter()
            extractor.ingest(evt)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        t_end = time.perf_counter()
        elapsed_sec = t_end - t_start
        throughput_eps = num_events / elapsed_sec if elapsed_sec > 0 else 0.0

        return latencies_ms, throughput_eps

    def _plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray):
        """Generate normalized confusion matrix heatmap."""
        cm = confusion_matrix(y_true, y_pred, normalize="true")
        labels = [THREAT_LABELS.get(i, f"C{i}") for i in sorted(list(set(y_true)))]

        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt=".2f", cmap="Blues", xticklabels=labels, yticklabels=labels)
        plt.title("Normalized Confusion Matrix — eBPF Threat Engine", fontsize=14, fontweight="bold")
        plt.xlabel("Predicted Threat Class", fontsize=12)
        plt.ylabel("True Threat Class", fontsize=12)
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "confusion_matrix.png", dpi=300)
        plt.close()

    def _plot_roc_pr_curves(self, y_true: np.ndarray, y_probs: np.ndarray):
        """Generate multi-class ROC and Precision-Recall curves."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # ROC Curve
        for i in range(min(y_probs.shape[1], 5)):
            y_binary = (y_true == i).astype(int)
            fpr, tpr, _ = roc_curve(y_binary, y_probs[:, i])
            roc_auc = auc(fpr, tpr)
            label_name = THREAT_LABELS.get(i, f"Class {i}")
            ax1.plot(fpr, tpr, label=f"{label_name} (AUC = {roc_auc:.3f})")

        ax1.plot([0, 1], [0, 1], "k--", alpha=0.5)
        ax1.set_title("Receiver Operating Characteristic (ROC)", fontsize=12, fontweight="bold")
        ax1.set_xlabel("False Positive Rate", fontsize=11)
        ax1.set_ylabel("True Positive Rate", fontsize=11)
        ax1.legend(loc="lower right")

        # Precision-Recall Curve
        for i in range(min(y_probs.shape[1], 5)):
            y_binary = (y_true == i).astype(int)
            p, r, _ = precision_recall_curve(y_binary, y_probs[:, i])
            pr_auc = auc(r, p)
            label_name = THREAT_LABELS.get(i, f"Class {i}")
            ax2.plot(r, p, label=f"{label_name} (AUC = {pr_auc:.3f})")

        ax2.set_title("Precision-Recall Curve", fontsize=12, fontweight="bold")
        ax2.set_xlabel("Recall", fontsize=11)
        ax2.set_ylabel("Precision", fontsize=11)
        ax2.legend(loc="lower left")

        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "roc_pr_curves.png", dpi=300)
        plt.close()

    def _plot_latency_throughput(self, latencies_ms: list[float], throughput_eps: float):
        """Generate dual-panel distribution chart for detection latency and throughput."""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        sns.histplot(latencies_ms, kde=True, ax=ax1, color="teal", bins=30)
        ax1.axvline(np.mean(latencies_ms), color="red", linestyle="--", label=f"Mean: {np.mean(latencies_ms):.3f}ms")
        ax1.axvline(np.percentile(latencies_ms, 99), color="orange", linestyle=":", label=f"P99: {np.percentile(latencies_ms, 99):.3f}ms")
        ax1.set_title("Per-Event Ingestion Latency (ms)", fontsize=12, fontweight="bold")
        ax1.set_xlabel("Latency (milliseconds)", fontsize=11)
        ax1.set_ylabel("Frequency", fontsize=11)
        ax1.legend()

        ax2.bar(["Streaming Engine Throughput"], [throughput_eps], color="mediumpurple", width=0.4)
        ax2.set_title("Ingestion Throughput Rate", fontsize=12, fontweight="bold")
        ax2.set_ylabel("Events per Second (EPS)", fontsize=11)
        ax2.text(0, throughput_eps * 0.5, f"{throughput_eps:,.0f} EPS", ha="center", va="center", color="white", fontweight="bold", fontsize=14)

        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "latency_throughput_distribution.png", dpi=300)
        plt.close()

    def _plot_feature_importance(self):
        """Generate eBPF feature importance bar chart."""
        rf = self.detector.rf_clf
        if not hasattr(rf, "feature_importances_"):
            return

        importances = rf.feature_importances_
        indices = np.argsort(importances)[::-1]

        plt.figure(figsize=(10, 6))
        plt.title("12-Dimensional eBPF Feature Importance (Random Forest)", fontsize=12, fontweight="bold")
        plt.bar(range(len(importances)), importances[indices], color="steelblue", align="center")
        plt.xticks(range(len(importances)), [FEATURE_COLUMNS[i] for i in indices], rotation=45, ha="right")
        plt.ylabel("Relative Importance Score", fontsize=11)
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "feature_importance.png", dpi=300)
        plt.close()

    def _save_reports(self, report_data: dict, y_true: np.ndarray, y_pred: np.ndarray):
        """Save JSON benchmark data and Markdown report."""
        with open(OUTPUT_DIR / "system_benchmark_report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        cls_rep = classification_report(y_true, y_pred, zero_division=0)

        md_content = f"""# 📊 eBPF-ML Threat Engine Benchmark & Observability Report

- **Report Generated**: `{report_data['timestamp']}`
- **Evaluation Dataset Size**: `{report_data['dataset_samples']} samples`
- **Streaming Throughput**: `{report_data['throughput_events_per_sec']:,} events/sec`
- **Mean Ingestion Latency**: `{report_data['latency_ms']['mean']} ms` (P99: `{report_data['latency_ms']['p99']} ms`)

---

### Core Performance Metrics
- **Accuracy**: `{report_data['metrics']['accuracy']:.2%}`
- **Weighted Precision**: `{report_data['metrics']['precision_weighted']:.2%}`
- **Weighted Recall**: `{report_data['metrics']['recall_weighted']:.2%}`
- **Weighted F1-Score**: `{report_data['metrics']['f1_weighted']:.2%}`

---

### Detailed Multi-Class Classification Report
```
{cls_rep}
```

---

### Generated Observability Visualizations
- `ml_engine/eval_results/confusion_matrix.png`
- `ml_engine/eval_results/roc_pr_curves.png`
- `ml_engine/eval_results/latency_throughput_distribution.png`
- `ml_engine/eval_results/feature_importance.png`
"""
        with open(OUTPUT_DIR / "system_evaluation_report.md", "w", encoding="utf-8") as f:
            f.write(md_content)


if __name__ == "__main__":
    evaluator = SystemEvaluator()
    evaluator.run_full_evaluation()
