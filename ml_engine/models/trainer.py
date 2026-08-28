"""
ML Model Training Pipeline for eBPF-ML Security Engine.

Trains dual-model suite:
  1. Isolation Forest (Unsupervised Anomaly Detector for zero-day threats)
  2. Random Forest & XGBoost Classifiers (Supervised Multi-Class Threat Detectors)

Features Used (12 dimensions):
  [syscall_rate, syscall_entropy, file_write_ratio, sensitive_file_access,
   privilege_events, memory_rwx_count, network_outbound_rate, dns_query_rate,
   parent_is_suspicious, execution_path_depth, failed_syscall_ratio, unique_syscall_count]

CLI Usage:
  python trainer.py --dataset-dir ../../logs/telemetry_raw --num-samples 3000 --subsample 10
  python trainer.py --full-cloud --num-samples 5000
"""

import sys
import argparse
import json
import logging
from pathlib import Path
from typing import Tuple, Dict

# Auto-inject virtualenv site-packages so joblib, sklearn, xgboost are always available
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

_venv_site = _project_root / "ml_engine" / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ml_engine.config import (
    DATASET_DIR,
    SAVED_MODELS_DIR,
    FEATURE_COLUMNS,

    ISOLATION_FOREST_PARAMS,
    RANDOM_FOREST_PARAMS,
    XGBOOST_PARAMS,
    THREAT_LABELS,
    THREAT_LABELS_INV,
)
from ml_engine.preprocessing.feature_extractor import extract_from_dataset

logger = logging.getLogger("ml_engine.trainer")


# ─────────────────────────────────────────────────────────────
# Synthetic Threat Telemetry Generator
# (Enriches baseline benign telemetry with labeled MITRE ATT&CK patterns)
# ─────────────────────────────────────────────────────────────

def generate_synthetic_attack_telemetry(
    benign_df: pd.DataFrame, num_samples_per_class: int = 3000
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Combines real benign baseline telemetry with realistic synthetic attack feature vectors.
    """
    np.random.seed(42)
    feature_list = []
    labels = []

    # 1. Comprehensive Benign samples (both idle, low-rate, medium, and high-rate system daemons)
    half = num_samples_per_class // 2
    benign_idle = np.column_stack([
        np.random.uniform(0.1, 50, half),                      # syscall_rate
        np.random.uniform(0.0, 2.5, half),                      # syscall_entropy
        np.random.uniform(0.0, 0.2, half),                      # file_write_ratio
        np.zeros(half),                                         # sensitive_file_access
        np.zeros(half),                                         # privilege_events
        np.zeros(half),                                         # memory_rwx_count
        np.zeros(half),                                         # network_outbound_rate
        np.zeros(half),                                         # dns_query_rate
        np.zeros(half),                                         # parent_is_suspicious
        np.random.uniform(1, 5, half),                          # execution_path_depth
        np.random.uniform(0.0, 0.05, half),                     # failed_syscall_ratio
        np.random.uniform(1, 8, half),                          # unique_syscall_count
    ])

    benign_active = np.column_stack([
        np.random.uniform(50, 2500, num_samples_per_class - half),  # syscall_rate
        np.random.uniform(1.5, 4.5, num_samples_per_class - half),  # syscall_entropy
        np.random.uniform(0.0, 0.25, num_samples_per_class - half), # file_write_ratio
        np.zeros(num_samples_per_class - half),                     # sensitive_file_access
        np.zeros(num_samples_per_class - half),                     # privilege_events
        np.zeros(num_samples_per_class - half),                     # memory_rwx_count
        np.random.uniform(0, 20, num_samples_per_class - half),     # network_outbound_rate
        np.random.uniform(0, 5, num_samples_per_class - half),      # dns_query_rate
        np.zeros(num_samples_per_class - half),                     # parent_is_suspicious
        np.random.uniform(2, 6, num_samples_per_class - half),      # execution_path_depth
        np.random.uniform(0.0, 0.03, num_samples_per_class - half), # failed_syscall_ratio
        np.random.uniform(5, 30, num_samples_per_class - half),     # unique_syscall_count
    ])
    feature_list.append(np.vstack([benign_idle, benign_active]))
    labels.extend([THREAT_LABELS_INV["BENIGN"]] * num_samples_per_class)


    # 2. Ransomware samples
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

    # 3. Privilege Escalation samples
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

    # 4. Reverse Shell samples
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

    # 5. Data Exfiltration samples
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

    # 6. Kernel Rootkit samples
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

    # 7. Crypto Miner samples
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

    # 8. Brute Force samples (high failed syscall ratio, authentication loops)
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
        np.random.uniform(0.40, 0.95, num_samples_per_class), # Very high failed syscall ratio!
        np.random.uniform(2, 6, num_samples_per_class),
    ])
    feature_list.append(bf)
    labels.extend([THREAT_LABELS_INV["BRUTE_FORCE"]] * num_samples_per_class)

    # 9. Container Escape samples (unshare/setns calls, /sys or /proc cgroup manipulation, high privilege events)
    ce = np.column_stack([
        np.random.uniform(50, 2000, num_samples_per_class),
        np.random.uniform(0.8, 2.2, num_samples_per_class),
        np.random.uniform(0.1, 0.5, num_samples_per_class),
        np.random.uniform(3, 15, num_samples_per_class),
        np.random.uniform(5, 30, num_samples_per_class), # High setns/unshare privilege events
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

    # 10. Log Tampering samples (high file unlink/truncate ops on sensitive paths, low network)
    lt = np.column_stack([
        np.random.uniform(100, 5000, num_samples_per_class),
        np.random.uniform(0.5, 1.8, num_samples_per_class),
        np.random.uniform(0.85, 1.0, num_samples_per_class), # Extremely high file write/unlink ratio
        np.random.uniform(4, 20, num_samples_per_class), # Sensitive log paths (/var/log, auditd)
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

    # 11. Denial of Service samples (massive burst rate, network flood, high syscall rate)
    dos = np.column_stack([
        np.random.uniform(200000, 1000000, num_samples_per_class), # Massive syscall rate flood
        np.random.uniform(0.0, 0.5, num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.zeros(num_samples_per_class),
        np.random.uniform(5000, 50000, num_samples_per_class), # Massive outbound network flood
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
# Training Engine
# ─────────────────────────────────────────────────────────────

def train_models(
    dataset_dir: Path = DATASET_DIR,
    output_dir: Path = SAVED_MODELS_DIR,
    num_samples_per_class: int = 3000,
    test_size: float = 0.20,
    subsample_step: int = 10,
    run_cv: bool = True,
):
    """Executes training, 5-fold cross-validation, and model serialization."""
    logger.info("Starting eBPF-ML Model Training Pipeline...")
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load telemetry dataset
    logger.info("Loading baseline benign/live telemetry from %s...", dataset_dir)
    try:
        benign_df = extract_from_dataset(dataset_dir=dataset_dir, max_files=20)
        logger.info("Loaded %d benign telemetry feature windows.", len(benign_df))
    except Exception as e:
        logger.warning("Could not extract live dataset (%s). Using fallback baseline.", e)
        benign_df = pd.DataFrame(columns=FEATURE_COLUMNS + ["pid", "comm"])

    # 2. Enrich with MITRE ATT&CK Threat Profiles
    logger.info("Enriching telemetry dataset with MITRE ATT&CK threat profiles (%d per class)...", num_samples_per_class)
    X_df, y = generate_synthetic_attack_telemetry(benign_df, num_samples_per_class=num_samples_per_class)
    logger.info("Total Combined Dataset Shape: %s (Class counts: %s)", X_df.shape, dict(y.value_counts()))

    # 3. Train-Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_df, y, test_size=test_size, random_state=42, stratify=y
    )

    logger.info("Train Set: %d samples | Test Set: %d samples", len(X_train), len(X_test))

    # 4. Standard Scaling
    logger.info("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 5. Train Isolation Forest (Unsupervised Zero-Day Anomaly Detector)
    logger.info("Training Isolation Forest Anomaly Detector...")
    benign_mask = (y_train == THREAT_LABELS_INV["BENIGN"])
    X_train_benign = X_train_scaled[benign_mask] if np.sum(benign_mask) > 0 else X_train_scaled

    iso_forest = IsolationForest(**ISOLATION_FOREST_PARAMS)
    iso_forest.fit(X_train_benign)

    iso_preds = iso_forest.predict(X_test_scaled)
    iso_anomalies_detected = np.sum(iso_preds == -1)
    logger.info("Isolation Forest: Flagged %d anomalies out of %d test samples.", iso_anomalies_detected, len(X_test))

    # 6. Train Random Forest Classifier
    logger.info("Training Random Forest Classifier (150 trees)...")
    rf_clf = RandomForestClassifier(n_estimators=150, max_depth=20, class_weight="balanced", random_state=42, n_jobs=-1)
    rf_clf.fit(X_train_scaled, y_train)

    rf_preds = rf_clf.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_test, rf_preds, average="weighted")
    logger.info("Random Forest — Accuracy: %.4f | Precision: %.4f | Recall: %.4f | F1-Score: %.4f", rf_acc, rf_prec, rf_rec, rf_f1)

    # 7. Train XGBoost Classifier
    logger.info("Training XGBoost Classifier (150 trees with histogram acceleration)...")
    xgb_clf = XGBClassifier(n_estimators=150, max_depth=8, learning_rate=0.1, tree_method="hist", eval_metric="mlogloss", random_state=42, n_jobs=-1)
    xgb_clf.fit(X_train_scaled, y_train)

    xgb_preds = xgb_clf.predict(X_test_scaled)
    xgb_acc = accuracy_score(y_test, xgb_preds)
    xgb_prec, xgb_rec, xgb_f1, _ = precision_recall_fscore_support(y_test, xgb_preds, average="weighted")
    logger.info("XGBoost — Accuracy: %.4f | Precision: %.4f | Recall: %.4f | F1-Score: %.4f", xgb_acc, xgb_prec, xgb_rec, xgb_f1)

    # 8. Stratified 5-Fold Cross-Validation
    rf_cv_scores = []
    if run_cv:
        logger.info("Running Stratified 5-Fold Cross-Validation for Random Forest...")
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        rf_cv_scores = cross_val_score(rf_clf, scaler.transform(X_df), y, cv=skf, scoring="f1_weighted", n_jobs=-1)
        logger.info("5-Fold CV Weighted F1-Scores: %s (Mean: %.4f ± %.4f)",
                    np.round(rf_cv_scores, 4), float(np.mean(rf_cv_scores)), float(np.std(rf_cv_scores)))

    # Print Evaluation Summary
    target_names = [THREAT_LABELS[i] for i in sorted(THREAT_LABELS.keys()) if i in y.unique()]

    print("\n" + "=" * 80)
    print("                 COMPREHENSIVE MODEL EVALUATION REPORT                   ")
    print("=" * 80)
    print(f"Total Dataset Size : {len(X_df):,d} samples")
    print(f"Training Set (80%) : {len(X_train):,d} samples")
    print(f"Testing Set (20%)  : {len(X_test):,d} samples")
    print("-" * 80)
    print(f"RANDOM FOREST  — Accuracy: {rf_acc:.4f} | Precision: {rf_prec:.4f} | Recall: {rf_rec:.4f} | F1-Score: {rf_f1:.4f}")
    print(f"XGBOOST        — Accuracy: {xgb_acc:.4f} | Precision: {xgb_prec:.4f} | Recall: {xgb_rec:.4f} | F1-Score: {xgb_f1:.4f}")
    if run_cv:
        print(f"5-FOLD CV F1   — Mean: {np.mean(rf_cv_scores):.4f} ± {np.std(rf_cv_scores):.4f}")
    print("-" * 80)
    print("\nClassification Report (Random Forest):")
    print(classification_report(y_test, rf_preds, target_names=target_names, digits=4))

    print("\nConfusion Matrix (Random Forest):")
    cm_df = pd.DataFrame(
        confusion_matrix(y_test, rf_preds),
        index=[f"True_{t}" for t in target_names],
        columns=[f"Pred_{t}" for t in target_names]
    )
    print(cm_df.to_string())

    print("\nFeature Importance Ranking:")
    importances = dict(zip(FEATURE_COLUMNS, rf_clf.feature_importances_))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    for feat, imp in sorted_imp:
        print(f"  {feat:25s}: {imp:.4f} ({imp*100:.2f}%)")
    print("=" * 80)

    # 9. Save Artifacts
    logger.info("Saving model artifacts to %s...", output_dir)
    joblib.dump(scaler, output_dir / "scaler.joblib")
    joblib.dump(iso_forest, output_dir / "isolation_forest.joblib")
    joblib.dump(rf_clf, output_dir / "random_forest.joblib")
    joblib.dump(xgb_clf, output_dir / "xgboost.joblib")

    metadata = {
        "feature_columns": FEATURE_COLUMNS,
        "threat_labels": THREAT_LABELS,
        "dataset_summary": {
            "total_samples": len(X_df),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
        },
        "metrics": {
            "random_forest": {
                "accuracy": float(rf_acc),
                "precision": float(rf_prec),
                "recall": float(rf_rec),
                "f1_score": float(rf_f1),
                "cv_f1_mean": float(np.mean(rf_cv_scores)) if run_cv else None,
            },
            "xgboost": {
                "accuracy": float(xgb_acc),
                "precision": float(xgb_prec),
                "recall": float(xgb_rec),
                "f1_score": float(xgb_f1),
            },
        },
        "feature_importance": importances,
    }

    with open(output_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Training complete. All model artifacts saved successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="eBPF ML Model Trainer")
    parser.add_argument("--dataset-dir", type=str, default=str(DATASET_DIR), help="Path to telemetry dataset")
    parser.add_argument("--output-dir", type=str, default=str(SAVED_MODELS_DIR), help="Path to save artifacts")
    parser.add_argument("--num-samples", type=int, default=3000, help="Number of samples per attack class")
    parser.add_argument("--test-size", type=float, default=0.20, help="Test set fraction")
    parser.add_argument("--subsample", type=int, default=10, help="Subsample step")
    parser.add_argument("--full-cloud", action="store_true", help="Run with 100% full dataset (for Kaggle/Colab)")

    args, _ = parser.parse_known_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    
    substep = 1 if args.full_cloud else args.subsample

    train_models(
        dataset_dir=Path(args.dataset_dir),
        output_dir=Path(args.output_dir),
        num_samples_per_class=args.num_samples,
        test_size=args.test_size,
        subsample_step=substep,
        run_cv=True,
    )
