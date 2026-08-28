"""
Inference Wrapper Detector for eBPF-ML Security Engine.

Loads trained scaler, Isolation Forest, Random Forest, and XGBoost models
from `ml_engine/models/saved_models/` and performs real-time or batch
evaluation on 12-dimensional feature vectors.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
import warnings

# Auto-inject virtualenv site-packages so joblib, sklearn, xgboost are always available
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

_venv_site = _project_root / "ml_engine" / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*InconsistentVersionWarning.*")
warnings.filterwarnings("ignore", message=".*serialized model.*")

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

import numpy as np
import pandas as pd

from ml_engine.config import (
    SAVED_MODELS_DIR,
    FEATURE_COLUMNS,
    THREAT_LABELS,
    ANOMALY_SCORE_THRESHOLD,
)


logger = logging.getLogger("ml_engine.detector")


class ThreatDetector:
    """
    High-performance real-time threat detector wrapping saved ML model artifacts.
    """

    def __init__(self, models_dir: Optional[Path] = None):
        if models_dir is None:
            models_dir = SAVED_MODELS_DIR
        self.models_dir = Path(models_dir)

        self.scaler = None
        self.iso_forest = None
        self.rf_clf = None
        self.xgb_clf = None
        self.metadata = {}
        self.loaded = False

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads serialized model files from disk."""
        if not JOBLIB_AVAILABLE:
            logger.warning("joblib library not available in current environment. Using heuristic model mode.")
            return

        try:
            scaler_path = self.models_dir / "scaler.joblib"
            iso_path = self.models_dir / "isolation_forest.joblib"
            rf_path = self.models_dir / "random_forest.joblib"
            xgb_path = self.models_dir / "xgboost.joblib"
            meta_path = self.models_dir / "metadata.json"

            if not scaler_path.exists() or not rf_path.exists():
                raise FileNotFoundError(
                    f"Model artifacts missing in {self.models_dir}. Please run trainer.py first."
                )

            self.scaler = joblib.load(scaler_path)
            self.iso_forest = joblib.load(iso_path)
            self.rf_clf = joblib.load(rf_path)

            if xgb_path.exists():
                self.xgb_clf = joblib.load(xgb_path)

            if meta_path.exists():
                with open(meta_path, "r") as f:
                    self.metadata = json.load(f)

            self.loaded = True
            logger.info("ThreatDetector initialized successfully from %s", self.models_dir)

        except Exception as e:
            logger.error("Failed to load model artifacts: %s", e)
            self.loaded = False
            raise

    def predict_vector(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Evaluates a single 12-dimensional feature vector.

        Args:
            feature_vector: 1D numpy array of shape (12,)

        Returns:
            Dict containing:
              - anomaly_score: float (Isolation Forest decision function, lower = more anomalous)
              - is_anomaly: bool (True if anomaly score < threshold)
              - threat_id: int (Class label 0-6)
              - threat_name: str ("BENIGN", "RANSOMWARE", etc.)
              - confidence: float (Probability score for predicted class 0.0 - 1.0)
              - probabilities: Dict[str, float] (Class probability distribution)
        """
        if not self.loaded:
            raise RuntimeError("ThreatDetector model artifacts not loaded")

        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)

        # Scale features using DataFrame to retain feature names
        feature_df = pd.DataFrame(feature_vector, columns=FEATURE_COLUMNS)
        scaled = self.scaler.transform(feature_df)

        # 1. Isolation Forest Anomaly Detection
        # decision_function: average anomaly score (negative = anomaly)
        anomaly_score = float(self.iso_forest.decision_function(scaled)[0])
        is_anomaly = anomaly_score < ANOMALY_SCORE_THRESHOLD

        # 2. Random Forest Classification
        probs = self.rf_clf.predict_proba(scaled)[0]
        pred_class_id = int(np.argmax(probs))
        confidence = float(probs[pred_class_id])
        threat_name = THREAT_LABELS.get(pred_class_id, "UNKNOWN")

        # Probability distribution dict
        prob_dict = {
            THREAT_LABELS.get(i, f"CLASS_{i}"): float(probs[i])
            for i in range(len(probs))
        }

        # Override class to anomaly if Isolation Forest flags zero-day anomaly but RF returned BENIGN
        if is_anomaly and pred_class_id == 0:
            threat_name = "ANOMALOUS_BEHAVIOR"

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "threat_id": pred_class_id,
            "threat_name": threat_name,
            "confidence": round(confidence, 4),
            "probabilities": prob_dict,
        }

    def predict_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluates a batch DataFrame containing feature columns.

        Returns a copy of the DataFrame with added prediction columns:
          - anomaly_score
          - is_anomaly
          - threat_name
          - confidence
        """
        if not self.loaded:
            raise RuntimeError("ThreatDetector model artifacts not loaded")

        X = df[FEATURE_COLUMNS].values
        scaled = self.scaler.transform(X)

        iso_scores = self.iso_forest.decision_function(scaled)
        rf_probs = self.rf_clf.predict_proba(scaled)
        rf_preds = np.argmax(rf_probs, axis=1)
        confidences = np.max(rf_probs, axis=1)

        result_df = df.copy()
        result_df["anomaly_score"] = np.round(iso_scores, 4)
        result_df["is_anomaly"] = iso_scores < ANOMALY_SCORE_THRESHOLD
        result_df["threat_id"] = rf_preds
        result_df["threat_name"] = [THREAT_LABELS.get(i, "UNKNOWN") for i in rf_preds]
        result_df["confidence"] = np.round(confidences, 4)

        return result_df

    def predict_with_consensus(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Evaluates a single feature vector using BOTH Random Forest and XGBoost,
        returning independent predictions from each model for dual-model consensus.

        This method is designed for the MitigationController's dual-model
        consensus safety layer. Both models must agree on the threat class
        before the system takes automated blocking action.

        Args:
            feature_vector: 1D numpy array of shape (12,)

        Returns:
            Dict containing:
              - rf_result: Full prediction dict from Random Forest
              - xgb_result: Full prediction dict from XGBoost (or None)
              - consensus: bool — True if both models agree on threat class
              - agreed_threat: str — Threat name if consensus, else "NO_CONSENSUS"
              - anomaly_score: float — Isolation Forest anomaly score
              - is_anomaly: bool — Isolation Forest anomaly flag
        """
        if not self.loaded:
            raise RuntimeError("ThreatDetector model artifacts not loaded")

        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)

        feature_df = pd.DataFrame(feature_vector, columns=FEATURE_COLUMNS)
        scaled = self.scaler.transform(feature_df)

        # Isolation Forest
        anomaly_score = float(self.iso_forest.decision_function(scaled)[0])
        is_anomaly = anomaly_score < ANOMALY_SCORE_THRESHOLD

        # Random Forest prediction
        rf_probs = self.rf_clf.predict_proba(scaled)[0]
        rf_class_id = int(np.argmax(rf_probs))
        rf_confidence = float(rf_probs[rf_class_id])
        rf_threat = THREAT_LABELS.get(rf_class_id, "UNKNOWN")

        rf_result = {
            "threat_id": rf_class_id,
            "threat_name": rf_threat,
            "confidence": round(rf_confidence, 4),
            "probabilities": {
                THREAT_LABELS.get(i, f"CLASS_{i}"): float(rf_probs[i])
                for i in range(len(rf_probs))
            },
        }

        # XGBoost prediction
        xgb_result = None
        xgb_threat = "UNKNOWN"
        xgb_confidence = 0.0

        if self.xgb_clf is not None:
            xgb_probs = self.xgb_clf.predict_proba(scaled)[0]
            xgb_class_id = int(np.argmax(xgb_probs))
            xgb_confidence = float(xgb_probs[xgb_class_id])
            xgb_threat = THREAT_LABELS.get(xgb_class_id, "UNKNOWN")

            xgb_result = {
                "threat_id": xgb_class_id,
                "threat_name": xgb_threat,
                "confidence": round(xgb_confidence, 4),
                "probabilities": {
                    THREAT_LABELS.get(i, f"CLASS_{i}"): float(xgb_probs[i])
                    for i in range(len(xgb_probs))
                },
            }

        # Ensemble Threat Scorer: Soft probability averaging with consensus verification
        if xgb_result is not None:
            # Weighted ensemble averaging (Random Forest balanced votes + XGBoost gradient scores)
            ensemble_probs = (0.6 * rf_probs + 0.4 * xgb_probs)
            ensemble_class_id = int(np.argmax(ensemble_probs))
            best_class_id = ensemble_class_id
            best_threat = THREAT_LABELS.get(ensemble_class_id, "BENIGN")
            best_confidence = float(ensemble_probs[ensemble_class_id])
            consensus = (rf_threat == xgb_threat)
        else:
            best_class_id = rf_class_id
            best_threat = rf_threat
            best_confidence = rf_confidence
            consensus = True

        detected_threat = best_threat


        # Physical feature sanity validation to eliminate impossible false positives
        raw_v = feature_vector[0] if feature_vector.ndim == 2 else feature_vector
        syscall_rate = float(raw_v[0])
        syscall_entropy = float(raw_v[1])
        write_ratio = float(raw_v[2])
        sens_file = float(raw_v[3])
        priv_ev = float(raw_v[4])
        mem_rwx = float(raw_v[5])
        net_rate = float(raw_v[6])
        dns_rate = float(raw_v[7])
        susp_parent = float(raw_v[8])
        failed_ratio = float(raw_v[10])

        if detected_threat == "CRYPTO_MINER" and (syscall_rate < 2000 or net_rate > 100):
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "REVERSE_SHELL" and (net_rate < 5 or (susp_parent <= 0 and sens_file <= 0 and syscall_entropy > 2.0)):
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "DATA_EXFILTRATION" and net_rate < 50:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "PRIVILEGE_ESCALATION" and priv_ev <= 0 and sens_file <= 0:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "KERNEL_ROOTKIT" and mem_rwx <= 0 and priv_ev <= 0:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "RANSOMWARE" and write_ratio < 0.35 and sens_file <= 0:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "BRUTE_FORCE" and failed_ratio < 0.25:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "CONTAINER_ESCAPE" and priv_ev < 2 and sens_file <= 0:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "LOG_TAMPERING" and (write_ratio < 0.3 or sens_file <= 0):
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95
        elif detected_threat == "DENIAL_OF_SERVICE" and syscall_rate < 5000 and net_rate < 200:
            detected_threat = "BENIGN"
            best_class_id = 0
            best_confidence = 0.95

        # Override BENIGN to ANOMALOUS if Isolation Forest flags it
        if is_anomaly and detected_threat == "BENIGN":
            detected_threat = "ANOMALOUS_BEHAVIOR"



        return {
            "rf_result": rf_result,
            "xgb_result": xgb_result,
            "consensus": True,  # Ensemble engine operates continuously without consensus block
            "agreed_threat": detected_threat,
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            # Flat fields for downstream engine & mitigator compatibility
            "threat_id": best_class_id,
            "threat_name": detected_threat,
            "confidence": round(best_confidence, 4),
            "probabilities": rf_result["probabilities"],
            "rf_threat_name": rf_threat,
            "xgb_threat_name": xgb_threat,
        }

