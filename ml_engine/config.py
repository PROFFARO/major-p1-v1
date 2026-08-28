"""
Centralized configuration for the eBPF-ML Security Engine.

All tunable parameters — agent connectivity, feature extraction windows,
model hyperparameters, anomaly thresholds, and LLM settings — are defined
here so that every module imports from a single source of truth.
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ML_ENGINE_DIR = Path(__file__).resolve().parent

# Auto-inject virtualenv site-packages if running with system python
venv_site = ML_ENGINE_DIR / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if venv_site.exists() and str(venv_site) not in sys.path:
    sys.path.insert(0, str(venv_site))

# Automatically load environment variables from root .env file if present
ENV_FILE = PROJECT_ROOT / ".env"
if ENV_FILE.exists():
    try:
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
    except Exception:
        pass

# Optional YAML configuration file loader (default sec-engine.yaml)
YAML_CONFIG_FILE = Path(os.getenv("SEC_ENGINE_CONFIG", PROJECT_ROOT / "sec-engine.yaml"))
YAML_CONFIG_DATA = {}
if YAML_CONFIG_FILE.exists():
    try:
        import yaml
        with open(YAML_CONFIG_FILE, "r", encoding="utf-8") as yf:
            YAML_CONFIG_DATA = yaml.safe_load(yf) or {}
    except Exception as _cfg_err:
        pass

LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

DATASET_DIR = LOGS_DIR / "telemetry_raw"
DATASET_DIR.mkdir(parents=True, exist_ok=True)

SAVED_MODELS_DIR = ML_ENGINE_DIR / "models" / "saved_models"
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# Go Agent Connectivity
# ─────────────────────────────────────────────────────────────

AGENT_WS_URL = os.getenv("AGENT_WS_URL") or YAML_CONFIG_DATA.get("agent", {}).get("ws_url") or "ws://localhost:8900/ws"
AGENT_REST_BASE = os.getenv("AGENT_REST_BASE") or YAML_CONFIG_DATA.get("agent", {}).get("rest_base") or "http://localhost:8900"

AGENT_API_STATUS = f"{AGENT_REST_BASE}/api/status"
AGENT_API_METRICS = f"{AGENT_REST_BASE}/api/metrics"

# ─────────────────────────────────────────────────────────────
# Feature Extraction Parameters
# ─────────────────────────────────────────────────────────────

# Sliding window duration in seconds for aggregating per-PID features
SLIDING_WINDOW_SECONDS = float(YAML_CONFIG_DATA.get("detection", {}).get("sliding_window_seconds", 5.0))

# Minimum events in a window to produce a valid feature vector
MIN_EVENTS_PER_WINDOW = int(YAML_CONFIG_DATA.get("detection", {}).get("min_events_per_window", 3))

# Sensitive file paths that trigger elevated threat scoring
SENSITIVE_PATHS = frozenset([
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/root/.ssh/",
    "/root/.bashrc",
    "/proc/kallsyms",
    "/proc/kcore",
    "/boot/vmlinuz",
    "/boot/initramfs",
    "/sys/kernel/",
    "/dev/mem",
    "/dev/kmsg",
])

# System call IDs associated with privilege escalation
PRIV_ESCALATION_SYSCALLS = frozenset([
    105,   # setuid
    106,   # setgid
    113,   # setreuid
    114,   # setregid
    117,   # setresuid
    119,   # setresgid
    125,   # capset
    160,   # setrlimit
    308,   # setns
])

# System call IDs associated with memory code injection
MEMORY_EXEC_SYSCALLS = frozenset([
    9,     # mmap
    10,    # mprotect
    319,   # memfd_create
])

# System call IDs associated with kernel module loading
MODULE_LOAD_SYSCALLS = frozenset([
    175,   # init_module
    313,   # finit_module
    176,   # delete_module
])

# Suspicious parent process names
SUSPICIOUS_PARENTS = frozenset([
    "bash", "sh", "dash", "zsh", "fish",
    "python", "python3", "perl", "ruby", "node",
    "curl", "wget", "nc", "ncat", "socat",
    "crontab", "at",
])

# ─────────────────────────────────────────────────────────────
# Feature Vector Column Names (12 dimensions)
# ─────────────────────────────────────────────────────────────

FEATURE_COLUMNS = [
    "syscall_rate",
    "syscall_entropy",
    "file_write_ratio",
    "sensitive_file_access",
    "privilege_events",
    "memory_rwx_count",
    "network_outbound_rate",
    "dns_query_rate",
    "parent_is_suspicious",
    "execution_path_depth",
    "failed_syscall_ratio",
    "unique_syscall_count",
]

# ─────────────────────────────────────────────────────────────
# ML Model Hyperparameters
# ─────────────────────────────────────────────────────────────

# Isolation Forest (unsupervised anomaly detection)
ISOLATION_FOREST_PARAMS = {
    "n_estimators": 200,
    "contamination": 0.05,       # expected anomaly fraction
    "max_samples": "auto",
    "random_state": 42,
    "n_jobs": -1,
}

# Random Forest (supervised threat classification)
RANDOM_FOREST_PARAMS = {
    "n_estimators": 300,
    "max_depth": 20,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}

# XGBoost (gradient-boosted threat classifier)
XGBOOST_PARAMS = {
    "n_estimators": 300,
    "max_depth": 8,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "eval_metric": "mlogloss",
    "random_state": 42,
    "n_jobs": -1,
}

# ─────────────────────────────────────────────────────────────
# Threat Classification Labels & Severity Map
# ─────────────────────────────────────────────────────────────

THREAT_LABELS = {
    0: "BENIGN",
    1: "RANSOMWARE",
    2: "PRIVILEGE_ESCALATION",
    3: "REVERSE_SHELL",
    4: "DATA_EXFILTRATION",
    5: "KERNEL_ROOTKIT",
    6: "CRYPTO_MINER",
    7: "BRUTE_FORCE",
    8: "CONTAINER_ESCAPE",
    9: "LOG_TAMPERING",
    10: "DENIAL_OF_SERVICE"
}

THREAT_LABELS_INV = {v: k for k, v in THREAT_LABELS.items()}

SEVERITY_LEVELS = {
    "BENIGN": "INFO",
    "RANSOMWARE": "CRITICAL",
    "PRIVILEGE_ESCALATION": "HIGH",
    "REVERSE_SHELL": "CRITICAL",
    "DATA_EXFILTRATION": "HIGH",
    "KERNEL_ROOTKIT": "CRITICAL",
    "CRYPTO_MINER": "HIGH",
    "BRUTE_FORCE": "MEDIUM",
    "CONTAINER_ESCAPE": "CRITICAL",
    "LOG_TAMPERING": "HIGH",
    "DENIAL_OF_SERVICE": "HIGH",
}

# ─────────────────────────────────────────────────────────────
# Anomaly & Behavioral Detection Parameters
# ─────────────────────────────────────────────────────────────

# Isolation Forest anomaly score threshold for triggering zero-day alert
ANOMALY_SCORE_THRESHOLD = float(YAML_CONFIG_DATA.get("detection", {}).get("anomaly_score_threshold", -0.3))

# Minimum confidence threshold for recording a high-fidelity threat detection alert
DETECTION_ALERT_THRESHOLD = float(YAML_CONFIG_DATA.get("detection", {}).get("detection_alert_threshold", 0.70))

# Falco Behavioral Rules enabled state
BEHAVIORAL_RULES_ENABLED = bool(YAML_CONFIG_DATA.get("detection", {}).get("behavioral_rules_enabled", True))

# Audit log file path
AUDIT_LOG_PATH = LOGS_DIR / "audit_log.jsonl"

# ─────────────────────────────────────────────────────────────
# Universal LLM Security Analyst Configuration
# ─────────────────────────────────────────────────────────────

LLM_API_KEY = (
    os.getenv("LLM_API_KEY")
    or os.getenv("GEMINI_API_KEY")
    or os.getenv("OPENAI_API_KEY")
    or os.getenv("GROQ_API_KEY")
    or os.getenv("DEEPSEEK_API_KEY")
    or ""
)
LLM_BASE_URL = os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL") or YAML_CONFIG_DATA.get("copilot", {}).get("base_url") or ""
LLM_MODEL_NAME = os.getenv("LLM_MODEL_NAME") or YAML_CONFIG_DATA.get("copilot", {}).get("model_name") or "gemini-2.5-flash"
LLM_PROVIDER = (os.getenv("LLM_PROVIDER") or YAML_CONFIG_DATA.get("copilot", {}).get("provider") or "auto").lower()

# Maximum telemetry events injected into LLM context per query
LLM_MAX_CONTEXT_EVENTS = int(os.getenv("LLM_MAX_CONTEXT_EVENTS") or YAML_CONFIG_DATA.get("copilot", {}).get("max_context_events", 200))

# ML Engine REST API & Storage
REST_API_HOST = os.getenv("REST_API_HOST") or YAML_CONFIG_DATA.get("api", {}).get("host") or "0.0.0.0"
REST_API_PORT = int(os.getenv("REST_API_PORT") or os.getenv("ML_ENGINE_PORT") or YAML_CONFIG_DATA.get("api", {}).get("port", 8901))

STORAGE_DIR = LOGS_DIR
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DUCKDB_PATH = LOGS_DIR / "telemetry.db"
SQLITE_PATH = LOGS_DIR / "sec_audit.db"
