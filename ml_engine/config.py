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

LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

DATASET_DIR = LOGS_DIR / "telemetry_raw"
DATASET_DIR.mkdir(parents=True, exist_ok=True)

SAVED_MODELS_DIR = ML_ENGINE_DIR / "models" / "saved_models"
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# Go Agent Connectivity
# ─────────────────────────────────────────────────────────────

AGENT_WS_URL = os.getenv("AGENT_WS_URL", "ws://localhost:8900/ws")
AGENT_REST_BASE = os.getenv("AGENT_REST_BASE", "http://localhost:8900")

AGENT_API_STATUS = f"{AGENT_REST_BASE}/api/status"
AGENT_API_METRICS = f"{AGENT_REST_BASE}/api/metrics"
AGENT_API_BLOCKLIST = f"{AGENT_REST_BASE}/api/blocklist"
AGENT_API_BLOCK_PID = f"{AGENT_REST_BASE}/api/block/pid"
AGENT_API_BLOCK_IP = f"{AGENT_REST_BASE}/api/block/ip"

# ─────────────────────────────────────────────────────────────
# Feature Extraction Parameters
# ─────────────────────────────────────────────────────────────

# Sliding window duration in seconds for aggregating per-PID features
SLIDING_WINDOW_SECONDS = 5.0

# Minimum events in a window to produce a valid feature vector
MIN_EVENTS_PER_WINDOW = 10

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
# Threat Classification Labels
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

# ─────────────────────────────────────────────────────────────
# Anomaly & Mitigation Thresholds
# ─────────────────────────────────────────────────────────────

# Isolation Forest anomaly score threshold for triggering alert
ANOMALY_SCORE_THRESHOLD = -0.3

# Minimum classifier confidence for automatic mitigation
AUTO_MITIGATE_CONFIDENCE = 0.85

# Cooldown period (seconds) before re-blocking same PID
MITIGATION_COOLDOWN_SECONDS = 30.0

# Require both Random Forest AND XGBoost to agree on threat class
DUAL_MODEL_CONSENSUS = True

# Dry-run mode: log mitigation decisions without actually blocking
DRY_RUN_DEFAULT = True

# Maximum number of concurrent active PID blocks (safety cap)
MAX_ACTIVE_BLOCKS = 50

# Auto-expire: seconds before a blocked PID is automatically unblocked.
# High-severity threats (RANSOMWARE, KERNEL_ROOTKIT, CRYPTO_MINER, REVERSE_SHELL)
# are blocked permanently (until manual unblock). Lower-severity threats expire.
AUTO_EXPIRE_SECONDS = 300  # 5 minutes for low/medium severity

# High-severity threat classes that get PERMANENT blocks (no auto-expire)
PERMANENT_BLOCK_THREATS = frozenset([
    "RANSOMWARE",
    "KERNEL_ROOTKIT",
    "CRYPTO_MINER",
    "REVERSE_SHELL",
    "CONTAINER_ESCAPE",
])

# Protected PIDs that must NEVER be blocked under any circumstance
PROTECTED_PIDS = frozenset([
    0,   # kernel scheduler / swapper
    1,   # init / systemd
    2,   # kthreadd (kernel thread parent)
])

# Protected process names that must NEVER be blocked
PROTECTED_PROCESS_NAMES = frozenset([
    "systemd", "systemd-journald", "systemd-logind", "systemd-udevd",
    "systemd-resolved", "systemd-timesyncd", "systemd-networkd",
    "init", "kthreadd", "kworker", "ksoftirqd", "kswapd", "rcu_sched",
    "rcu_preempt", "rcu_bh", "migration", "watchdog", "cpuhp",
    "irq", "scsi_eh", "kblockd", "md", "edac-poller",
    "containerd", "containerd-shim", "dockerd", "runc",
    "kubelet", "kube-proxy", "kube-apiserver", "etcd",
    "sshd", "login", "getty", "agetty",
    "journald", "rsyslogd", "syslogd",
    "dbus-daemon", "dbus-broker",
    "NetworkManager", "dhclient", "wpa_supplicant",
    "polkitd", "udisksd", "accounts-daemon",
    "cron", "crond", "atd",
    "auditd", "firewalld", "iptables",
    "ebpf-ml-agent",  # our own agent process
])

# Audit log file path
AUDIT_LOG_PATH = LOGS_DIR / "audit_log.jsonl"

# Rate limiter: max block API requests per second to Go Agent
RATE_LIMIT_REQUESTS_PER_SECOND = 10

# Background expiry sweep interval (seconds)
EXPIRY_SWEEP_INTERVAL_SECONDS = 30

# Network threats that trigger automatic IP blocking (when dst_ip is available)
NETWORK_BLOCK_THREATS = frozenset([
    "REVERSE_SHELL",
    "DATA_EXFILTRATION",
    "DENIAL_OF_SERVICE",
    "BRUTE_FORCE",
])

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
LLM_BASE_URL = os.getenv("LLM_BASE_URL", os.getenv("OPENAI_BASE_URL", ""))
LLM_MODEL_NAME = os.getenv("LLM_MODEL_NAME", "gemini-2.5-flash")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").lower()

# Maximum telemetry events injected into LLM context per query
LLM_MAX_CONTEXT_EVENTS = 200

# ML Engine REST API & Storage
REST_API_HOST = os.getenv("REST_API_HOST", "0.0.0.0")
REST_API_PORT = int(os.getenv("REST_API_PORT", "8901"))

STORAGE_DIR = LOGS_DIR
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DUCKDB_PATH = LOGS_DIR / "telemetry.db"
SQLITE_PATH = LOGS_DIR / "sec_audit.db"
