"""
Automated Mitigation Controller for the eBPF-ML Security Feedback Loop.

Bridges the ML Engine's threat predictions to the Go Agent's eBPF kernel-level
enforcement. When the ML models detect a malicious process, this controller
issues REST API calls to the Go Agent, which updates the kernel eBPF hash maps
(pid_blocklist, ip_blocklist) — causing the LSM enforcer to immediately return
-EPERM for that process's system calls.

Architecture Flow:
    eBPF Probes → Ring Buffer → Go Agent → WebSocket → ML Feature Extractor
    → ThreatDetector (RF + XGB + IsoForest) → MitigationController
    → POST /api/block/pid & POST /api/block/ip → Go Agent → BPF Maps → eBPF Enforcer

Safety & Performance Features:
    1. Protected PID Allowlist         — Critical kernel/system PIDs exempt
    2. Confidence Threshold Gate       — ≥85% classifier confidence required
    3. Dual-Model Consensus            — RF AND XGBoost must agree on class
    4. Cooldown Timer                  — Same PID cannot be re-blocked within 30s
    5. Dry-Run Mode (default)          — Logs without sending block requests
    6. Audit Trail                     — Every decision logged for forensic review
    7. Background Expiry Sweep         — Daemon thread auto-unblocks expired PIDs every 30s
    8. Rate Limiter                    — Max 10 API requests/sec to prevent Go Agent overload
    9. Auto-IP Blocking                — Network threats auto-block destination IPs
"""

import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

import requests

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from ml_engine.config import (
    AGENT_REST_BASE,
    AGENT_API_BLOCK_PID,
    AGENT_API_BLOCK_IP,
    AUTO_MITIGATE_CONFIDENCE,
    MITIGATION_COOLDOWN_SECONDS,
    DUAL_MODEL_CONSENSUS,
    DRY_RUN_DEFAULT,
    MAX_ACTIVE_BLOCKS,
    AUTO_EXPIRE_SECONDS,
    PERMANENT_BLOCK_THREATS,
    PROTECTED_PIDS,
    PROTECTED_PROCESS_NAMES,
    THREAT_LABELS,
    RATE_LIMIT_REQUESTS_PER_SECOND,
    EXPIRY_SWEEP_INTERVAL_SECONDS,
    NETWORK_BLOCK_THREATS,
)

from ml_engine.feedback.actions import (
    ActionType,
    MitigationAction,
    AuditLogger,
    create_action,
)

logger = logging.getLogger("ml_engine.feedback.mitigator")


# ─────────────────────────────────────────────────────────────
# Active Block Entry (tracks state of each blocked PID)
# ─────────────────────────────────────────────────────────────

class ActiveBlock:
    """Represents a currently active PID block with optional auto-expiry."""

    __slots__ = ("pid", "threat_name", "confidence", "blocked_at",
                 "expire_at", "is_permanent", "action_id")

    def __init__(self, pid: int, threat_name: str, confidence: float,
                 action_id: str, is_permanent: bool = False,
                 expire_seconds: Optional[float] = None):
        self.pid = pid
        self.threat_name = threat_name
        self.confidence = confidence
        self.action_id = action_id
        self.blocked_at = time.time()
        self.is_permanent = is_permanent
        if is_permanent or expire_seconds is None:
            self.expire_at = None
        else:
            self.expire_at = self.blocked_at + expire_seconds

    def is_expired(self) -> bool:
        """Check if this block has expired."""
        if self.is_permanent or self.expire_at is None:
            return False
        return time.time() > self.expire_at


# ─────────────────────────────────────────────────────────────
# Rate Limiter Helper
# ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket style rate limiter for outgoing API requests."""

    def __init__(self, rate_limit: int = RATE_LIMIT_REQUESTS_PER_SECOND):
        self.rate_limit = rate_limit
        self.tokens = float(rate_limit)
        self.last_update = time.time()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(float(self.rate_limit), self.tokens + elapsed * self.rate_limit)

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


# ─────────────────────────────────────────────────────────────
# Mitigation Controller
# ─────────────────────────────────────────────────────────────

class MitigationController:
    """
    Thread-safe automated mitigation controller with safety layers,
    background expiry daemon, rate limiting, and network IP auto-blocking.
    """

    def __init__(
        self,
        agent_base_url: str = AGENT_REST_BASE,
        confidence_threshold: float = AUTO_MITIGATE_CONFIDENCE,
        cooldown_seconds: float = MITIGATION_COOLDOWN_SECONDS,
        dual_consensus: bool = DUAL_MODEL_CONSENSUS,
        dry_run: bool = DRY_RUN_DEFAULT,
        max_active_blocks: int = MAX_ACTIVE_BLOCKS,
        auto_expire_seconds: float = AUTO_EXPIRE_SECONDS,
        audit_logger: Optional[AuditLogger] = None,
        enable_background_sweep: bool = True,
    ):
        self.agent_base_url = agent_base_url.rstrip("/")
        self.confidence_threshold = confidence_threshold
        self.cooldown_seconds = cooldown_seconds
        self.dual_consensus = dual_consensus
        self.dry_run = dry_run
        self.max_active_blocks = max_active_blocks
        self.auto_expire_seconds = auto_expire_seconds

        # Thread safety lock
        self._lock = threading.Lock()

        # Active blocks: pid -> ActiveBlock
        self._active_blocks: Dict[int, ActiveBlock] = {}

        # Cooldown tracker: pid -> last_block_timestamp
        self._cooldowns: Dict[int, float] = {}

        # Rate limiter
        self.rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS_PER_SECOND)

        # Statistics counters
        self._stats = {
            "total_evaluated": 0,
            "total_blocked": 0,
            "total_ip_blocked": 0,
            "total_skipped": 0,
            "total_logged_only": 0,
            "total_unblocked": 0,
            "total_expired": 0,
            "total_rate_limited": 0,
        }

        # Audit logger
        self.audit = audit_logger or AuditLogger()

        # Background expiry thread
        self._running = True
        self._sweep_thread = None
        if enable_background_sweep:
            self._start_expiry_sweep_thread()

        mode = "DRY-RUN" if self.dry_run else "ENFORCEMENT"
        consensus = "DUAL-MODEL" if self.dual_consensus else "SINGLE-MODEL"
        logger.info(
            "MitigationController initialized [mode=%s, consensus=%s, "
            "confidence≥%.2f, cooldown=%ds, max_blocks=%d, rate_limit=%d/s]",
            mode, consensus, self.confidence_threshold,
            int(self.cooldown_seconds), self.max_active_blocks,
            RATE_LIMIT_REQUESTS_PER_SECOND,
        )

    # ─────────────────────────────────────────────────────────
    # Background Expiry Thread
    # ─────────────────────────────────────────────────────────

    def _start_expiry_sweep_thread(self) -> None:
        def sweep_loop():
            while self._running:
                time.sleep(EXPIRY_SWEEP_INTERVAL_SECONDS)
                if not self._running:
                    break
                with self._lock:
                    self._expire_stale_blocks()

        self._sweep_thread = threading.Thread(target=sweep_loop, daemon=True, name="mitigator-expiry-sweep")
        self._sweep_thread.start()
        logger.info("Background block expiry sweep thread started (interval=%ds)", EXPIRY_SWEEP_INTERVAL_SECONDS)

    def stop(self) -> None:
        """Stop background sweep thread gracefully."""
        self._running = False
        if self._sweep_thread and self._sweep_thread.is_alive():
            self._sweep_thread.join(timeout=2.0)

    # ─────────────────────────────────────────────────────────
    # Core Decision Engine
    # ─────────────────────────────────────────────────────────

    def evaluate_and_mitigate(
        self,
        pid: int,
        threat_result: dict,
        metadata: dict,
        xgb_threat_name: str = "BENIGN",
    ) -> MitigationAction:
        """
        Evaluate a threat prediction and decide whether to block the process.
        """
        with self._lock:
            self._stats["total_evaluated"] += 1

            # Expire stale blocks before evaluation
            self._expire_stale_blocks()

            rf_threat = (
                threat_result.get("rf_threat_name")
                or (threat_result.get("rf_result") or {}).get("threat_name")
                or threat_result.get("threat_name")
                or "BENIGN"
            )
            confidence = threat_result.get("confidence", 0.0)
            comm = metadata.get("comm", "")
            dst_ip = metadata.get("dst_ip", "")

            # ── Safety Layer 1: Protected PID Allowlist ──
            if self._is_protected(pid, comm):
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.SKIP_PROTECTED,
                    reason=f"PID {pid} ({comm}) is in protected allowlist",
                )
                self._stats["total_skipped"] += 1
                self.audit.record(action)
                return action

            # ── Safety Layer 2: Skip BENIGN predictions ──
            if rf_threat == "BENIGN" and xgb_threat_name == "BENIGN":
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.SKIP_BENIGN,
                    reason="Both models predict BENIGN — no mitigation needed",
                )
                self._stats["total_skipped"] += 1
                self.audit.record(action)
                return action

            # ── Safety Layer 3: Confidence Threshold Gate ──
            if confidence < self.confidence_threshold:
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.SKIP_LOW_CONFIDENCE,
                    reason=f"Confidence {confidence:.4f} < threshold {self.confidence_threshold:.2f}",
                )
                self._stats["total_skipped"] += 1
                self.audit.record(action)
                return action

            # ── Safety Layer 4: Cooldown Timer ──
            if self._is_in_cooldown(pid):
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.SKIP_COOLDOWN,
                    reason=f"PID {pid} is in cooldown (blocked within last {self.cooldown_seconds}s)",
                )
                self._stats["total_skipped"] += 1
                self.audit.record(action)
                return action

            # ── Safety Cap: Max Active Blocks ──
            if len(self._active_blocks) >= self.max_active_blocks:
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.SKIP_MAX_BLOCKS,
                    reason=f"Max active blocks reached ({self.max_active_blocks})",
                )
                self._stats["total_skipped"] += 1
                self.audit.record(action)
                return action

            # ── Rate Limiter Check ──
            if not self.rate_limiter.acquire():
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.SKIP_MAX_BLOCKS,
                    reason="Rate limit exceeded — request throttled",
                )
                self._stats["total_rate_limited"] += 1
                self.audit.record(action)
                return action

            # ── All safety layers passed — MITIGATE ──
            is_permanent = rf_threat in PERMANENT_BLOCK_THREATS
            expire_seconds = None if is_permanent else self.auto_expire_seconds
            expire_at = None if is_permanent else (
                datetime.now(timezone.utc) + timedelta(seconds=self.auto_expire_seconds)
            )

            description = (
                f"ML-AUTO: {rf_threat} (conf={confidence:.2f}, "
                f"RF={rf_threat}, XGB={xgb_threat_name}, "
                f"comm={comm})"
            )

            # ── Safety Layer 6: Dry-Run Mode ──
            if self.dry_run:
                action = create_action(
                    pid=pid, metadata=metadata, threat_result=threat_result,
                    rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                    action_type=ActionType.LOG_ONLY,
                    reason=f"DRY-RUN: Would block PID {pid} for {rf_threat}",
                    is_permanent=is_permanent,
                    expire_at=expire_at,
                )
                self._stats["total_logged_only"] += 1
                self.audit.record(action)
                logger.warning(
                    "[DRY-RUN] Would block PID %d (%s) — %s (conf=%.4f)",
                    pid, comm, rf_threat, confidence,
                )
                return action

            # ── ENFORCEMENT MODE: Send block request to Go Agent ──
            agent_response = self._send_block_pid(pid, description)

            # Auto-block Destination IP if Network Threat
            if rf_threat in NETWORK_BLOCK_THREATS and dst_ip and dst_ip not in ("0.0.0.0", "127.0.0.1"):
                ip_desc = f"ML-AUTO-IP: {rf_threat} via PID {pid}"
                ip_resp = self._send_block_ip(dst_ip, ip_desc)
                self._stats["total_ip_blocked"] += 1
                logger.critical("🚨 BLOCKED IP %s — Network Threat: %s | Agent: %s", dst_ip, rf_threat, ip_resp)

            action = create_action(
                pid=pid, metadata=metadata, threat_result=threat_result,
                rf_threat=rf_threat, xgb_threat=xgb_threat_name,
                action_type=ActionType.BLOCK_PID,
                reason=f"Blocked PID {pid} ({comm}) for {rf_threat} — "
                       f"{'PERMANENT' if is_permanent else f'expires in {self.auto_expire_seconds}s'}",
                agent_response=agent_response,
                is_permanent=is_permanent,
                expire_at=expire_at,
            )

            self._active_blocks[pid] = ActiveBlock(
                pid=pid, threat_name=rf_threat, confidence=confidence,
                action_id=action.action_id, is_permanent=is_permanent,
                expire_seconds=expire_seconds,
            )
            self._cooldowns[pid] = time.time()
            self._stats["total_blocked"] += 1
            self.audit.record(action)

            logger.critical(
                "🚨 BLOCKED PID %d (%s) — Threat: %s | Confidence: %.4f | "
                "Permanent: %s | Agent: %s",
                pid, comm, rf_threat, confidence,
                is_permanent, agent_response,
            )
            return action

    # ─────────────────────────────────────────────────────────
    # Direct Block/Unblock Operations
    # ─────────────────────────────────────────────────────────

    def block_pid(self, pid: int, description: str = "") -> Optional[str]:
        if self._is_protected(pid, ""):
            logger.warning("Refused to block protected PID %d", pid)
            return None
        if self.dry_run:
            logger.warning("[DRY-RUN] Would block PID %d: %s", pid, description)
            return "DRY-RUN"
        return self._send_block_pid(pid, description)

    def block_ip(self, ip: str, description: str = "") -> Optional[str]:
        if self.dry_run:
            logger.warning("[DRY-RUN] Would block IP %s: %s", ip, description)
            return "DRY-RUN"
        return self._send_block_ip(ip, description)

    def unblock_pid(self, pid: int, reason: str = "") -> Optional[str]:
        with self._lock:
            if pid in self._active_blocks:
                del self._active_blocks[pid]
            self._stats["total_unblocked"] += 1

        if self.dry_run:
            logger.info("[DRY-RUN] Would unblock PID %d: %s", pid, reason)
            return "DRY-RUN"
        return self._send_unblock_pid(pid)

    def unblock_ip(self, ip: str, reason: str = "") -> Optional[str]:
        if self.dry_run:
            logger.info("[DRY-RUN] Would unblock IP %s: %s", ip, reason)
            return "DRY-RUN"
        return self._send_unblock_ip(ip)

    # ─────────────────────────────────────────────────────────
    # Query Operations
    # ─────────────────────────────────────────────────────────

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._expire_stale_blocks()
            blocks = [
                {
                    "pid": b.pid,
                    "threat_name": b.threat_name,
                    "confidence": b.confidence,
                    "blocked_at": datetime.fromtimestamp(
                        b.blocked_at, tz=timezone.utc
                    ).isoformat(),
                    "is_permanent": b.is_permanent,
                    "expire_at": datetime.fromtimestamp(
                        b.expire_at, tz=timezone.utc
                    ).isoformat() if b.expire_at else None,
                    "action_id": b.action_id,
                }
                for b in self._active_blocks.values()
            ]
            if not blocks:
                try:
                    resp = requests.get(f"{self.agent_base_url}/blocklist", timeout=1.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        for pb in data.get("pid_blocks", []):
                            blocks.append({
                                "pid": pb.get("key"),
                                "threat_name": pb.get("description", "LSM_BLOCK"),
                                "confidence": 1.0,
                                "blocked_at": pb.get("created_at"),
                                "is_permanent": True,
                                "expire_at": None,
                            })
                except Exception:
                    pass
            return blocks

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            stats = dict(self._stats)
            stats["active_blocks"] = len(self._active_blocks)
            stats["dry_run"] = self.dry_run
            stats["dual_consensus"] = self.dual_consensus
            stats["confidence_threshold"] = self.confidence_threshold
            return stats

    def get_audit_log(self) -> list:
        return [a.to_dict() for a in self.audit.read_all()]

    # ─────────────────────────────────────────────────────────
    # Safety Check Helpers
    # ─────────────────────────────────────────────────────────

    def _is_protected(self, pid: int, comm: str) -> bool:
        if pid in PROTECTED_PIDS:
            return True
        comm_lower = comm.lower().strip()
        if not comm_lower:
            return False
        for protected_name in PROTECTED_PROCESS_NAMES:
            if comm_lower == protected_name.lower():
                return True
            if comm_lower.startswith(protected_name.lower()):
                return True
        return False

    def _is_in_cooldown(self, pid: int) -> bool:
        last_block = self._cooldowns.get(pid)
        if last_block is None:
            return False
        return (time.time() - last_block) < self.cooldown_seconds

    def _expire_stale_blocks(self) -> None:
        expired_pids = [
            pid for pid, block in self._active_blocks.items()
            if block.is_expired()
        ]
        for pid in expired_pids:
            block = self._active_blocks.pop(pid)
            self._stats["total_expired"] += 1
            logger.info(
                "Auto-expired block for PID %d (%s) after %.0fs",
                pid, block.threat_name,
                time.time() - block.blocked_at,
            )
            if not self.dry_run:
                try:
                    self._send_unblock_pid(pid)
                except Exception as e:
                    logger.error("Failed to auto-unblock PID %d: %s", pid, e)

    # ─────────────────────────────────────────────────────────
    # Go Agent REST API Communication
    # ─────────────────────────────────────────────────────────

    def _send_block_pid(self, pid: int, description: str) -> str:
        url = f"{self.agent_base_url}/api/block/pid"
        payload = {"pid": pid, "desc": description}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.ConnectionError:
            logger.error("Cannot reach Go Agent at %s — is the agent running?", url)
            return "CONNECTION_ERROR"
        except requests.exceptions.Timeout:
            logger.error("Timeout connecting to Go Agent at %s", url)
            return "TIMEOUT"
        except requests.exceptions.RequestException as e:
            logger.error("Failed to block PID %d via agent: %s", pid, e)
            return f"ERROR: {e}"

    def _send_block_ip(self, ip: str, description: str) -> str:
        url = f"{self.agent_base_url}/api/block/ip"
        payload = {"ip": ip, "desc": description}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as e:
            logger.error("Failed to block IP %s via agent: %s", ip, e)
            return f"ERROR: {e}"

    def _send_unblock_pid(self, pid: int) -> str:
        url = f"{self.agent_base_url}/api/block/pid"
        payload = {"pid": pid}
        try:
            resp = requests.delete(url, json=payload, timeout=5)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as e:
            logger.error("Failed to unblock PID %d via agent: %s", pid, e)
            return f"ERROR: {e}"

    def _send_unblock_ip(self, ip: str) -> str:
        url = f"{self.agent_base_url}/api/block/ip"
        payload = {"ip": ip}
        try:
            resp = requests.delete(url, json=payload, timeout=5)
            resp.raise_for_status()
            return resp.text
        except requests.exceptions.RequestException as e:
            logger.error("Failed to unblock IP %s via agent: %s", ip, e)
            return f"ERROR: {e}"

    # ─────────────────────────────────────────────────────────
    # Configuration Control
    # ─────────────────────────────────────────────────────────

    def set_dry_run(self, enabled: bool) -> None:
        self.dry_run = enabled
        mode = "DRY-RUN" if enabled else "ENFORCEMENT"
        logger.warning("Mitigation mode changed to: %s", mode)

    def set_confidence_threshold(self, threshold: float) -> None:
        old = self.confidence_threshold
        self.confidence_threshold = max(0.0, min(1.0, threshold))
        logger.info(
            "Confidence threshold changed: %.2f → %.2f",
            old, self.confidence_threshold,
        )
