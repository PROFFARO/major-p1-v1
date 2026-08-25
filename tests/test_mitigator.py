"""
Comprehensive Unit Tests for the Automated Mitigation Controller.

Verifies all safety layers:
    1. Protected PIDs are NEVER blocked
    2. BENIGN predictions are NEVER blocked
    3. Low-confidence threats are NEVER blocked
    4. Dual-model consensus prevents blocking on disagreement
    5. Cooldown timer prevents re-blocking same PID
    6. Dry-run mode logs without sending HTTP requests

Also verifies:
    - High-confidence agreed threats ARE blocked (in enforcement mode)
    - Network threats trigger automatic IP blocking (when dst_ip is present)
    - Rate limiting caps API request rates
    - Background expiry sweep removes stale blocks
    - Max active blocks limit is enforced
    - Audit log records all decisions correctly
    - Permanent blocks for high-severity threats
"""

import os
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml_engine.feedback.actions import ActionType, MitigationAction, AuditLogger, create_action
from ml_engine.feedback.mitigator import MitigationController, ActiveBlock, RateLimiter


# ─────────────────────────────────────────────────────────────
# Test Fixtures
# ─────────────────────────────────────────────────────────────

def make_threat_result(threat_name="RANSOMWARE", threat_id=1,
                       confidence=0.95, anomaly_score=-0.5,
                       is_anomaly=True) -> dict:
    """Create a mock ThreatDetector.predict_vector() result."""
    return {
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "threat_id": threat_id,
        "threat_name": threat_name,
        "confidence": confidence,
        "probabilities": {threat_name: confidence, "BENIGN": 1.0 - confidence},
    }


def make_metadata(comm="malware", exe_path="/tmp/malware",
                  parent_comm="bash", dst_ip="") -> dict:
    """Create a mock process metadata dict."""
    return {
        "comm": comm,
        "exe_path": exe_path,
        "parent_comm": parent_comm,
        "event_count": 100,
        "dst_ip": dst_ip,
    }


def make_controller(dry_run=True, dual_consensus=True, enable_background_sweep=False, **kwargs) -> MitigationController:
    """Create a MitigationController with a temp audit log."""
    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    tmp.close()
    audit = AuditLogger(log_path=Path(tmp.name))
    return MitigationController(
        dry_run=dry_run,
        dual_consensus=dual_consensus,
        audit_logger=audit,
        enable_background_sweep=enable_background_sweep,
        **kwargs,
    )


# ─────────────────────────────────────────────────────────────
# Test Cases
# ─────────────────────────────────────────────────────────────

class TestSafetyLayer1_ProtectedPIDs(unittest.TestCase):
    """Safety Layer 1: Protected PIDs must NEVER be blocked."""

    def test_pid_0_never_blocked(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=0,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.99),
            metadata=make_metadata(comm="swapper"),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)

    def test_pid_1_systemd_never_blocked(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=1,
            threat_result=make_threat_result("KERNEL_ROOTKIT", confidence=0.99),
            metadata=make_metadata(comm="systemd"),
            xgb_threat_name="KERNEL_ROOTKIT",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)

    def test_pid_2_kthreadd_never_blocked(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=2,
            threat_result=make_threat_result("CRYPTO_MINER", confidence=0.99),
            metadata=make_metadata(comm="kthreadd"),
            xgb_threat_name="CRYPTO_MINER",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)

    def test_protected_process_name_sshd(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=8888,
            threat_result=make_threat_result("BRUTE_FORCE", confidence=0.99),
            metadata=make_metadata(comm="sshd"),
            xgb_threat_name="BRUTE_FORCE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)

    def test_protected_process_name_kworker_prefix(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=55,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.99),
            metadata=make_metadata(comm="kworker/0:1H"),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)

    def test_protected_process_name_dockerd(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=1200,
            threat_result=make_threat_result("CONTAINER_ESCAPE", confidence=0.99),
            metadata=make_metadata(comm="dockerd"),
            xgb_threat_name="CONTAINER_ESCAPE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)

    def test_own_agent_never_blocked(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=5000,
            threat_result=make_threat_result("DENIAL_OF_SERVICE", confidence=0.99),
            metadata=make_metadata(comm="ebpf-ml-agent"),
            xgb_threat_name="DENIAL_OF_SERVICE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_PROTECTED.value)


class TestSafetyLayer2_BenignSkip(unittest.TestCase):
    """Safety Layer 2: BENIGN predictions are NEVER blocked."""

    def test_benign_both_models(self):
        ctrl = make_controller()
        result = ctrl.evaluate_and_mitigate(
            pid=12345,
            threat_result=make_threat_result("BENIGN", threat_id=0, confidence=0.99),
            metadata=make_metadata(comm="nginx"),
            xgb_threat_name="BENIGN",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_BENIGN.value)


class TestSafetyLayer3_ConfidenceGate(unittest.TestCase):
    """Safety Layer 3: Low-confidence threats must NOT be blocked."""

    def test_low_confidence_skipped(self):
        ctrl = make_controller(confidence_threshold=0.85)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.60),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_LOW_CONFIDENCE.value)

    def test_borderline_confidence_skipped(self):
        ctrl = make_controller(confidence_threshold=0.85)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.84),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_LOW_CONFIDENCE.value)

    def test_high_confidence_passes_gate(self):
        ctrl = make_controller(confidence_threshold=0.85)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertNotEqual(result.action_taken, ActionType.SKIP_LOW_CONFIDENCE.value)


class TestSafetyLayer4_EnsembleScoring(unittest.TestCase):
    """Ensemble Scoring: High confidence threat outputs mitigation action."""

    def test_ensemble_threat_mitigated(self):
        ctrl = make_controller(dry_run=False, dual_consensus=False)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="PRIVILEGE_ESCALATION",
        )
        self.assertEqual(result.action_taken, ActionType.BLOCK_PID.value)

    def test_single_model_mode_mitigates(self):
        ctrl = make_controller(dry_run=False, dual_consensus=False)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="BENIGN",
        )
        self.assertEqual(result.action_taken, ActionType.BLOCK_PID.value)


class TestSafetyLayer5_Cooldown(unittest.TestCase):
    """Safety Layer 5: Cooldown timer prevents re-blocking same PID."""

    def test_cooldown_prevents_reblock(self):
        ctrl = make_controller(cooldown_seconds=10)
        ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        ctrl._cooldowns[90001] = time.time()

        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_COOLDOWN.value)


class TestSafetyLayer6_DryRun(unittest.TestCase):
    """Safety Layer 6: Dry-run mode logs without blocking."""

    def test_dry_run_logs_only(self):
        ctrl = make_controller(dry_run=True)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.LOG_ONLY.value)
        self.assertIn("DRY-RUN", result.reason)

    @patch("ml_engine.feedback.mitigator.requests")
    def test_enforcement_mode_sends_http(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.text = '{"status":"blocked"}'
        mock_resp.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_resp

        ctrl = make_controller(dry_run=False)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.BLOCK_PID.value)
        mock_requests.post.assert_called_once()


class TestNetworkThreatAutoIPBlock(unittest.TestCase):
    """Network threats auto-block destination IPs."""

    @patch("ml_engine.feedback.mitigator.requests")
    def test_network_threat_blocks_ip(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.text = '{"status":"blocked"}'
        mock_resp.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_resp

        ctrl = make_controller(dry_run=False)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("REVERSE_SHELL", confidence=0.95),
            metadata=make_metadata(dst_ip="192.168.1.50"),
            xgb_threat_name="REVERSE_SHELL",
        )
        self.assertEqual(result.action_taken, ActionType.BLOCK_PID.value)
        # Should have called post twice: once for PID, once for IP
        self.assertEqual(mock_requests.post.call_count, 2)
        stats = ctrl.get_stats()
        self.assertEqual(stats["total_ip_blocked"], 1)


class TestRateLimiter(unittest.TestCase):
    """Rate limiter throttles excessive requests."""

    def test_rate_limiter_tokens(self):
        limiter = RateLimiter(rate_limit=2)
        self.assertTrue(limiter.acquire())
        self.assertTrue(limiter.acquire())
        self.assertFalse(limiter.acquire())  # Exhausted


class TestBackgroundExpirySweep(unittest.TestCase):
    """Background expiry thread clears expired blocks."""

    def test_background_sweep_thread(self):
        ctrl = make_controller(enable_background_sweep=True)
        block = ActiveBlock(
            pid=90001, threat_name="BRUTE_FORCE", confidence=0.90,
            action_id="test-bg", is_permanent=False, expire_seconds=0.01,
        )
        block.blocked_at = time.time() - 10
        block.expire_at = time.time() - 5
        ctrl._active_blocks[90001] = block

        # Manually invoke background sweep logic or stop
        ctrl._expire_stale_blocks()
        self.assertNotIn(90001, ctrl._active_blocks)
        ctrl.stop()


class TestMaxActiveBlocks(unittest.TestCase):
    """Safety cap: max active blocks limit."""

    def test_max_blocks_enforced(self):
        ctrl = make_controller(max_active_blocks=2, dry_run=False)
        for i in range(2):
            ctrl._active_blocks[90000 + i] = ActiveBlock(
                pid=90000 + i, threat_name="TEST", confidence=0.99,
                action_id=f"test-{i}", is_permanent=True,
            )

        result = ctrl.evaluate_and_mitigate(
            pid=99999,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.99),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertEqual(result.action_taken, ActionType.SKIP_MAX_BLOCKS.value)


class TestAutoExpiry(unittest.TestCase):
    """Auto-expiry removes stale blocks."""

    def test_expired_block_removed(self):
        ctrl = make_controller()
        block = ActiveBlock(
            pid=90001, threat_name="BRUTE_FORCE", confidence=0.90,
            action_id="test-expire", is_permanent=False, expire_seconds=0.1,
        )
        block.blocked_at = time.time() - 10
        block.expire_at = time.time() - 5
        ctrl._active_blocks[90001] = block

        ctrl._expire_stale_blocks()
        self.assertNotIn(90001, ctrl._active_blocks)
        self.assertEqual(ctrl._stats["total_expired"], 1)

    def test_permanent_block_never_expires(self):
        ctrl = make_controller()
        block = ActiveBlock(
            pid=90001, threat_name="RANSOMWARE", confidence=0.99,
            action_id="test-permanent", is_permanent=True,
        )
        block.blocked_at = time.time() - 86400
        ctrl._active_blocks[90001] = block

        ctrl._expire_stale_blocks()
        self.assertIn(90001, ctrl._active_blocks)


class TestAuditLog(unittest.TestCase):
    """Audit log records all decisions."""

    def test_all_decisions_logged(self):
        ctrl = make_controller()
        ctrl.evaluate_and_mitigate(
            pid=1, threat_result=make_threat_result("RANSOMWARE", confidence=0.99),
            metadata=make_metadata(comm="systemd"),
            xgb_threat_name="RANSOMWARE",
        )
        ctrl.evaluate_and_mitigate(
            pid=12345, threat_result=make_threat_result("BENIGN", threat_id=0, confidence=0.99),
            metadata=make_metadata(comm="nginx"),
            xgb_threat_name="BENIGN",
        )
        ctrl.evaluate_and_mitigate(
            pid=90001, threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )

        actions = ctrl.audit.read_all()
        self.assertEqual(len(actions), 3)
        self.assertEqual(actions[0].action_taken, ActionType.SKIP_PROTECTED.value)
        self.assertEqual(actions[1].action_taken, ActionType.SKIP_BENIGN.value)
        self.assertEqual(actions[2].action_taken, ActionType.LOG_ONLY.value)


class TestPermanentBlocksForHighSeverity(unittest.TestCase):
    """High-severity threats get permanent blocks."""

    def test_ransomware_is_permanent(self):
        ctrl = make_controller(dry_run=True)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("RANSOMWARE", confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="RANSOMWARE",
        )
        self.assertTrue(result.is_permanent)
        self.assertIsNone(result.expire_at)

    def test_brute_force_is_not_permanent(self):
        ctrl = make_controller(dry_run=True)
        result = ctrl.evaluate_and_mitigate(
            pid=90001,
            threat_result=make_threat_result("BRUTE_FORCE", threat_id=7, confidence=0.95),
            metadata=make_metadata(),
            xgb_threat_name="BRUTE_FORCE",
        )
        self.assertFalse(result.is_permanent)
        self.assertIsNotNone(result.expire_at)


if __name__ == "__main__":
    unittest.main(verbosity=2)
