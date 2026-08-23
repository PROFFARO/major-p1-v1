"""
Live Production System Entry Point — eBPF-ML Security Engine & Interactive LLM Copilot.

Launches the complete live real-time security pipeline:
    1. Connects to Go Agent WebSocket (ws://localhost:8900/ws) streaming eBPF kernel telemetry.
    2. Runs continuous 12-Dimensional Feature Extraction & Sliding Windowing.
    3. Evaluates processes using Dual-Model ML Consensus (Random Forest + XGBoost + Isolation Forest).
    4. Triggers automated LSM Kernel PID Blocking and IP Blackholing via Go Agent REST API.
    5. Synthesizes real-time SOC Incident Reports & Remediation Shell Guides using LLMSecurityCopilot.
    6. Provides an interactive Analyst CLI for querying threat history and copilot Q&A.
"""

import sys
import time
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Any, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.config import (
    AGENT_WS_URL,
    AGENT_REST_BASE,
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_MODEL_NAME,
    LLM_PROVIDER,
)
from ml_engine.models.detector import ThreatDetector
from ml_engine.feedback.mitigator import MitigationController
from ml_engine.feedback.actions import AuditLogger
from ml_engine.inference.realtime_engine import RealtimeIngestionEngine
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot
from ml_engine.storage import DatabaseManager
from ml_engine.api import APIServerRunner

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ml_engine.main")


class LiveSecurityEngineRunner:
    """Orchestrates the live eBPF telemetry streaming, ML detection, kernel enforcement, and LLM copilot."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.running = False

        logger.info("Initializing eBPF-ML Live Security Engine...")

        # 1. Audit Logger
        self.audit_logger = AuditLogger()

        # 2. Threat Detector (Loads trained joblib artifacts)
        self.detector = ThreatDetector()
        if not self.detector.loaded:
            logger.warning("ML Model joblib artifacts missing or unreadable! Operating in fallback mode.")

        # 3. Mitigation Controller (Communicates with Go Agent REST API)
        self.mitigator = MitigationController(
            agent_base_url=AGENT_REST_BASE,
            dry_run=self.dry_run,
            audit_logger=self.audit_logger,
            enable_background_sweep=True,
        )

        # 4. Universal LLM Security Analyst Copilot
        self.copilot = LLMSecurityCopilot(
            api_key=LLM_API_KEY,
            base_url=LLM_BASE_URL,
            model_name=LLM_MODEL_NAME,
            provider=LLM_PROVIDER,
        )

        # 5. Database Manager (DuckDB + SQLite WAL)
        self.db_mgr = DatabaseManager()

        # 6. Realtime Ingestion Engine (WebSocket streaming worker)
        self.engine = RealtimeIngestionEngine(
            ws_url=AGENT_WS_URL,
            detector=self.detector,
            mitigator=self.mitigator,
            on_detection_callback=self._handle_live_detection,
            window_seconds=5.0,
            db_manager=self.db_mgr,
        )

        # 7. FastAPI REST Server Runner (Port 8901)
        self.api_server = APIServerRunner(
            db_mgr=self.db_mgr,
            copilot=self.copilot,
            engine=self.engine,
            mitigator=self.mitigator,
        )

        self.latest_reports = []

    def _handle_live_detection(self, action, threat_res: Dict[str, Any]):
        """Callback invoked whenever a threat is detected by ML consensus."""
        pid = action.pid
        threat_name = action.threat_name
        action_taken = action.action_taken

        logger.critical(
            "🚨 LIVE THREAT DETECTED — PID: %d | Threat: %s | Action: %s | Conf: %.2f%%",
            pid,
            threat_name,
            action_taken,
            action.confidence * 100.0,
        )

        # Synthesize SOC Incident Report & Remediation Guide via LLM Copilot
        metadata = {
            "pid": pid,
            "comm": threat_res.get("comm", "unknown"),
            "exe_path": threat_res.get("exe_path", "/tmp/unknown"),
            "parent_comm": threat_res.get("parent_comm", "bash"),
            "dst_ip": threat_res.get("dst_ip", "0.0.0.0"),
        }

        report = self.copilot.analyze_threat(action.to_dict(), metadata)
        remediation = self.copilot.generate_remediation(action.to_dict(), metadata)

        report_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pid": pid,
            "threat_name": threat_name,
            "action_taken": action_taken,
            "soc_report": report,
            "remediation_guide": remediation,
        }
        self.latest_reports.insert(0, report_entry)
        if len(self.latest_reports) > 50:
            self.latest_reports.pop()

        print("\n" + "=" * 80)
        print(f"🛡️  LIVE SOC INCIDENT SYNTHESIS — PID {pid} [{threat_name}]")
        print("=" * 80)
        print(report)
        print("\n" + remediation)
        print("=" * 80 + "\n")

    def start(self):
        """Start live streaming ingestion engine & REST API server."""
        self.running = True
        logger.info("Starting FastAPI REST API server & WebSocket streaming engine...")
        self.api_server.start()
        self.engine.start()

    def stop(self):
        """Stop the engine and cleanup resources."""
        self.running = False
        logger.info("Stopping Live Security Engine & REST API server...")
        self.api_server.stop()
        self.engine.stop()
        self.mitigator.stop()
        logger.info("Engine stopped cleanly.")

    def run_interactive_cli(self):
        """Interactive Analyst CLI interface for querying status and copilot Q&A."""
        print("\n" + "═" * 80)
        print(" 🛡️  eBPF-ML SECURITY ENGINE & LLM COPILOT — LIVE MONITORING DASHBOARD")
        print(" ═" * 80)
        print(f" • Go Agent WS Endpoint : {AGENT_WS_URL}")
        print(f" • Go Agent REST Base  : {AGENT_REST_BASE}")
        print(f" • LLM Provider / Model: {self.copilot.provider.upper()} / {self.copilot.model_name}")
        print(f" • Copilot Mode        : {'ONLINE' if self.copilot.is_available() else 'OFFLINE (Rule-Based Fallback)'}")
        print(f" • Mitigation Mode     : {'DRY-RUN (Logging Only)' if self.dry_run else 'ACTIVE LSM KERNEL ENFORCEMENT'}")
        print(" ═" * 80)
        print(" Commands: 'status', 'blocks', 'reports', 'chat <question>', 'help', 'exit'")
        print(" ═" * 80 + "\n")

        while self.running:
            try:
                cmd = input("SOC-Copilot> ").strip()
                if not cmd:
                    continue

                if cmd.lower() in ("exit", "quit", "q"):
                    break
                elif cmd.lower() == "status":
                    stats = self.engine.get_stats()
                    active_blocks = self.mitigator.get_active_blocks()
                    print(f"\n📊 System Status:")
                    print(f"   • Total Processed Events: {stats.get('total_events_ingested', 0):,}")
                    print(f"   • Ingestion Rate (EPS)  : {stats.get('events_per_second', 0.0)} events/sec")
                    print(f"   • Active Feature Windows: {stats.get('active_pid_windows', 0)}")
                    print(f"   • Detections Triggered   : {stats.get('total_threats_detected', 0)}")
                    print(f"   • Active Kernel Blocks  : {len(active_blocks)}\n")
                elif cmd.lower() == "blocks":
                    blocks = self.mitigator.get_active_blocks()
                    print(f"\n🔒 Active Kernel Blocklist ({len(blocks)} entries):")
                    for b in blocks:
                        print(f"   • PID {b.get('pid')} | Threat: {b.get('threat_name')} | Permanent: {b.get('is_permanent')}")
                    print()
                elif cmd.lower() == "reports":
                    print(f"\n📑 Recent SOC Incident Reports ({len(self.latest_reports)} available):")
                    for r in self.latest_reports[:5]:
                        print(f"   • [{r['timestamp']}] PID {r['pid']} - {r['threat_name']} ({r['action_taken']})")
                    print()
                elif cmd.lower().startswith("chat"):
                    query = cmd[4:].strip()
                    if not query:
                        print("Please provide a question for the LLM Copilot. Example: chat Why was PID 90001 blocked?\n")
                        continue
                    print("\n🤖 Analyst Copilot Thinking...\n")
                    history = [a.to_dict() for a in self.audit_logger.read_all()]
                    active_blocks = self.mitigator.get_active_blocks()
                    answer = self.copilot.chat(query, audit_history=history, active_blocks=active_blocks)
                    print(answer + "\n")
                elif cmd.lower() == "help":
                    print("\nAvailable Commands:")
                    print("  • status        — Show streaming engine statistics")
                    print("  • blocks        — List currently active kernel PID blocklist")
                    print("  • reports       — List recent LLM SOC Incident Reports")
                    print("  • chat <prompt> — Ask the LLM Copilot any security question")
                    print("  • exit          — Stop the engine and quit\n")
                else:
                    print("Unknown command. Type 'help' for available commands.\n")

            except (KeyboardInterrupt, EOFError):
                break


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run eBPF-ML Live Security Engine & LLM Copilot")
    parser.add_argument("--dry-run", action="store_true", help="Log detection actions without applying LSM kernel blocks")
    args = parser.parse_args()

    runner = LiveSecurityEngineRunner(dry_run=args.dry_run)
    try:
        runner.start()
        runner.run_interactive_cli()
    finally:
        runner.stop()


if __name__ == "__main__":
    main()
