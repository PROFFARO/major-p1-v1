#!/usr/bin/env python3
"""
Single Centralized System Orchestrator & Interactive Command Center
eBPF-ML Security System & LLM Copilot Analyst Platform.

Orchestrates the Go eBPF kernel agent subprocess, Python ML real-time ingestion,
DuckDB columnar storage, SQLite WAL audit logging, FastAPI REST server, and interactive
Analyst Copilot CLI in a single unified process lifecycle.

Usage:
  sudo python3 main.py
  python3 main.py --dry-run
  python3 main.py --no-agent --port-api 8901
  python3 main.py --non-interactive
"""

import argparse
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

# Silence third-party logger outputs before module imports
logging.getLogger("numexpr").setLevel(logging.WARNING)
logging.getLogger("numexpr.utils").setLevel(logging.WARNING)

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import ML Engine Components
from ml_engine.config import (
    AGENT_WS_URL,
    AGENT_REST_BASE,
    REST_API_PORT,
    REST_API_HOST,
    LLM_API_KEY,
    LLM_BASE_URL,
    LLM_MODEL_NAME,
    LLM_PROVIDER,
    LOGS_DIR,
)
from ml_engine.models.detector import ThreatDetector
from ml_engine.rules.behavioral_engine import BehavioralEngine
from ml_engine.detection.alert_dispatcher import AlertDispatcher
from ml_engine.inference.realtime_engine import RealtimeIngestionEngine
from ml_engine.llm_analyst.copilot import LLMSecurityCopilot
from ml_engine.storage import DatabaseManager
from ml_engine.api import APIServerRunner

logger = logging.getLogger("system.orchestrator")


class UnifiedSystemOrchestrator:
    """
    Centralized controller for managing:
      1. Go eBPF Agent Subprocess (kernel probe loader & ring buffer broadcaster)
      2. Python Streaming ML Inference Engine & Falco Behavioral Rules
      3. DuckDB Columnar & SQLite WAL Database Managers
      4. FastAPI REST Server & Dashboard API
      5. Interactive Analyst Copilot CLI Console
    """

    def __init__(
        self,
        dry_run: bool = False,
        no_agent: bool = False,
        no_api: bool = False,
        bpf_dir: Optional[str] = None,
        agent_listen: str = ":8900",
        api_port: int = REST_API_PORT,
        export_dataset: bool = False,
    ):
        self.dry_run = dry_run
        self.no_agent = no_agent
        self.no_api = no_api
        self.bpf_dir = bpf_dir
        self.agent_listen = agent_listen
        self.api_port = api_port
        self.export_dataset = export_dataset

        self.running = False
        self.agent_process: Optional[subprocess.Popen] = None
        self.latest_reports: List[Dict[str, Any]] = []

        logger.info("Initializing Unified eBPF Telemetry & Security Engine...")

        # Ensure log directory and files are accessible
        for log_file in LOGS_DIR.glob("*"):
            try:
                log_file.chmod(0o666)
            except Exception:
                pass

        # 1. Database Manager & Alert Dispatcher
        self.db_mgr = DatabaseManager()
        self.dispatcher = AlertDispatcher(db_manager=self.db_mgr)

        # 2. ML Threat Detector & Behavioral Engine
        self.detector = ThreatDetector()
        if not self.detector.loaded:
            logger.warning("ML model joblib artifacts missing! Operating in Falco rule-based mode.")

        self.behavioral_engine = BehavioralEngine()

        # 3. Universal LLM Security Analyst Copilot
        self.copilot = LLMSecurityCopilot(
            api_key=LLM_API_KEY,
            base_url=LLM_BASE_URL,
            model_name=LLM_MODEL_NAME,
            provider=LLM_PROVIDER,
        )

        # 4. Realtime Ingestion Engine
        ws_url = f"ws://localhost{agent_listen if agent_listen.startswith(':') else ':' + agent_listen}/ws"
        self.engine = RealtimeIngestionEngine(
            ws_url=ws_url,
            detector=self.detector,
            behavioral_engine=self.behavioral_engine,
            on_detection_callback=self._handle_live_detection,
            window_seconds=5.0,
            db_manager=self.db_mgr,
        )

        # 5. FastAPI REST Server Runner
        self.api_server = None
        if not self.no_api:
            self.api_server = APIServerRunner(
                host=REST_API_HOST,
                port=self.api_port,
                db_mgr=self.db_mgr,
                copilot=self.copilot,
                engine=self.engine,
            )

    def _handle_live_detection(self, alert: Dict[str, Any]):
        """Callback triggered when an ML anomaly or behavioral rule detects a threat."""
        pid = alert.get("pid", 0)
        threat_name = alert.get("threat_name", alert.get("rule_name", "UNKNOWN"))
        source = alert.get("detection_source", "alert_dispatcher")

        if threat_name == "BENIGN":
            return

        logger.critical(
            "🚨 LIVE THREAT DETECTED — PID: %d | Threat: %s | Source: %s | Conf: %.2f%%",
            pid,
            threat_name,
            source,
            float(alert.get("confidence", 1.0)) * 100.0,
        )

        metadata = {
            "pid": pid,
            "comm": alert.get("comm", "unknown"),
            "exe_path": alert.get("exe_path", "/tmp/unknown"),
            "parent_comm": alert.get("parent_comm", "bash"),
            "dst_ip": alert.get("dst_ip", "0.0.0.0"),
        }

        report = self.copilot.analyze_threat(alert, metadata)
        remediation = self.copilot.generate_remediation(alert, metadata)

        report_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pid": pid,
            "threat_name": threat_name,
            "action_taken": source,
            "soc_report": report,
            "remediation_guide": remediation,
        }
        self.latest_reports.insert(0, report_entry)
        if len(self.latest_reports) > 50:
            self.latest_reports.pop()

        print("\n" + "═" * 80)
        print(f"🛡️  LIVE SOC INCIDENT SYNTHESIS — PID {pid} [{threat_name}]")
        print("═" * 80)
        print(report)
        print("\n" + remediation)
        print("═" * 80 + "\n")

    def _start_go_agent(self):
        """Builds (if needed) and spawns the Go eBPF Agent background subprocess."""
        if self.no_agent:
            logger.info("Go eBPF Agent startup skipped (--no-agent flag specified).")
            return

        agent_bin = PROJECT_ROOT / "agent" / "ebpf-ml-agent"
        if not agent_bin.exists():
            logger.info("Building Go eBPF Agent binary...")
            try:
                res = subprocess.run(
                    ["go", "build", "-o", "ebpf-ml-agent", "./cmd/agent"],
                    cwd=str(PROJECT_ROOT / "agent"),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                logger.info("Go eBPF Agent binary compiled successfully.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.error("Failed to build Go Agent binary: %s", e)
                sys.exit(1)

        # Privilege Check
        is_root = (os.geteuid() == 0)
        if not is_root:
            logger.error("❌ Root privileges required to load eBPF kernel probes!")
            logger.error("Please re-run the command with sudo:")
            logger.error("    sudo python3 main.py\n")
            sys.exit(1)

        cmd = [
            str(agent_bin),
            "--listen", self.agent_listen,
        ]
        if self.bpf_dir:
            cmd.extend(["--bpf-dir", self.bpf_dir])
        if self.export_dataset:
            cmd.append("--export-dataset")

        logger.info("Spawning Go eBPF Agent background process: %s", " ".join(cmd))
        try:
            self.agent_process = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT / "agent"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            # Spawn background thread to pipe agent log output cleanly
            threading.Thread(target=self._pipe_agent_logs, daemon=True, name="go-agent-logger").start()

            # Wait up to 5 seconds for Go agent HTTP status endpoint to become ready
            agent_port = self.agent_listen.split(":")[-1]
            status_url = f"http://localhost:{agent_port}/api/status"
            ready = False
            for _ in range(25):
                try:
                    with urllib.request.urlopen(status_url, timeout=0.5) as resp:
                        if resp.status == 200:
                            ready = True
                            break
                except Exception:
                    time.sleep(0.2)

            if ready:
                logger.info("✓ Go eBPF Agent active and listening on http://localhost:%s", agent_port)
            else:
                logger.warning("Go Agent process spawned, waiting for WebSocket connection...")

        except Exception as e:
            logger.error("Failed to launch Go eBPF Agent process: %s", e)

    def _pipe_agent_logs(self):
        """Pipe stdout lines from Go agent subprocess to python logger."""
        if not self.agent_process or not self.agent_process.stdout:
            return
        for line in iter(self.agent_process.stdout.readline, ""):
            line_str = line.strip()
            if line_str:
                logger.info("[Go-Agent] %s", line_str)

    def start(self):
        """Start all system subsystems in parallel."""
        self.running = True
        self._start_go_agent()

        if self.api_server:
            logger.info("Starting FastAPI REST API Server on port %d...", self.api_port)
            self.api_server.start()

        logger.info("Starting Streaming Realtime Ingestion Engine...")
        self.engine.start()

    def stop(self):
        """Cleanly terminate all subprocesses and background threads."""
        if not self.running:
            return
        self.running = False
        print("\n[*] Initiating graceful teardown of eBPF-ML Security System...")

        # 1. Stop Python REST server & Ingestion engine
        if self.api_server:
            try:
                self.api_server.stop()
            except Exception:
                pass

        try:
            self.engine.stop()
        except Exception:
            pass

        try:
            self.engine.stop()
        except Exception:
            pass

        # 2. Terminate Go Agent Subprocess
        if self.agent_process and self.agent_process.poll() is None:
            logger.info("Sending SIGTERM to Go eBPF Agent process (PID %d)...", self.agent_process.pid)
            try:
                self.agent_process.terminate()
                self.agent_process.wait(timeout=1.0)
            except Exception:
                try:
                    self.agent_process.kill()
                except Exception:
                    pass
            logger.info("Go eBPF Agent process terminated.")

        logger.info("✓ eBPF Telemetry & Security Engine shut down cleanly.")

    def run_interactive_cli(self):
        """Interactive Professional Command Center for SOC Analysts."""
        agent_status = "ONLINE" if (self.agent_process and self.agent_process.poll() is None) else ("DISABLED" if self.no_agent else "UNKNOWN")
        models_status = "LOADED (RF + XGB + ISO)" if self.detector.loaded else "FALLBACK (Falco Rules Only)"
        copilot_status = "ONLINE" if self.copilot.is_available() else "OFFLINE"

        print("\n" + "═" * 80)
        print("   🛡️   eBPF TELEMETRY & THREAT OBSERVABILITY ENGINE — COMMAND CENTER")
        print("═" * 80)
        print(f" • Mode                  : NON-INTRUSIVE TELEMETRY OBSERVABILITY & AUDIT")
        print(f" • Go eBPF Agent        : {agent_status} ({self.agent_listen})")
        print(f" • ML & Behavioral Rules: {models_status}")
        print(f" • Analyst Copilot      : {copilot_status} ({self.copilot.provider.upper()}: {self.copilot.model_name})")
        print(f" • FastAPI REST Server   : {'ONLINE' if self.api_server else 'DISABLED'} (http://localhost:{self.api_port})")
        print(" ═" * 80)
        print(" Catalog: 'status', 'alerts [N]', 'audit [N]', 'query <SQL>', 'chat <prompt>', 'reports', 'help', 'exit'")
        print(" ═" * 80 + "\n")

        while self.running:
            try:
                cmd = input("SOC-CommandCenter> ").strip()
                if not cmd:
                    continue

                if cmd.lower() in ("exit", "quit", "q"):
                    break

                elif cmd.lower() == "status":
                    stats = self.engine.get_stats()
                    db_alerts = self.db_mgr.sqlite.get_alerts(limit=10000)
                    total_threats = max(stats.get('total_threats_detected', 0), len(db_alerts))

                    print(f"\n📊 Live Operational Status:")
                    print(f"   • Total Events Ingested  : {stats.get('total_events_ingested', 0):,}")
                    print(f"   • Telemetry Throughput   : {stats.get('events_per_second', 0.0):.1f} EPS")
                    print(f"   • Active Feature Windows : {stats.get('active_pid_windows', 0)}")
                    print(f"   • Total Threats Detected : {total_threats}")
                    print(f"   • Go Agent Process PID   : {self.agent_process.pid if self.agent_process else 'N/A'}\n")

                elif cmd.lower().startswith("alerts"):
                    parts = cmd.split()
                    limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
                    alerts = self.db_mgr.sqlite.get_alerts(limit=limit)
                    print(f"\n🚨 Threat Alert Records (Last {len(alerts)}):")
                    if not alerts:
                        print("   (No threat alerts recorded in database)\n")
                    for a in alerts:
                        conf = a.get('confidence', 0.0) * 100.0
                        print(f"   • [{a.get('timestamp')}] PID {a.get('pid')} ({a.get('comm')}) — Threat: {a.get('threat_name')} (Conf: {conf:.1f}%) -> Source: {a.get('action_taken')}")
                    print()

                elif cmd.lower().startswith("audit"):
                    parts = cmd.split()
                    limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
                    logs = self.db_mgr.sqlite.get_mitigation_audit_logs(limit=limit)
                    print(f"\n📋 Mitigation Audit Records (Last {len(logs)}):")
                    if not logs:
                        print("   (No audit records present)\n")
                    for l in logs:
                        comm = l.get('comm') or 'N/A'
                        reason = l.get('details') or l.get('reason') or 'No details provided'
                        threat = l.get('threat_name') or 'BENIGN'
                        conf = l.get('confidence', 0.0)
                        print(f"   • [{l.get('timestamp')}] PID {l.get('pid')} ({comm}) -> {l.get('action_taken')} | Threat: {threat} (conf={conf:.2f}) | Reason: {reason}")
                    print()

                elif cmd.lower().startswith("query"):
                    sql = cmd[5:].strip()
                    if not sql:
                        print("Usage: query <SELECT SQL> (e.g. query SELECT comm, count(*) FROM feature_windows GROUP BY comm)\n")
                        continue
                    try:
                        rows = self.db_mgr.duckdb.query_sql(sql, limit=50)
                        print(f"\n📈 DuckDB Query Results ({len(rows)} rows):")
                        for r in rows[:20]:
                            print(f"   {r}")
                        print()
                    except Exception as e:
                        print(f"❌ DuckDB SQL Error: {e}\n")

                elif cmd.lower().startswith("chat"):
                    prompt = cmd[4:].strip()
                    if not prompt:
                        print("Usage: chat <question> (e.g. chat What process generated ransomware alerts?)\n")
                        continue
                    print("\n🤖 Analyst Copilot Analyzing Context...\n")
                    history = self.db_mgr.sqlite.get_mitigation_audit_logs(limit=20)
                    answer = self.copilot.chat(user_query=prompt, audit_history=history)
                    print(answer + "\n")

                elif cmd.lower() == "reports":
                    print(f"\n📑 Generated SOC Incident Reports ({len(self.latest_reports)} available):")
                    if not self.latest_reports:
                        print("   (No live threat reports generated in this session)\n")
                    for r in self.latest_reports[:5]:
                        print(f"   • [{r['timestamp']}] PID {r['pid']} — {r['threat_name']} ({r['action_taken']})")
                    print()

                elif cmd.lower() == "help":
                    print("\nCatalog of Available Console Commands:")
                    print("  • status           — Display live throughput EPS, event metrics, and subsystem health")
                    print("  • alerts [limit]   — Retrieve recent threat alerts from SQLite WAL database")
                    print("  • audit [limit]    — Retrieve telemetry audit decision history")
                    print("  • query <SQL>      — Run analytical SQL queries on DuckDB columnar telemetry store")
                    print("  • chat <prompt>    — Submit security questions to Universal LLM Analyst Copilot")
                    print("  • reports          — View full SOC incident reports generated during current session")
                    print("  • exit / quit      — Safely shut down all background threads & Go agent subprocess\n")

                else:
                    print("Unknown command. Type 'help' to see full command catalog.\n")

            except (KeyboardInterrupt, EOFError):
                break
            except Exception as err:
                print(f"❌ Command execution error: {err}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Unified System Orchestrator & Command Center — eBPF-ML Security System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--dry-run", action="store_true", help="Log detection actions without applying kernel LSM PID blocks")
    parser.add_argument("--no-agent", action="store_true", help="Do not spawn Go eBPF agent background subprocess")
    parser.add_argument("--no-api", action="store_true", help="Disable FastAPI REST API server")
    parser.add_argument("--bpf-dir", type=str, default=None, help="Directory containing compiled .bpf.o object files")
    parser.add_argument("--listen-agent", type=str, default=":8900", help="Go eBPF Agent HTTP/WebSocket listen address")
    parser.add_argument("--port-api", type=int, default=REST_API_PORT, help="FastAPI REST API server listening port")
    parser.add_argument("--export-dataset", action="store_true", help="Enable continuous logging of raw telemetry to .jsonl dataset files")
    parser.add_argument("--non-interactive", action="store_true", help="Run in headless daemon mode without interactive CLI console")

    args = parser.parse_args()

    # Configure Central Logging after CLI args parse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    orchestrator = UnifiedSystemOrchestrator(
        dry_run=args.dry_run,
        no_agent=args.no_agent,
        no_api=args.no_api,
        bpf_dir=args.bpf_dir,
        agent_listen=args.listen_agent,
        api_port=args.port_api,
        export_dataset=args.export_dataset,
    )

    # Register OS Signal Handlers
    def _sig_handler(sig, frame):
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        orchestrator.start()
        if not args.non_interactive:
            orchestrator.run_interactive_cli()
        else:
            logger.info("Running in non-interactive daemon mode. Press Ctrl+C to stop.")
            while orchestrator.running:
                time.sleep(1.0)
    finally:
        orchestrator.stop()


if __name__ == "__main__":
    main()
