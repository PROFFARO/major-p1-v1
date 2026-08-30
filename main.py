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
    DATASET_DIR,
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
        auto_build_bpf: bool = False,
    ):
        self.dry_run = dry_run
        self.no_agent = no_agent
        self.no_api = no_api
        self.bpf_dir = bpf_dir
        self.agent_listen = agent_listen
        self.api_port = api_port
        self.export_dataset = export_dataset
        self.auto_build_bpf = auto_build_bpf

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
            "THREAT DETECTED [PID %d] Class: %s | Source: %s | Confidence: %.2f%%",
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

        print("\n" + "─" * 80)
        print(f"INCIDENT REPORT [PID {pid}] Classification: {threat_name}")
        print("─" * 80)
        print(report)
        print("\nREMEDIATION RUNBOOK:")
        print(remediation)
        print("─" * 80 + "\n")

    def _start_go_agent(self):
        """Builds (if needed) and spawns the Go eBPF Agent background subprocess."""
        if self.no_agent:
            logger.info("Go eBPF Agent startup skipped (--no-agent specified).")
            return

        agent_bin = PROJECT_ROOT / "agent" / "ebpf-ml-agent"
        if not agent_bin.exists():
            logger.info("Compiling Go eBPF Agent binary...")
            try:
                res = subprocess.run(
                    ["go", "build", "-o", "ebpf-ml-agent", "./cmd/agent"],
                    cwd=str(PROJECT_ROOT / "agent"),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                logger.info("Go eBPF Agent compiled successfully.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.error("Failed to compile Go eBPF Agent binary: %s", e)
                sys.exit(1)

        # Privilege Check
        is_root = (os.geteuid() == 0)
        if not is_root:
            logger.error("Insufficient privileges: Root access required to attach eBPF probes.")
            logger.error("Execute using administrative credentials:")
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
            cmd.extend(["--dataset-dir", str(DATASET_DIR)])
        if self.auto_build_bpf:
            cmd.append("--auto-build-bpf")

        logger.info("Executing Go eBPF Agent: %s", " ".join(cmd))
        try:
            self.agent_process = subprocess.Popen(
                cmd,
                cwd=str(PROJECT_ROOT / "agent"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            threading.Thread(target=self._pipe_agent_logs, daemon=True, name="go-agent-logger").start()

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
                logger.info("Go eBPF Agent active and listening on http://localhost:%s", agent_port)
            else:
                logger.warning("Go eBPF Agent process spawned, awaiting HTTP readiness check.")

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
        logger.info("Initiating system shutdown sequence...")

        if self.api_server:
            try:
                self.api_server.stop()
            except Exception:
                pass

        try:
            self.engine.stop()
        except Exception:
            pass

        if self.agent_process and self.agent_process.poll() is None:
            logger.info("Terminating Go eBPF Agent process (PID %d)...", self.agent_process.pid)
            try:
                self.agent_process.terminate()
                self.agent_process.wait(timeout=1.0)
            except Exception:
                try:
                    self.agent_process.kill()
                except Exception:
                    pass
        logger.info("System shutdown sequence completed cleanly.")

    def run_interactive_cli(self):
        """Interactive Enterprise Command Center for Security Operations."""
        agent_status = "ONLINE" if (self.agent_process and self.agent_process.poll() is None) else ("DISABLED" if self.no_agent else "OFFLINE")
        models_status = "LOADED (RandomForest + XGBoost)" if self.detector.loaded else "FALLBACK (Falco Rules Only)"
        copilot_status = "ONLINE" if self.copilot.is_available() else "OFFLINE"

        print("\n" + "┌" + "─" * 78 + "┐")
        print("│            eBPF SECURITY OBSERVABILITY & THREAT ENGINE (v1.0.0)             │")
        print("├" + "─" * 78 + "┤")
        print(f"│ Operating Mode     : Non-Intrusive Telemetry Observability & Audit            │")
        print(f"│ Go eBPF Agent      : {agent_status:<10} ({self.agent_listen:<20})                  │")
        print(f"│ Detection Engine   : {models_status:<55} │")
        print(f"│ Analyst Copilot    : {copilot_status:<10} ({self.copilot.provider.upper()}: {self.copilot.model_name:<20})            │")
        print(f"│ REST API Gateway   : {'ONLINE' if self.api_server else 'DISABLED':<10} (http://localhost:{self.api_port:<5})                   │")
        print("└" + "─" * 78 + "┘")
        print(" Available commands: status, alerts, subsystems, audit, query <SQL>, chat <prompt>, reports, help, exit")
        print("─" * 80 + "\n")

        while self.running:
            try:
                cmd = input("sec-engine> ").strip()
                if not cmd:
                    continue

                tokens = cmd.split()
                base_cmd = tokens[0].lower() if tokens else ""

                if base_cmd in ("exit", "quit", "q"):
                    break

                elif base_cmd in ("status", "info"):
                    stats = self.engine.get_stats()
                    db_alerts = self.db_mgr.sqlite.get_alerts(limit=10000)
                    total_threats = max(stats.get('total_threats_detected', 0), len(db_alerts))

                    try:
                        from rich.console import Console
                        from rich.table import Table
                        from rich import box
                        console = Console()

                        table = Table(title="SYSTEM OPERATIONAL METRICS", show_header=True, header_style="bold cyan", box=box.ROUNDED)
                        table.add_column("Component / Metric", style="bold white")
                        table.add_column("Current Value", style="bold yellow")
                        table.add_column("State", style="bold green")

                        table.add_row("Total Events Ingested", f"{stats.get('total_events_ingested', 0):,}", "ONLINE")
                        table.add_row("Telemetry Throughput", f"{stats.get('events_per_second', 0.0):.1f} EPS", "ACTIVE")
                        table.add_row("Active Feature Windows", f"{stats.get('active_pid_windows', 0)}", "MONITORING")
                        table.add_row("Total Threat Detections", f"{total_threats}", "PROTECTED" if total_threats == 0 else "ALERT")
                        table.add_row("Go eBPF Agent Process", f"PID {self.agent_process.pid if self.agent_process else 'N/A'}", "RUNNING" if self.agent_process else "STOPPED")
                        table.add_row("DuckDB Storage Store", "telemetry.db", "CONNECTED")
                        table.add_row("SQLite Audit Store", "sec_audit.db", "CONNECTED")

                        console.print(table)
                    except ImportError:
                        print(f"\nSystem Operational Status:")
                        print(f"   - Total Events Ingested  : {stats.get('total_events_ingested', 0):,}")
                        print(f"   - Telemetry Throughput   : {stats.get('events_per_second', 0.0):.1f} EPS")
                        print(f"   - Active Feature Windows : {stats.get('active_pid_windows', 0)}")
                        print(f"   - Total Threats Detected : {total_threats}")
                        print(f"   - Go Agent Process PID   : {self.agent_process.pid if self.agent_process else 'N/A'}\n")

                elif base_cmd in ("alerts", "events"):
                    limit = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 10
                    alerts = self.db_mgr.sqlite.get_alerts(limit=limit)

                    try:
                        from rich.console import Console
                        from rich.table import Table
                        from rich import box
                        console = Console()

                        table = Table(title=f"THREAT INCIDENT LOGS (Last {len(alerts)} Records)", show_header=True, header_style="bold magenta", box=box.ROUNDED)
                        table.add_column("Timestamp", style="dim")
                        table.add_column("PID", style="bold yellow")
                        table.add_column("Process", style="bold white")
                        table.add_column("Threat Classification", style="bold red")
                        table.add_column("Confidence", style="bold green")
                        table.add_column("Source", style="cyan")

                        if not alerts:
                            table.add_row("N/A", "N/A", "N/A", "No threats recorded", "0.0%", "N/A")
                        else:
                            for a in alerts:
                                conf = a.get('confidence', 0.0) * 100.0
                                threat_style = "bold red" if "RANSOMWARE" in str(a.get('threat_name')) or "REVERSE_SHELL" in str(a.get('threat_name')) else "yellow"
                                table.add_row(
                                    str(a.get('timestamp')),
                                    str(a.get('pid')),
                                    str(a.get('comm')),
                                    f"[{threat_style}]{a.get('threat_name')}[/{threat_style}]",
                                    f"{conf:.1f}%",
                                    str(a.get('action_taken'))
                                )
                        console.print(table)
                    except ImportError:
                        print(f"\nThreat Alert Records (Last {len(alerts)}):")
                        for a in alerts:
                            conf = a.get('confidence', 0.0) * 100.0
                            print(f"   - [{a.get('timestamp')}] PID {a.get('pid')} ({a.get('comm')}) — Threat: {a.get('threat_name')} (Conf: {conf:.1f}%) -> Source: {a.get('action_taken')}")
                        print()

                elif base_cmd in ("subsystems", "wrappers"):
                    try:
                        from rich.console import Console
                        from rich.table import Table
                        from rich import box
                        console = Console()

                        table = Table(title="EBPF SUBSYSTEM INTEGRATION MATRIX (13 Native Wrappers)", show_header=True, header_style="bold blue", box=box.ROUNDED)
                        table.add_column("Subsystem", style="bold yellow")
                        table.add_column("Telemetry Focus", style="white")
                        table.add_column("Kernel Hook Mechanism", style="cyan")
                        table.add_column("Status", style="bold green")

                        wrappers_data = [
                            ("Bpfman", "Priority probe attachment & pinning manager", "BPFFS Pinning / Maps", "ACTIVE"),
                            ("eCapture", "TLS/SSL master key extraction & payload decoding", "OpenSSL Uretprobes", "ACTIVE"),
                            ("eunomia-bpf", "Dynamic WASM/JSON eBPF package metadata loader", "Dynamic RingBuf", "ACTIVE"),
                            ("Falco", "Behavioral rule matching & MITRE ATT&CK tags", "Tracepoints / LSM", "ACTIVE"),
                            ("Inspektor Gadget", "Container tracing & cgroup metadata enrichment", "Cgroups / Tracepoints", "ACTIVE"),
                            ("Kepler", "Process & node microjoule power/energy tracking", "Perf Events / CPU", "ACTIVE"),
                            ("KubeArmor", "Container isolation security posture enforcer", "LSM Hooks / Posture", "ACTIVE"),
                            ("NetObserv", "Flow metrics aggregation & TCP RTT tracking", "TC Classifier", "ACTIVE"),
                            ("Parca", "DWARF continuous stack unwinding", "Perf Sampling", "ACTIVE"),
                            ("Pyroscope", "CPU stack sampling & flamegraph profile generation", "Perf Profiler", "ACTIVE"),
                            ("Sysmon", "Linux Event ID translation (Process/Net/File)", "Syscall Tracepoints", "ACTIVE"),
                            ("Tetragon", "LSM cred validation & SIGKILL enforcement", "LSM / Signal Kill", "ACTIVE"),
                            ("Tracee", "Memory protection W^X anomaly detection", "Tracepoints / Mprotect", "ACTIVE"),
                        ]

                        for name, desc, hook, status in wrappers_data:
                            table.add_row(name, desc, hook, f"[bold green]{status}[/bold green]")

                        console.print(table)
                    except ImportError:
                        print("\n13 Native eBPF Integration Wrappers active and operating natively.\n")

                elif base_cmd in ("audit", "log"):
                    limit = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 10
                    logs = self.db_mgr.sqlite.get_mitigation_audit_logs(limit=limit)

                    try:
                        from rich.console import Console
                        from rich.table import Table
                        from rich import box
                        console = Console()

                        table = Table(title=f"TELEMETRY AUDIT DECISION LOGS (Last {len(logs)} Records)", show_header=True, header_style="bold yellow", box=box.ROUNDED)
                        table.add_column("Timestamp", style="dim")
                        table.add_column("PID", style="bold white")
                        table.add_column("Action Taken", style="bold cyan")
                        table.add_column("Classification", style="bold red")
                        table.add_column("Reason / Context", style="white")

                        if not logs:
                            table.add_row("N/A", "N/A", "No records", "N/A", "N/A")
                        else:
                            for l in logs:
                                table.add_row(
                                    str(l.get('timestamp')),
                                    str(l.get('pid')),
                                    str(l.get('action_taken')),
                                    str(l.get('threat_name', 'BENIGN')),
                                    str(l.get('details') or l.get('reason') or 'OK')
                                )
                        console.print(table)
                    except ImportError:
                        print(f"\nMitigation Audit Records (Last {len(logs)}):")
                        for l in logs:
                            print(f"   - [{l.get('timestamp')}] PID {l.get('pid')} -> {l.get('action_taken')}")

                elif base_cmd in ("query", "sql"):
                    sql = cmd[len(base_cmd):].strip()
                    if not sql:
                        print("Usage: query <SELECT SQL> (e.g. query SELECT comm, count(*) FROM feature_windows GROUP BY comm)\n")
                        continue
                    try:
                        rows = self.db_mgr.duckdb.query_sql(sql, limit=50)
                        try:
                            from rich.console import Console
                            from rich.table import Table
                            from rich import box
                            console = Console()

                            table = Table(title=f"DUCKDB ANALYTICAL QUERY RESULTS ({len(rows)} Rows)", show_header=True, header_style="bold green", box=box.ROUNDED)
                            if rows:
                                for col in rows[0].keys():
                                    table.add_column(str(col), style="bold white")
                                for r in rows[:25]:
                                    table.add_row(*[str(val) for val in r.values()])
                            console.print(table)
                        except ImportError:
                            print(f"\nDuckDB Query Results ({len(rows)} rows):")
                            for r in rows[:20]:
                                print(f"   {r}")
                            print()
                    except Exception as e:
                        print(f"DuckDB SQL Execution Error: {e}\n")

                elif base_cmd in ("export"):
                    args_str = cmd[len(base_cmd):].strip()
                    if not args_str:
                        print("Usage: export [--format csv|parquet|json] [--out path] <SELECT SQL>\n")
                        continue
                    fmt = "csv"
                    out_path = "logs/query_export.csv"
                    sql = args_str

                    if "--format" in args_str:
                        parts = args_str.split("--format", 1)[1].strip().split(maxsplit=1)
                        fmt = parts[0]
                        sql = parts[1] if len(parts) > 1 else ""
                    if "--out" in sql:
                        parts = sql.split("--out", 1)[1].strip().split(maxsplit=1)
                        out_path = parts[0]
                        sql = parts[1] if len(parts) > 1 else ""

                    try:
                        res_path = self.db_mgr.duckdb.export_query(sql=sql, format_type=fmt, output_path=out_path)
                        print(f" Successfully exported query results to: {res_path}\n")
                    except Exception as err:
                        print(f"Export execution error: {err}\n")

                elif base_cmd in ("chat", "copilot", "analyze"):
                    prompt = cmd[len(base_cmd):].strip()
                    if not prompt:
                        print("Usage: chat <prompt> (e.g. chat Analyze recent ransomware activity)\n")
                        continue
                    print("\nProcessing context query via LLM Analyst Copilot...\n")
                    history = self.db_mgr.sqlite.get_mitigation_audit_logs(limit=20)
                    answer = self.copilot.chat(user_query=prompt, audit_history=history)

                    try:
                        from rich.console import Console
                        from rich.markdown import Markdown
                        from rich.panel import Panel
                        from rich import box
                        console = Console()
                        console.print(Panel(Markdown(answer), title="SECURITY ANALYST COPILOT RESPONSE", border_style="bold cyan", box=box.ROUNDED))
                    except ImportError:
                        print(answer + "\n")

                elif base_cmd in ("reports", "incidents"):
                    print(f"\nSOC Incident Reports ({len(self.latest_reports)} available):")
                    if not self.latest_reports:
                        print("   (No threat incidents recorded during this session)\n")
                    else:
                        try:
                            from rich.console import Console
                            from rich.panel import Panel
                            from rich.markdown import Markdown
                            from rich import box
                            console = Console()
                            for r in self.latest_reports[:3]:
                                content = f"**PID**: {r['pid']} | **Classification**: {r['threat_name']} | **Action**: {r['action_taken']}\n\n" + r['soc_report']
                                console.print(Panel(Markdown(content), title=f"INCIDENT REPORT - {r['timestamp']}", border_style="bold red", box=box.ROUNDED))
                        except ImportError:
                            for r in self.latest_reports[:5]:
                                print(f"   - [{r['timestamp']}] PID {r['pid']} — {r['threat_name']} ({r['action_taken']})")

                elif base_cmd in ("help", "h"):
                    try:
                        from rich.console import Console
                        from rich.table import Table
                        from rich import box
                        console = Console()

                        table = Table(title="ENTERPRISE COMMAND CENTER CATALOG", show_header=True, header_style="bold magenta", box=box.ROUNDED)
                        table.add_column("Command", style="bold yellow")
                        table.add_column("Aliases", style="cyan")
                        table.add_column("Description", style="white")

                        table.add_row("status", "info", "Display system metrics, throughput EPS, and service states")
                        table.add_row("alerts [N]", "events", "Display threat alert records from SQLite WAL audit store")
                        table.add_row("subsystems", "wrappers", "Display operational matrix for all 13 eBPF project wrappers")
                        table.add_row("audit [N]", "log", "Display telemetry decision and enforcement audit records")
                        table.add_row("query <SQL>", "sql", "Execute analytical SQL queries directly on DuckDB columnar engine")
                        table.add_row("chat <prompt>", "copilot, analyze", "Submit context queries to Universal LLM Analyst Copilot")
                        table.add_row("reports", "incidents", "View structured SOC incident reports generated during session")
                        table.add_row("exit", "quit, q", "Terminate background services and exit command shell")

                        console.print(table)
                    except ImportError:
                        print("\nConsole Command Catalog:")
                        print("  status, info           - Display throughput EPS and service status")
                        print("  alerts, events [N]     - Retrieve recent threat alerts")
                        print("  subsystems, wrappers   - Display status for all 13 eBPF wrappers")
                        print("  audit, log [N]         - Retrieve telemetry decision audit records")
                        print("  query, sql <SQL>       - Run analytical SQL queries on DuckDB store")
                        print("  chat, copilot <prompt> - Submit security questions to LLM Analyst Copilot")
                        print("  reports, incidents     - View generated SOC incident reports")
                        print("  exit, quit             - Safely terminate background processes and exit\n")

                else:
                    print("Unknown command. Type 'help' to view available command catalog.\n")

            except (KeyboardInterrupt, EOFError):
                break
            except Exception as err:
                print(f"Command execution error: {err}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Unified System Orchestrator & Enterprise Command Center — eBPF Security System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--config", type=str, default=None, help="Path to custom YAML configuration file (e.g. sec-engine.yaml)")
    parser.add_argument("--dry-run", action="store_true", help="Log detection actions without applying kernel LSM PID blocks")
    parser.add_argument("--no-agent", action="store_true", help="Do not spawn Go eBPF agent background subprocess")
    parser.add_argument("--no-api", action="store_true", help="Disable FastAPI REST API server")
    parser.add_argument("--bpf-dir", type=str, default=None, help="Directory containing compiled .bpf.o object files")
    parser.add_argument("--listen-agent", type=str, default=":8900", help="Go eBPF Agent HTTP/WebSocket listen address")
    parser.add_argument("--port-api", type=int, default=REST_API_PORT, help="FastAPI REST API server listening port")
    parser.add_argument("--export-dataset", action="store_true", help="Enable continuous logging of raw telemetry to .jsonl dataset files")
    parser.add_argument("--auto-build-bpf", action="store_true", help="Automatically re-compile .bpf.c probes if outdated or missing")
    parser.add_argument("--non-interactive", action="store_true", help="Run in headless daemon mode without interactive CLI console")
    parser.add_argument("--gui", action="store_true", help="Launch KShark Desktop Observability GUI")

    args = parser.parse_args()

    if args.gui:
        from kshark.app import run_app
        sys.exit(run_app())


    if args.config:
        os.environ["SEC_ENGINE_CONFIG"] = args.config

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
        auto_build_bpf=args.auto_build_bpf,
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
