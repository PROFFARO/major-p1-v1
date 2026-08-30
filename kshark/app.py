"""
KShark Centralized Entry Point — Desktop GUI & CLI Enterprise Command Center.

Author: Dayananda Bindhani
"""

import sys
import os
import argparse
from pathlib import Path

# Ensure root directory and venv site-packages are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_venv_site = PROJECT_ROOT / "ml_engine" / ".venv" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
if _venv_site.exists() and str(_venv_site) not in sys.path:
    sys.path.insert(0, str(_venv_site))

from kshark import __version__, __author__, __license__, __description__


def print_version():
    """Outputs professional open-source CLI version details (like Wireshark/Falco/Suricata)."""
    import platform

    try:
        from PyQt6.QtCore import PYQT_VERSION_STR, qVersion
        qt_info = f"PyQt {PYQT_VERSION_STR} / Qt {qVersion()}"
    except Exception:
        qt_info = "PyQt 6.8"

    py_ver = platform.python_version()
    os_name = platform.system()
    os_release = platform.release()
    arch = platform.machine()

    print(f"KShark {__version__} (v{__version__})")
    print()
    print(f"Compiled with Python {py_ver}, {qt_info}.")
    print(f"Running on {os_name} {os_release} ({arch}).")
    print()
    print("Kernel Subsystem:   eBPF CO-RE Probes (Tracepoints, KProbes, LSM, TC Filter)")
    print("Inference Engine:   Real-Time Behavioral Signatures + ML Anomaly Detection")
    print("Storage Engine:     Dual DuckDB (Columnar OLAP) + SQLite (WAL Audit Store)")
    print("Security Copilot:   Universal Multi-Provider LLM Analyst (RAG Lineage)")
    print()
    print(f"Author:             {__author__}")
    print(f"License:            {__license__}")


def _run_gui(args):
    """Launches the KShark PyQt6 Desktop GUI application."""
    from PyQt6.QtWidgets import QApplication
    from kshark.main_window import KSharkMainWindow
    from kshark.core.theme import ThemeManager

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("KShark")
    app.setOrganizationName("KShark")
    app.setApplicationDisplayName("KShark")

    tm = ThemeManager.instance()
    if getattr(args, "light", False):
        tm.set_theme(ThemeManager.THEME_WIRESHARK_LIGHT)
    elif getattr(args, "dark", False):
        tm.set_theme(ThemeManager.THEME_WIRESHARK_DARK)
    else:
        from kshark.core.settings import KSharkSettings
        saved_theme = KSharkSettings().get_theme()
        tm.set_theme(saved_theme or ThemeManager.THEME_WIRESHARK_DARK)

    window = KSharkMainWindow()
    if getattr(args, "file", None) and os.path.exists(args.file):
        window._load_capture_from_path(args.file)
    window.show()

    return app.exec()


def _run_cli(args):
    """Launches the Unified System Orchestrator & CLI Command Center."""
    import signal
    import logging
    from main import UnifiedSystemOrchestrator

    if args.config:
        os.environ["SEC_ENGINE_CONFIG"] = args.config

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
            logging.info("Running in non-interactive daemon mode. Press Ctrl+C to stop.")
            import time
            while orchestrator.running:
                time.sleep(1.0)
    finally:
        orchestrator.stop()
    return 0


def run_app(argv=None):
    """
    Centralized router for GUI, CLI, and diagnostic operations.
    """
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="kshark",
        description="KShark — Linux Kernel eBPF Observability & Threat Detection System (GUI / CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Execution Modes:
  ./bin/kshark                     Launch full Wireshark-fidelity Desktop GUI (Default)
  ./bin/kshark --cli               Launch interactive Terminal Command Center & SOC Console
  ./bin/kshark --dry-run           Launch CLI in non-blocking test mode
  ./bin/kshark --version, -v       Display author, architecture, and version metadata
  ./bin/kshark --self-test         Run diagnostic engine self-test suite
        """,
    )

    # Informational & Diagnostic Flags
    parser.add_argument("-v", "--version", action="store_true", help="Display KShark version, author, and system architecture details")
    parser.add_argument("--self-test", action="store_true", help="Run comprehensive diagnostic self-test and exit")

    # Mode Selectors
    parser.add_argument("--gui", action="store_true", help="Explicitly launch KShark Desktop Observability GUI")
    parser.add_argument("--cli", action="store_true", help="Launch interactive Terminal Command Center & SOC Console")

    # GUI Options
    parser.add_argument("--dark", action="store_true", help="Launch GUI in Wireshark Dark mode (Default)")
    parser.add_argument("--light", action="store_true", help="Launch GUI in Wireshark Light mode")
    parser.add_argument("--no-root", action="store_true", help="Allow running in unprivileged non-root mode")
    parser.add_argument("file", nargs="?", default=None, help="Capture file to open in GUI (.scap, .jsonl, .duckdb)")

    # CLI Orchestrator Options
    parser.add_argument("--config", type=str, default=None, help="Path to custom YAML configuration file (e.g. sec-engine.yaml)")
    parser.add_argument("--dry-run", action="store_true", help="Log detection actions without applying kernel LSM PID blocks")
    parser.add_argument("--no-agent", action="store_true", help="Do not spawn Go eBPF agent background subprocess")
    parser.add_argument("--no-api", action="store_true", help="Disable FastAPI REST API server")
    parser.add_argument("--bpf-dir", type=str, default=None, help="Directory containing compiled .bpf.o object files")
    parser.add_argument("--listen-agent", type=str, default=":8900", help="Go eBPF Agent HTTP/WebSocket listen address")
    parser.add_argument("--port-api", type=int, default=8901, help="FastAPI REST API server listening port")
    parser.add_argument("--export-dataset", action="store_true", help="Enable continuous logging of raw telemetry to .jsonl dataset files")
    parser.add_argument("--auto-build-bpf", action="store_true", help="Automatically re-compile .bpf.c probes if outdated or missing")
    parser.add_argument("--non-interactive", action="store_true", help="Run in headless daemon mode without interactive CLI console")

    args = parser.parse_args(argv)

    # 1. Version Output
    if args.version:
        print_version()
        return 0

    # 2. Self-Test Diagnostic
    if args.self_test:
        print("[*] Running KShark diagnostic self-test...")
        from kshark.core.filter_engine import compile_filter
        from kshark.core.coloring_engine import ColoringEngine
        from kshark.models.event_table_model import EventTableModel

        node = compile_filter("evt.type == 'execve' and proc.name == 'curl'")
        assert node is not None, "Filter compile failed"
        print("  [✓] KShark display filter compiler & AST engine: OK")

        engine = ColoringEngine()
        assert len(engine.rules) > 0, "Coloring rules empty"
        print("  [✓] KShark coloring rules engine: OK")

        model = EventTableModel()
        model.add_events_batch([{"syscall": "execve", "comm": "bash", "pid": 1234, "timestamp_ns": 1000000000}])
        assert model.rowCount() == 1, "Model insertion failed"
        print("  [✓] KShark event table virtualization model: OK")

        print("[*] Diagnostic self-test PASSED successfully.")
        return 0

    # 3. Mode Evaluation: Dynamic Routing
    cli_flags_present = (
        args.cli
        or args.dry_run
        or args.no_agent
        or args.no_api
        or args.non_interactive
        or args.export_dataset
        or args.auto_build_bpf
        or (args.config is not None)
        or (args.bpf_dir is not None)
        or (args.listen_agent != ":8900")
        or (args.port_api != 8901 and not args.gui)
    )

    if cli_flags_present and not args.gui:
        return _run_cli(args)
    else:
        return _run_gui(args)


if __name__ == "__main__":
    sys.exit(run_app())
