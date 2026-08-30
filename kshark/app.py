"""
KShark Desktop Application Entry Point.
"""

import sys
import argparse
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

# Ensure root directory is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from kshark.main_window import KSharkMainWindow
from kshark.core.theme import ThemeManager


def run_app(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="KShark — System Call & Kernel Observability Analyzer")
    parser.add_argument("--dark", action="store_true", help="Launch in KShark Dark mode")
    parser.add_argument("--light", action="store_true", help="Launch in KShark Light mode")
    parser.add_argument("--no-root", action="store_true", help="Allow running in unprivileged non-root mode")
    parser.add_argument("--self-test", action="store_true", help="Run diagnostic self-test and exit")
    parser.add_argument("file", nargs="?", default=None, help="Capture file to open (.scap, .jsonl, .duckdb)")
    args = parser.parse_args(argv)


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

    app = QApplication(sys.argv)
    app.setApplicationName("KShark")
    app.setOrganizationName("KShark")
    app.setApplicationDisplayName("KShark")

    tm = ThemeManager.instance()
    if args.light:
        tm.set_theme(ThemeManager.THEME_KSHARK_LIGHT)
    elif args.dark:
        tm.set_theme(ThemeManager.THEME_KSHARK_DARK)
    else:
        tm.set_theme(ThemeManager.THEME_KSHARK_DARK)

    window = KSharkMainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(run_app())
