"""
CLI / GUI Dispatcher & Main Entry Point for KShark.
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from kshark import __version__, __app_name__, __description__
from kshark.app import run_kshark


def parse_args():
    parser = argparse.ArgumentParser(
        prog="kshark",
        description=f"{__app_name__} v{__version__} — {__description__}"
    )
    parser.add_argument("-r", "--read-file", help="Read and analyze a recorded DuckDB telemetry session database", type=str)
    parser.add_argument("-f", "--filter", help="Pre-apply display filter expression on startup", type=str)
    parser.add_argument("--dark", action="store_true", help="Force dark appearance theme")
    parser.add_argument("--light", action="store_true", help="Force light appearance theme")
    parser.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    parser.add_argument("--dry-run", "--self-test", action="store_true", help="Run diagnostic headless self-test")
    return parser.parse_args()



def run_self_test() -> int:
    """Headless sanity test verifying all models, filter engine, and Qt bindings."""
    print(f"[*] Running {__app_name__} diagnostic self-test...")
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    import sys
    app = QApplication.instance() or QApplication(sys.argv)

    from kshark.core.filter_engine import compile_filter, validate_filter
    from kshark.core.coloring_engine import ColoringEngine
    from kshark.models.event_table_model import EventTableModel


    # Test 1: Filter Engine
    valid, _ = validate_filter('comm == "bash" && (syscall_id == 59 || threat != "BENIGN")')
    assert valid, "Filter validation failed"
    ast = compile_filter('comm == "bash"')
    assert ast.evaluate({"comm": "bash"}), "AST evaluation failed"
    print("  [✓] Display filter compiler & AST engine: OK")

    # Test 2: Coloring Engine
    ce = ColoringEngine()
    bg, fg = ce.get_colors_for_event({"threat_name": "RANSOMWARE"})
    assert bg.name().upper() == "#FF4444", "Coloring engine failed"
    print("  [✓] Coloring rules engine: OK")

    # Test 3: Event Table Model
    tm = EventTableModel()
    tm.add_event({"comm": "test", "pid": 1234, "syscall": "execve", "threat_name": "BENIGN", "confidence": 0.0})
    assert tm.rowCount() == 1, "Table model row count mismatch"
    print("  [✓] Event table virtualization model: OK")

    print("[*] Diagnostic self-test PASSED successfully.")
    return 0


def main():
    args = parse_args()
    if args.dry_run:
        sys.exit(run_self_test())

    sys.exit(run_kshark(sys.argv))


if __name__ == "__main__":
    main()
