#!/usr/bin/env python3
"""
Master Test Runner for eBPF-ML Security System.

Discovers and executes all unit & integration tests inside tests/ directory.
"""

import sys
import unittest
from pathlib import Path

# Auto-inject project root into sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_test_suite():
    """Discover and execute all test cases under tests/ directory."""
    print("=" * 70)
    print(" 🛡️  Running eBPF-ML Security System Centralized Test Suite")
    print("=" * 70)

    loader = unittest.TestLoader()
    tests_dir = PROJECT_ROOT / "tests"
    suite = loader.discover(start_dir=str(tests_dir), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("=" * 70)
    if result.wasSuccessful():
        print(" SUCCESS: All tests passed cleanly! 100% Pass Rate.")
        sys.exit(0)
    else:
        print(f" FAILURE: {len(result.failures)} failures, {len(result.errors)} errors encountered.")
        sys.exit(1)


if __name__ == "__main__":
    run_test_suite()
