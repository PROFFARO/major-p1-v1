#!/usr/bin/env python3
"""
Legacy entry point wrapper — forwards execution to root main.py orchestrator.
"""

import sys
from pathlib import Path

# Forward execution to root main.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from main import main

if __name__ == "__main__":
    main()
