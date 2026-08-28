"""
Unit Tests for KShark Coloring Rules Engine.
"""

from PyQt6.QtWidgets import QApplication
import sys

app = QApplication.instance() or QApplication(sys.argv)

from kshark.core.coloring_engine import ColoringEngine, ColoringRule


def test_coloring_engine_resolution():
    engine = ColoringEngine()

    # 1. Ransomware event should be red
    bg, fg = engine.get_colors_for_event({"threat_name": "RANSOMWARE"})
    assert bg.name().upper() == "#FF4444"

    # 2. Reverse Shell should be purple
    bg, fg = engine.get_colors_for_event({"threat_name": "REVERSE_SHELL"})
    assert bg.name().upper() == "#6A1B9A"

    # 3. Benign Network event should be lavender
    bg, fg = engine.get_colors_for_event({"threat_name": "BENIGN", "event_type": "NET"})
    assert bg.name().upper() == "#E7E6FF"

    # 4. Fallback benign
    bg, fg = engine.get_colors_for_event({"threat_name": "BENIGN", "event_type": "OTHER"})
    assert bg.name().upper() == "#FFFFFF"
