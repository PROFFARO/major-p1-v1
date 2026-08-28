"""
Unit tests for Configuration Management (sec-engine.yaml & ml_engine/config.py).
"""

import unittest
from pathlib import Path
import os
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine import config

class TestConfigManagement(unittest.TestCase):

    def test_default_config_file_exists(self):
        """Verify sec-engine.yaml exists at project root."""
        yaml_file = PROJECT_ROOT / "sec-engine.yaml"
        self.assertTrue(yaml_file.exists(), "sec-engine.yaml should exist in project root")

    def test_config_variables_loaded(self):
        """Verify key config variables are properly initialized."""
        self.assertIsNotNone(config.AGENT_WS_URL)
        self.assertIsNotNone(config.REST_API_PORT)
        self.assertGreater(config.SLIDING_WINDOW_SECONDS, 0)
        self.assertGreater(config.DETECTION_ALERT_THRESHOLD, 0.0)

if __name__ == "__main__":
    unittest.main()
