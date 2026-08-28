"""
Unit tests for Process Lineage Tree DAG and Falco Rule Hot-Reloading.
"""

import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.preprocessing.process_graph import ProcessTreeGraph
from ml_engine.rules.behavioral_engine import BehavioralEngine

class TestProcessGraphAndHotReload(unittest.TestCase):

    def test_process_tree_lineage_tracking(self):
        """Test process parent-child relationship tracking and ASCII lineage formatting."""
        tree = ProcessTreeGraph()

        # Ingest root process (systemd, PID=1)
        tree.add_event({"pid": 1, "ppid": 0, "comm": "systemd"})
        # Ingest shell process (bash, PID=100, PPID=1)
        tree.add_event({"pid": 100, "ppid": 1, "comm": "bash"})
        # Ingest reverse shell process (nc, PID=500, PPID=100)
        tree.add_event({"pid": 500, "ppid": 100, "comm": "nc"})

        self.assertEqual(tree.size(), 3)
        lineage = tree.get_lineage(500)
        self.assertEqual(len(lineage), 3)
        self.assertEqual(lineage[0]["comm"], "systemd")
        self.assertEqual(lineage[1]["comm"], "bash")
        self.assertEqual(lineage[2]["comm"], "nc")

        lineage_str = tree.get_lineage_string(500)
        self.assertIn("systemd(1) -> bash(100) -> nc(500)", lineage_str)

    def test_behavioral_engine_hot_reload(self):
        """Test that reload_rules_if_modified executes cleanly."""
        engine = BehavioralEngine()
        engine.reload_rules_if_modified()
        self.assertGreater(len(engine.rules), 0)

if __name__ == "__main__":
    unittest.main()
