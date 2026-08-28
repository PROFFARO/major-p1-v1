"""
Unit tests for Copilot RAG Process Lineage Context Enrichment & Fallback Reports.
"""

import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.llm_analyst.copilot import LLMSecurityCopilot

class TestCopilotRAGLineage(unittest.TestCase):

    def test_copilot_threat_report_includes_process_lineage(self):
        """Verify that copilot threat analysis incorporates Process Lineage Path into reports."""
        copilot = LLMSecurityCopilot(api_key="", base_url="")
        action = {
            "pid": 5432,
            "threat_name": "REVERSE_SHELL",
            "confidence": 0.98,
            "action_taken": "LOG_ONLY",
        }
        metadata = {
            "pid": 5432,
            "comm": "nc",
            "exe_path": "/usr/bin/nc",
            "parent_comm": "bash",
            "lineage_str": "systemd(1) -> sshd(880) -> bash(1000) -> nc(5432)",
            "dst_ip": "1.2.3.4",
        }

        report = copilot.analyze_threat(action=action, metadata=metadata)
        self.assertIn("Process Lineage Path", report)
        self.assertIn("systemd(1) -> sshd(880) -> bash(1000) -> nc(5432)", report)

if __name__ == "__main__":
    unittest.main()
