"""Adversarial security tests — Phase 5."""
import unittest

class TestSanitization(unittest.TestCase):
    def test_no_sql_injection_in_param_queries(self):
        """Verify param_queries returns tuple; no raw string concat."""
        from kshark.core.param_queries import params
        q, vals = params("SELECT * FROM t WHERE id = ?", (42,))
        self.assertIn("?", q)
        self.assertNotIn("42", q)  # value not embedded in string

    def test_telemetry_schema_rejects_bad_severity(self):
        from ml_engine.preprocessing.schemas import TelemetryEvent
        with self.assertRaises(Exception):
            TelemetryEvent(event_id="e1", timestamp=0.0, source_ip="1.1.1.1", event_type="network", severity=2.0, feature_vector=[1])

if __name__ == "__main__":
    unittest.main()
