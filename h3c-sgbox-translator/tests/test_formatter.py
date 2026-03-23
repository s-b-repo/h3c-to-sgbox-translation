"""
Unit tests for the SGBox Formatter.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.formatter import SGBoxFormatter


class TestSGBoxFormatter(unittest.TestCase):
    """Test SGBox output formatting."""

    def setUp(self):
        self.core_fmt = SGBoxFormatter(output_format="core")
        self.ext_fmt = SGBoxFormatter(output_format="extended")

    def test_core_format(self):
        """Core format should produce: proto src dst sport dport action."""
        parsed = {
            "proto": "TCP",
            "src": "10.1.1.10",
            "dst": "8.8.8.8",
            "sport": "52314",
            "dport": "443",
            "action": "permit",
            "app": "cPanel",  # Should NOT appear in core format
        }

        result = self.core_fmt.format(parsed)
        self.assertEqual(
            result,
            "proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=52314 dport=443 action=permit"
        )

    def test_extended_format(self):
        """Extended format should include additional fields."""
        parsed = {
            "proto": "TCP",
            "src": "10.1.1.10",
            "dst": "8.8.8.8",
            "sport": "52314",
            "dport": "443",
            "action": "permit",
            "app": "cPanel",
            "hostname": "FW-01",
        }

        result = self.ext_fmt.format(parsed)
        self.assertIn("proto=TCP", result)
        self.assertIn("app=cPanel", result)
        self.assertIn("hostname=FW-01", result)

    def test_missing_proto_returns_none(self):
        """Entries without 'proto' should be skipped."""
        result = self.core_fmt.format({"src": "1.1.1.1"})
        self.assertIsNone(result)

    def test_empty_input_returns_none(self):
        """Empty/None input returns None."""
        self.assertIsNone(self.core_fmt.format(None))
        self.assertIsNone(self.core_fmt.format({}))

    def test_sanitize_spaces(self):
        """Values with spaces should have spaces replaced."""
        parsed = {
            "proto": "TCP",
            "src": "1.1.1.1",
            "dst": "2.2.2.2",
            "sport": "1234",
            "dport": "443",
            "action": "permit",
            "src_nat_type": "Not translated",
        }

        result = self.ext_fmt.format(parsed)
        self.assertIn("src_nat_type=Not_translated", result)
        self.assertNotIn("Not translated", result)

    def test_skip_placeholder_values(self):
        """Values like '--' should be omitted."""
        parsed = {
            "proto": "TCP",
            "src": "1.1.1.1",
            "dst": "2.2.2.2",
            "sport": "80",
            "dport": "443",
            "action": "permit",
            "vlan_id": "--",
        }

        result = self.ext_fmt.format(parsed)
        self.assertNotIn("vlan_id", result)

    def test_syslog_format(self):
        """Syslog format should include PRI and hostname."""
        parsed = {
            "proto": "TCP",
            "src": "1.1.1.1",
            "dst": "2.2.2.2",
            "sport": "80",
            "dport": "443",
            "action": "permit",
            "hostname": "FW-01",
        }

        result = self.ext_fmt.format_syslog(parsed)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("<"))
        self.assertIn("h3c-translator:", result)
        self.assertIn("proto=TCP", result)

    def test_batch_format(self):
        """Batch formatting should skip None entries."""
        entries = [
            {"proto": "TCP", "src": "1.1.1.1", "dst": "2.2.2.2",
             "sport": "80", "dport": "443", "action": "permit"},
            {},
            None,
            {"proto": "UDP", "src": "3.3.3.3", "dst": "4.4.4.4",
             "sport": "53", "dport": "53", "action": "permit"},
        ]

        results = self.ext_fmt.format_batch(entries)
        self.assertEqual(len(results), 2)

    def test_pri_calculation(self):
        """Verify syslog PRI calculation."""
        # local0 (16) * 8 + info (6) = 134
        self.assertEqual(SGBoxFormatter._calculate_pri("local0", "info"), 134)
        # kern (0) * 8 + emerg (0) = 0
        self.assertEqual(SGBoxFormatter._calculate_pri("kern", "emerg"), 0)

    def test_stats_tracking(self):
        """Formatter should track format/skip counts."""
        self.core_fmt.format({"proto": "TCP", "src": "1.1.1.1",
                              "dst": "2.2.2.2", "sport": "80",
                              "dport": "443", "action": "permit"})
        self.core_fmt.format({})

        stats = self.core_fmt.stats
        self.assertEqual(stats["formatted"], 1)
        self.assertEqual(stats["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
