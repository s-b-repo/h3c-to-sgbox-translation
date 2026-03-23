"""
Integration test: Parse real CSV data and verify end-to-end translation.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import H3CLogParser
from src.formatter import SGBoxFormatter


# Path to the sample CSV in the project root
CSV_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..",
    "Raw_logs_1_8694_20260313102459.csv"
)


class TestIntegration(unittest.TestCase):
    """End-to-end translation of real H3C log data."""

    def setUp(self):
        self.parser = H3CLogParser()
        self.formatter = SGBoxFormatter(output_format="core")
        self.ext_formatter = SGBoxFormatter(output_format="extended")

    @unittest.skipUnless(os.path.exists(CSV_PATH), "CSV sample file not found")
    def test_translate_first_100_lines(self):
        """Parse and format the first 100 data lines from the CSV."""
        translated = []
        total = 0

        with open(CSV_PATH, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i == 0:
                    continue  # Skip header
                if i > 100:
                    break

                total += 1
                parsed = self.parser.parse_csv_line(line.strip())
                if parsed:
                    formatted = self.formatter.format(parsed)
                    if formatted:
                        translated.append(formatted)

        # Should translate most lines successfully
        self.assertGreater(len(translated), 80,
                           "Expected >80% translation rate for real data")

        # Verify format of first translated line
        first = translated[0]
        self.assertIn("proto=", first)
        self.assertIn("src=", first)
        self.assertIn("dst=", first)
        self.assertIn("action=", first)

        # Should NOT contain H3C format artifacts
        self.assertNotIn("Protocol(1001)", first)
        self.assertNotIn("SrcIPAddr(1003)", first)

        print("\n=== Integration Test Results ===")
        print("Lines processed: {}".format(total))
        print("Lines translated: {}".format(len(translated)))
        print("Sample output (first 5):")
        for line in translated[:5]:
            print("  " + line)

    @unittest.skipUnless(os.path.exists(CSV_PATH), "CSV sample file not found")
    def test_extended_format_has_extra_fields(self):
        """Extended format should include app, nat fields, hostname."""
        with open(CSV_PATH, "r", encoding="utf-8", errors="replace") as f:
            next(f)  # Skip header
            line = next(f).strip()

        parsed = self.parser.parse_csv_line(line)
        self.assertIsNotNone(parsed)

        core = self.formatter.format(parsed)
        extended = self.ext_formatter.format(parsed)

        # Extended should be longer (more fields)
        self.assertGreater(len(extended), len(core))
        self.assertIn("app=", extended)

    def test_expected_sgbox_format(self):
        """Verify output matches the exact format SGBox expects."""
        raw = (
            '10.16.18.1 kern.info Gole-F1000-Firewall-01 %%10 VsysId:1 '
            'nat/6/NAT_IPV4_MATCH: Protocol(1001)=TCP;'
            'SrcIPAddr(1003)=10.1.1.10;SrcPort(1004)=52314;'
            'DstIPAddr(1007)=8.8.8.8;DstPort(1008)=443;'
            'Event(1048)=(8)Session created'
        )

        parsed = self.parser.parse(raw)
        formatted = self.formatter.format(parsed)

        self.assertEqual(
            formatted,
            "proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=52314 dport=443 action=permit"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
