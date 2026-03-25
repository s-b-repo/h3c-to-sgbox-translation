"""
Unit tests for the H3C Log Parser.

Tests parsing of real log entries from the H3C F1000 firewall CSV export.
"""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.parser import H3CLogParser


class TestH3CLogParser(unittest.TestCase):
    """Test H3C syslog message parsing."""

    def setUp(self):
        self.parser = H3CLogParser()

    def test_parse_tcp_nat_session(self):
        """Parse a typical TCP NAT session log."""
        raw = (
            '10.16.18.1 kern.info Gole-F1000-Firewall-01 %%10 VsysId:1 '
            'nat/6/NAT_IPV4_MATCH: Protocol(1001)=TCP;Application(1002)=cPanel;'
            'Category(1174)=Other_Service;SrcIPAddr(1003)=68.183.184.83;'
            'SrcPort(1004)=46644;NatSrcIPAddr(1005)=68.183.184.83;'
            'NatSrcPort(1006)=46644;DstIPAddr(1007)=102.134.120.157;'
            'DstPort(1008)=22;NatDstIPAddr(1009)=10.17.0.13;'
            'NatDstPort(1010)=22;InitPktCount(1044)=1;InitByteCount(1046)=60;'
            'RplyPktCount(1045)=0;RplyByteCount(1047)=0;'
            'RcvVPNInstance(1042)=;SndVPNInstance(1043)=;'
            'RcvDSLiteTunnelPeer(1040)=;SndDSLiteTunnelPeer(1041)=;'
            'BeginTime_e(1013)=03132026162009;EndTime_e(1014)=;'
            'Event(1048)=(8)Session created; VlanID(1175)=--; VNI(1213)=--;'
            'RuleId(1249)=0;SrcAddrTransConfig(1247)=Not translated;'
            'DstAddrTransConfig(1248)=NAT server.'
        )

        result = self.parser.parse(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["proto"], "TCP")
        self.assertEqual(result["src"], "68.183.184.83")
        self.assertEqual(result["dst"], "102.134.120.157")
        self.assertEqual(result["sport"], "46644")
        self.assertEqual(result["dport"], "22")
        self.assertEqual(result["app"], "cPanel")
        self.assertEqual(result["nat_dst"], "10.17.0.13")
        self.assertEqual(result["nat_dport"], "22")
        self.assertEqual(result["action"], "permit")
        self.assertEqual(result["hostname"], "Gole-F1000-Firewall-01")
        self.assertEqual(result["init_pkts"], "1")
        self.assertEqual(result["init_bytes"], "60")

    def test_parse_udp_dns(self):
        """Parse a UDP DNS session log."""
        raw = (
            '10.16.18.1 kern.info Gole-F1000-Firewall-01 %%10 VsysId:1 '
            'nat/6/NAT_IPV4_MATCH: Protocol(1001)=UDP;Application(1002)=dns;'
            'Category(1174)=Protocol;SrcIPAddr(1003)=10.13.0.20;'
            'SrcPort(1004)=44000;NatSrcIPAddr(1005)=102.134.120.153;'
            'NatSrcPort(1006)=44000;DstIPAddr(1007)=8.8.8.8;'
            'DstPort(1008)=53;NatDstIPAddr(1009)=8.8.8.8;'
            'NatDstPort(1010)=53;InitPktCount(1044)=1;InitByteCount(1046)=82;'
            'RplyPktCount(1045)=0;RplyByteCount(1047)=0;'
            'RcvVPNInstance(1042)=;SndVPNInstance(1043)=;'
            'RcvDSLiteTunnelPeer(1040)=;SndDSLiteTunnelPeer(1041)=;'
            'BeginTime_e(1013)=03132026162018;EndTime_e(1014)=;'
            'Event(1048)=(8)Session created; VlanID(1175)=--; VNI(1213)=--;'
            'RuleId(1249)=0;SrcAddrTransConfig(1247)=NAT server;'
            'DstAddrTransConfig(1248)=Not translated.'
        )

        result = self.parser.parse(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["proto"], "UDP")
        self.assertEqual(result["src"], "10.13.0.20")
        self.assertEqual(result["dst"], "8.8.8.8")
        self.assertEqual(result["sport"], "44000")
        self.assertEqual(result["dport"], "53")
        self.assertEqual(result["app"], "dns")
        self.assertEqual(result["action"], "permit")
        self.assertEqual(result["nat_src"], "102.134.120.153")

    def test_parse_icmp(self):
        """Parse an ICMP log entry."""
        raw = (
            '10.16.18.1 kern.info Gole-F1000-Firewall-01 %%10 VsysId:1 '
            'nat/6/NAT_IPV4_MATCH: Protocol(1001)=ICMP;Application(1002)=ICMP;'
            'Category(1174)=Other_Service;SrcIPAddr(1003)=15.160.244.197;'
            'SrcPort(1004)=11;NatSrcIPAddr(1005)=15.160.244.197;'
            'NatSrcPort(1006)=0;DstIPAddr(1007)=102.134.120.156;'
            'DstPort(1008)=2048;NatDstIPAddr(1009)=10.17.0.253;'
            'NatDstPort(1010)=11;InitPktCount(1044)=1;InitByteCount(1046)=68;'
            'RplyPktCount(1045)=0;RplyByteCount(1047)=0;'
            'RcvVPNInstance(1042)=;SndVPNInstance(1043)=;'
            'RcvDSLiteTunnelPeer(1040)=;SndDSLiteTunnelPeer(1041)=;'
            'BeginTime_e(1013)=03132026162020;EndTime_e(1014)=;'
            'Event(1048)=(8)Session created; VlanID(1175)=--; VNI(1213)=--;'
            'RuleId(1249)=0;SrcAddrTransConfig(1247)=Not translated;'
            'DstAddrTransConfig(1248)=NAT server.'
        )

        result = self.parser.parse(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["proto"], "ICMP")
        self.assertEqual(result["src"], "15.160.244.197")

    def test_parse_empty_line(self):
        """Empty / blank lines return None."""
        self.assertIsNone(self.parser.parse(""))
        self.assertIsNone(self.parser.parse("   "))
        self.assertIsNone(self.parser.parse(None))

    def test_parse_non_h3c_line(self):
        """Non-H3C syslog lines return None."""
        self.assertIsNone(self.parser.parse("Just some random text"))

    def test_action_mapping(self):
        """Verify event code → action mapping."""
        self.assertEqual(self.parser._derive_action("(8)Session created"), "permit")
        self.assertEqual(self.parser._derive_action("(9)Session deleted"), "close")
        self.assertEqual(self.parser._derive_action("(1)Session denied"), "deny")
        self.assertEqual(self.parser._derive_action("Unknown event"), "unknown")

    def test_csv_line_parsing(self):
        """Parse a CSV-formatted log entry."""
        csv_line = (
            '"2026-03-13 10:24:05",10.16.18.1,'
            '"10.16.18.1 kern.info Gole-F1000-Firewall-01 %%10 VsysId:1 '
            'nat/6/NAT_IPV4_MATCH: Protocol(1001)=TCP;'
            'SrcIPAddr(1003)=79.124.49.114;SrcPort(1004)=51766;'
            'DstIPAddr(1007)=102.134.120.157;DstPort(1008)=61779;'
            'Event(1048)=(8)Session created"'
        )

        result = self.parser.parse_csv_line(csv_line)
        self.assertIsNotNone(result)
        self.assertEqual(result["proto"], "TCP")
        self.assertEqual(result["_csv_timestamp"], "2026-03-13 10:24:05")

    def test_stats_tracking(self):
        """Parser should track parse/fail counts."""
        self.parser.parse("Protocol(1001)=TCP;SrcIPAddr(1003)=1.1.1.1")
        self.parser.parse("garbage")

        stats = self.parser.stats
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["parsed"], 1)
        self.assertEqual(stats["failed"], 1)


if __name__ == "__main__":
    unittest.main()
