"""
H3C Firewall Log Parser

Parses raw H3C syslog messages from the Comware platform into structured
dictionaries. Handles the H3C key(id)=value;... format used by NAT, firewall,
and session log modules.

Dependencies: structlog
"""

import csv
import io
import ipaddress
import re
import threading

import structlog
from typing import Dict, Optional

logger = structlog.get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────
# H3C Field ID → Internal Key Mapping
# ──────────────────────────────────────────────────────────────────────
FIELD_MAP = {
    "Protocol(1001)":           "proto",
    "Application(1002)":        "app",
    "SrcIPAddr(1003)":          "src",
    "SrcPort(1004)":            "sport",
    "NatSrcIPAddr(1005)":       "nat_src",
    "NatSrcPort(1006)":         "nat_sport",
    "DstIPAddr(1007)":          "dst",
    "DstPort(1008)":            "dport",
    "NatDstIPAddr(1009)":       "nat_dst",
    "NatDstPort(1010)":         "nat_dport",
    "BeginTime_e(1013)":        "start_time",
    "EndTime_e(1014)":          "end_time",
    "RcvDSLiteTunnelPeer(1040)":"rcv_ds_tunnel",
    "SndDSLiteTunnelPeer(1041)":"snd_ds_tunnel",
    "RcvVPNInstance(1042)":     "rcv_vpn",
    "SndVPNInstance(1043)":     "snd_vpn",
    "InitPktCount(1044)":       "init_pkts",
    "RplyPktCount(1045)":       "reply_pkts",
    "InitByteCount(1046)":      "init_bytes",
    "RplyByteCount(1047)":      "reply_bytes",
    "Event(1048)":              "event",
    "Category(1174)":           "category",
    "VlanID(1175)":             "vlan_id",
    "VNI(1213)":                "vni",
    "SrcAddrTransConfig(1247)": "src_nat_type",
    "DstAddrTransConfig(1248)": "dst_nat_type",
    "RuleId(1249)":             "rule_id",
}

# ──────────────────────────────────────────────────────────────────────
# Event code → action mapping
# ──────────────────────────────────────────────────────────────────────
EVENT_ACTION_MAP = {
    "1":  "deny",       # Session denied
    "2":  "deny",       # Session denied (policy)
    "8":  "permit",     # Session created
    "9":  "close",      # Session deleted/closed
    "10": "close",      # Session aged out
}

# Regex patterns
SYSLOG_HEADER_RE = re.compile(
    r'^(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<facility>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'%%\d+\s+'
    r'(?:VsysId:\d+\s+)?'
    r'(?P<module>\S+):\s*'
)

FIELD_RE = re.compile(r'(?P<key>[A-Za-z_]+\(\d+\))=(?P<value>[^;]*)')
EVENT_CODE_RE = re.compile(r'^\((\d+)\)')

# Fields whose values must be valid IP addresses
_IP_FIELDS = {"src", "dst", "nat_src", "nat_dst"}


class H3CLogParser:
    """
    Parses H3C Comware syslog messages into structured dictionaries.

    Supports log types:
        - nat/6/NAT_IPV4_MATCH (NAT session logs)
        - FILTER/6/FILTER_... (Firewall filter logs)
        - SESSION/6/SESSION_... (Session logs)

    Thread-safe: stats counters are protected by a lock.
    """

    def __init__(self):
        self._field_map = FIELD_MAP.copy()
        self._stats_lock = threading.Lock()
        self._stats = {
            "parsed": 0,
            "failed": 0,
            "total": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        """Return parsing statistics."""
        with self._stats_lock:
            return self._stats.copy()

    def parse(self, raw_line: str) -> Optional[Dict[str, str]]:
        """
        Parse a single raw H3C syslog line into a structured dictionary.

        Args:
            raw_line: Raw syslog message string from H3C firewall.

        Returns:
            Dictionary with translated field keys, or None if unparsable.
        """
        with self._stats_lock:
            self._stats["total"] += 1

        if not raw_line or not raw_line.strip():
            with self._stats_lock:
                self._stats["failed"] += 1
            return None

        line = raw_line.strip()
        result: dict[str, str] = {}

        # ── Extract syslog header ──────────────────────────────────
        header_match = SYSLOG_HEADER_RE.search(line)
        if header_match:
            result["_src_ip"] = header_match.group("src_ip")
            result["hostname"] = header_match.group("hostname")
            result["_module"] = header_match.group("module")
            payload = line[header_match.end():]
        else:
            payload = line

        # ── Extract key(id)=value fields ───────────────────────────
        fields_found = 0
        for match in FIELD_RE.finditer(payload):
            raw_key = match.group("key")
            raw_value = match.group("value").strip()

            mapped_key = self._field_map.get(raw_key)
            if mapped_key:
                # Validate IP address fields
                if mapped_key in _IP_FIELDS and raw_value:
                    if not self._is_valid_ip(raw_value):
                        logger.warning("parser.invalid_ip",
                                        field=mapped_key,
                                        value=raw_value[:40])
                        continue
                result[mapped_key] = raw_value
                fields_found += 1
            else:
                result["_raw_" + raw_key] = raw_value

        if fields_found == 0:
            with self._stats_lock:
                self._stats["failed"] += 1
            logger.debug("parser.no_fields", line=line[:120])
            return None

        # ── Derive action from Event field ─────────────────────────
        event_raw = result.get("event", "")
        result["action"] = self._derive_action(event_raw)

        # Clean up: no action needed — formatter handles empty/placeholder values

        with self._stats_lock:
            self._stats["parsed"] += 1
        return result

    def parse_csv_line(self, csv_line: str) -> Optional[Dict[str, str]]:
        """
        Parse a CSV-formatted log line (Timestamp, Hostname, RawData).

        Uses stdlib csv.reader for correct CSV parsing.

        Args:
            csv_line: A line from the H3C CSV export.

        Returns:
            Parsed dictionary or None.
        """
        if not csv_line or csv_line.startswith("Timestamp"):
            return None

        # Use stdlib csv.reader for correct parsing
        try:
            reader = csv.reader(io.StringIO(csv_line))
            parts = next(reader)
        except (StopIteration, csv.Error):
            return self.parse(csv_line)

        if len(parts) >= 3:
            timestamp = parts[0].strip()
            hostname = parts[1].strip() if len(parts) > 1 else ""
            raw_data = parts[2].strip()
            result = self.parse(raw_data)
            if result:
                result["_csv_timestamp"] = timestamp
                # Preserve the CSV hostname if not already set by syslog header
                if hostname and "hostname" not in result:
                    result["hostname"] = hostname
            return result

        return self.parse(csv_line)

    def _derive_action(self, event_raw: str) -> str:
        """
        Map H3C Event field to a clean action string.

        "(8)Session created"  → "permit"
        "(9)Session deleted"  → "close"
        "(1)Session denied"   → "deny"
        """
        match = EVENT_CODE_RE.match(event_raw)
        if match:
            code = match.group(1)
            return EVENT_ACTION_MAP.get(code, "unknown")

        # Fallback: try to infer from text
        event_lower = event_raw.lower()
        if "created" in event_lower or "permit" in event_lower:
            return "permit"
        elif "denied" in event_lower or "deny" in event_lower:
            return "deny"
        elif "deleted" in event_lower or "closed" in event_lower:
            return "close"

        return "unknown"

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """Validate that a string is a legitimate IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
