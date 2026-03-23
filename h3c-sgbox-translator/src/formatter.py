"""
SGBox Log Formatter

Converts parsed H3C log dictionaries into the clean key=value format
required by SGBox SIEM.

Output format:
    Core:     proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=52314 dport=443 action=permit
    Extended: core + app=cPanel nat_src=102.134.120.153 nat_dst=10.17.0.13 hostname=FW-01

Dependencies: structlog
"""

import threading

import structlog
from typing import Dict, Optional, List

logger = structlog.get_logger(__name__)

# Fields included in "core" output format (order matters)
CORE_FIELDS = [
    "proto",
    "src",
    "dst",
    "sport",
    "dport",
    "action",
]

# Additional fields for "extended" output format
EXTENDED_FIELDS = [
    "app",
    "category",
    "nat_src",
    "nat_dst",
    "nat_sport",
    "nat_dport",
    "init_pkts",
    "init_bytes",
    "reply_pkts",
    "reply_bytes",
    "rule_id",
    "src_nat_type",
    "dst_nat_type",
    "hostname",
    "start_time",
    "end_time",
    "vlan_id",
    "vni",
]


class SGBoxFormatter:
    """
    Formats parsed H3C log data into SGBox-compatible key=value strings.

    Supports two output modes:
        - core:     Minimal fields (proto, src, dst, sport, dport, action)
        - extended: All available fields

    Thread-safe: stats counters are protected by a lock.
    """

    def __init__(self, output_format: str = "extended",
                 include_hostname: bool = True,
                 include_timestamp: bool = True):
        self.output_format = output_format.lower()
        self.include_hostname = include_hostname
        self.include_timestamp = include_timestamp

        if self.output_format == "core":
            self._fields = CORE_FIELDS[:]
        else:
            self._fields = CORE_FIELDS + EXTENDED_FIELDS

        self._stats_lock = threading.Lock()
        self._stats = {
            "formatted": 0,
            "skipped": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        """Return formatting statistics."""
        with self._stats_lock:
            return self._stats.copy()

    def format(self, parsed: Dict[str, str]) -> Optional[str]:
        """
        Format a parsed H3C log dictionary into SGBox key=value string.

        Args:
            parsed: Dictionary from H3CLogParser.parse()

        Returns:
            Formatted string like "proto=TCP src=10.1.1.10 dst=8.8.8.8 ..."
            Returns None if essential fields are missing.
        """
        if not parsed:
            with self._stats_lock:
                self._stats["skipped"] += 1
            return None

        # Require at least proto and one of src/dst
        if "proto" not in parsed:
            self._stats["skipped"] += 1
            logger.debug("formatter.missing_proto")
            return None

        parts = []
        for field in self._fields:
            value = parsed.get(field, "")
            if value and value not in ("--", ""):
                safe_value = self._sanitize_value(value)
                parts.append(f"{field}={safe_value}")

        if not parts:
            with self._stats_lock:
                self._stats["skipped"] += 1
            return None

        with self._stats_lock:
            self._stats["formatted"] += 1
        return " ".join(parts)

    def format_syslog(self, parsed: Dict[str, str],
                      facility: str = "local0",
                      severity: str = "info") -> Optional[str]:
        """
        Format as a complete syslog message suitable for forwarding.

        Returns a BSD-style syslog message: <PRI>TIMESTAMP HOSTNAME MSG
        """
        msg = self.format(parsed)
        if not msg:
            return None

        pri = self._calculate_pri(facility, severity)
        hostname = parsed.get("hostname", "h3c-firewall")
        timestamp = parsed.get("_csv_timestamp", "")

        if self.include_timestamp and timestamp:
            return f"<{pri}>{timestamp}  {hostname} h3c-translator: {msg}"
        else:
            return f"<{pri}>{hostname} h3c-translator: {msg}"

    def format_batch(self, parsed_list: List[Dict[str, str]]) -> List[str]:
        """Format a batch of parsed logs."""
        results = []
        for parsed in parsed_list:
            formatted = self.format(parsed)
            if formatted:
                results.append(formatted)
        return results

    @staticmethod
    def _sanitize_value(value: str) -> str:
        """
        Sanitize a field value for safe inclusion in key=value output.
        Replaces spaces with underscores and removes problematic characters.
        """
        sanitized = value.replace(" ", "_")
        sanitized = sanitized.replace(";", "")
        sanitized = sanitized.replace("=", "")
        sanitized = sanitized.replace("\n", "")
        sanitized = sanitized.replace("\r", "")
        return sanitized

    @staticmethod
    def _calculate_pri(facility: str, severity: str) -> int:
        """Calculate syslog PRI value from facility and severity names."""
        facilities = {
            "kern": 0, "user": 1, "mail": 2, "daemon": 3,
            "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
            "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
            "local0": 16, "local1": 17, "local2": 18, "local3": 19,
            "local4": 20, "local5": 21, "local6": 22, "local7": 23,
        }
        severities = {
            "emerg": 0, "alert": 1, "crit": 2, "err": 3,
            "warning": 4, "notice": 5, "info": 6, "debug": 7,
        }
        fac = facilities.get(facility.lower(), 16)
        sev = severities.get(severity.lower(), 6)
        return (fac * 8) + sev
