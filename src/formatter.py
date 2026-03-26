"""
SGBox Log Formatter

Converts parsed H3C log dictionaries into SGBox-compatible output formats.

Supported output formats:
    core:     proto=TCP src=… dst=… sport=… dport=… action=…  (key=value)
    extended: core + all available fields                        (key=value)
    cef:      CEF:0|H3C|Comware|7.0|SigID|Name|Sev|ext=val …  (RFC-compliant)

SGBox natively understands CEF without requiring custom patterns.
Use output_format = cef in translator.config for best SGBox compatibility.

Dependencies: structlog
"""

import re
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
    # H2: New parser fields from FILTER/SESSION/policy modules
    "src_zone",
    "dst_zone",
    "policy_name",
    "user",
    "fw_action",
    "hit_count",
    "match_count",
]

# M2: PRI calculation constants — built once at module level
_SYSLOG_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3,
    "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
    "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
_SYSLOG_SEVERITIES = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}

# ── CEF (Common Event Format) constants ───────────────────────────────────
# SGBox has built-in normalization patterns for CEF — no custom SGBox config needed.
# CEF spec: https://community.microfocus.com/cfs-file/__key/communityserver-wikis-components-files/

# H3C internal key → CEF extension key (ArcSight CEF standard names)
_CEF_KEY_MAP = {
    "src":                  "src",
    "dst":                  "dst",
    "sport":                "spt",
    "dport":                "dpt",
    "proto":                "proto",
    "action":               "act",
    "app":                  "app",
    "hostname":             "shost",
    "nat_src":              "natTranslatedAddress",
    "nat_dst":              "natDestinationAddress",
    "nat_sport":            "natTranslatedPort",
    "nat_dport":            "natDestinationPort",
    "user":                 "suser",
    "init_bytes":           "out",
    "reply_bytes":          "in",
    "init_pkts":            "cnt",
    "start_time":           "start",
    "end_time":             "end",
    "event":                "msg",
    # Custom strings for firewall-specific fields (cs1–cs6)
    "policy_name":          "cs1",
    "src_zone":             "cs2",
    "dst_zone":             "cs3",
    "rule_id":              "cs4",
    "vlan_id":              "cs5",
    "vni":                  "cs6",
    "category":             "cat",
    # CEF-01: src_nat_type was mapped to cs1Label which collides with
    # policy_name's auto-emitted cs1Label. Remapped to cs8.
    "src_nat_type":         "cs8",
    "dst_nat_type":         "cs7",
}

# CEF labels for custom string fields (required by CEF spec)
_CEF_CS_LABELS = {
    "cs1": "policyName",
    "cs2": "srcZone",
    "cs3": "dstZone",
    "cs4": "ruleId",
    "cs5": "vlanId",
    "cs6": "vni",
    "cs7": "dstNatType",
    "cs8": "srcNatType",
}

# H3C action → CEF severity (0=Unknown … 10=Critical)
_CEF_SEVERITY_MAP = {
    "permit":   3,   # Low — normal traffic
    "close":    2,   # Low — session teardown
    "log":      1,   # Very low
    "deny":     7,   # High — blocked
    "drop":     8,   # High — dropped
    "reset":    8,   # High — reset
    "redirect": 5,   # Medium
    "unknown":  5,   # Medium
}

# H3C event code → CEF SignatureID
_CEF_SIGID_MAP = {
    "1":  "SESSION_DENIED",
    "2":  "SESSION_DENIED_POLICY",
    "3":  "PACKET_DROPPED",
    "4":  "PACKET_DROPPED_RATELIMIT",
    "5":  "CONNECTION_RESET",
    "6":  "SESSION_REDIRECTED",
    "7":  "LOG_ONLY",
    "8":  "SESSION_CREATED",
    "9":  "SESSION_DELETED",
    "10": "SESSION_AGED_OUT",
    "11": "SESSION_MATCHED",
    "12": "SESSION_DENIED_AUTH",
}

# H3C action → human-readable CEF event name
_CEF_EVENT_NAME_MAP = {
    "permit":   "Session Permitted",
    "deny":     "Session Denied",
    "drop":     "Packet Dropped",
    "reset":    "Connection Reset",
    "close":    "Session Closed",
    "redirect": "Session Redirected",
    "log":      "Log Only",
    "unknown":  "Unknown Event",
}


class SGBoxFormatter:
    """
    Formats parsed H3C log data into SGBox-compatible key=value strings.

    Supports two output modes:
        - core:     Minimal fields (proto, src, dst, sport, dport, action)
        - extended: All available fields

    Thread-safe: stats counters are protected by a lock.
    """

    def __init__(self, output_format: str = "cef",
                 include_hostname: bool = True,
                 include_timestamp: bool = True):
        self.output_format = output_format.lower()
        self.include_hostname = include_hostname
        self.include_timestamp = include_timestamp

        match self.output_format:
            case "core":
                self._fields = CORE_FIELDS[:]
                print(f"[FORMATTER] Format: core ({len(self._fields)} fields, key=value)")
            case "extended":
                self._fields = CORE_FIELDS + EXTENDED_FIELDS
                print(f"[FORMATTER] Format: extended ({len(self._fields)} fields, key=value)")
            case "cef":
                self._fields = CORE_FIELDS + EXTENDED_FIELDS
                print(f"[FORMATTER] Format: CEF (SGBox native — no custom pattern needed)")
            case _:
                self._fields = CORE_FIELDS + EXTENDED_FIELDS
                print(f"[FORMATTER] Unknown format '{output_format}', defaulting to CEF")
                self.output_format = "cef"

        self._stats_lock = threading.Lock()
        self._stats = {
            "formatted": 0,
            "skipped": 0,
        }

        print(f"[FORMATTER] Initialized")
        print(f"[FORMATTER]   Include hostname:  {include_hostname}")
        print(f"[FORMATTER]   Include timestamp: {include_timestamp}")

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
            print(f"[FORMATTER] ✗ Skipped — empty parsed dict")
            return None

        # Require at least proto
        match "proto" in parsed:
            case False:
                with self._stats_lock:
                    self._stats["skipped"] += 1
                print(f"[FORMATTER] ✗ Skipped — missing 'proto' field (required)")
                logger.debug("formatter.missing_proto")
                return None
            case True:
                pass

        parts = []
        for field in self._fields:
            value = parsed.get(field, "")
            if value and value not in ("--", ""):
                safe_value = self._sanitize_value(value)
                parts.append(f"{field}={safe_value}")

        if not parts:
            with self._stats_lock:
                self._stats["skipped"] += 1
            print(f"[FORMATTER] ✗ Skipped — no fields had values")
            return None

        result = " ".join(parts)
        with self._stats_lock:
            self._stats["formatted"] += 1
        print(f"[FORMATTER] ✓ Formatted ({len(parts)} fields): {result[:120]}...")
        return result

    def format_syslog(self, parsed: Dict[str, str],
                      facility: str = "local0",
                      severity: str = "info") -> Optional[str]:
        """
        Format as a complete syslog message suitable for forwarding.

        Returns a BSD-style syslog message: <PRI>TIMESTAMP HOSTNAME MSG
        """
        msg = self.format(parsed)
        if not msg:
            print(f"[FORMATTER] ✗ format_syslog — base format returned None")
            return None

        pri = self._calculate_pri(facility, severity)
        # CEF-02: Sanitize hostname/timestamp to prevent log injection
        raw_hostname = parsed.get("hostname", "h3c-firewall")
        hostname = re.sub(r'[\x00-\x1f\x7f|<>\\\n\r]', '', raw_hostname)[:253]
        timestamp = parsed.get("_csv_timestamp", "") or parsed.get("_syslog_timestamp", "")
        timestamp = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', timestamp)[:64]

        match (self.include_timestamp, bool(timestamp)):
            case (True, True):
                result = f"<{pri}>{timestamp} {hostname} h3c-translator: {msg}"
            case _:
                result = f"<{pri}>{hostname} h3c-translator: {msg}"

        print(f"[FORMATTER] ✓ Syslog message: <{pri}> host={hostname} ({len(result)} bytes)")
        return result

    def format_batch(self, parsed_list: List[Dict[str, str]]) -> List[str]:
        """Format a batch of parsed logs (auto-selects CEF or key=value mode)."""
        print(f"[FORMATTER] Batch formatting {len(parsed_list)} messages ({self.output_format})...")
        results = []
        for parsed in parsed_list:
            if self.output_format == "cef":
                formatted = self.format_cef(parsed)
            else:
                formatted = self.format(parsed)
            if formatted:
                results.append(formatted)
        print(f"[FORMATTER] ✓ Batch complete: {len(results)}/{len(parsed_list)} formatted")
        return results

    def format_cef(self, parsed: Dict[str, str]) -> Optional[str]:
        """
        Format a parsed H3C log dictionary as CEF (Common Event Format).

        SGBox has built-in CEF normalization — no custom SGBox pattern needed.

        Output: CEF:0|H3C|Comware|7.0|SignatureID|EventName|Severity|ext=val …
        """
        if not parsed:
            with self._stats_lock:
                self._stats["skipped"] += 1
            return None

        if "proto" not in parsed:
            with self._stats_lock:
                self._stats["skipped"] += 1
            logger.debug("formatter.cef_missing_proto")
            return None

        action = parsed.get("action", "unknown")

        # ── CEF header (pipe-delimited) ────────────────────────────────
        severity = _CEF_SEVERITY_MAP.get(action, 5)

        # Derive SignatureID from event code if available
        event_raw = parsed.get("event", "")
        code_match = re.match(r'^\((\d+)\)', event_raw)
        if code_match:
            sig_id = _CEF_SIGID_MAP.get(code_match.group(1), "H3C_EVENT")
        else:
            sig_id = f"H3C_{action.upper()}"

        event_name = _CEF_EVENT_NAME_MAP.get(action, "H3C Firewall Event")

        # CEF header fields must escape pipe (|) and backslash (\)
        header = (
            f"CEF:0"
            f"|H3C"
            f"|Comware"
            f"|7.0"
            f"|{self._sanitize_cef_header(sig_id)}"
            f"|{self._sanitize_cef_header(event_name)}"
            f"|{severity}"
        )

        # ── CEF extension (key=value pairs) ───────────────────────────
        ext_parts = []
        used_cs: set = set()

        for h3c_key, cef_key in _CEF_KEY_MAP.items():
            value = parsed.get(h3c_key, "")
            if not value or value == "--":
                continue
            safe_val = self._sanitize_cef_value(value)

            # Emit cs_Label before the cs_ value (CEF spec requirement)
            if cef_key in _CEF_CS_LABELS and cef_key not in used_cs:
                label_key = f"{cef_key}Label"
                ext_parts.append(f"{label_key}={_CEF_CS_LABELS[cef_key]}")
                used_cs.add(cef_key)

            ext_parts.append(f"{cef_key}={safe_val}")

        if not ext_parts:
            with self._stats_lock:
                self._stats["skipped"] += 1
            return None

        cef_msg = f"{header}|{' '.join(ext_parts)}"

        # CEF-04: Cap output length to 64KB to prevent memory exhaustion
        # from crafted mega-values. Truncate extension, keep header intact.
        if len(cef_msg) > 65536:
            cef_msg = cef_msg[:65536]
            print(f"[FORMATTER] ⚠ CEF message truncated to 64KB")

        with self._stats_lock:
            self._stats["formatted"] += 1
        print(f"[FORMATTER] ✓ CEF ({len(ext_parts)} ext fields): {cef_msg[:120]}...")
        return cef_msg

    def format_syslog_cef(self, parsed: Dict[str, str],
                          facility: str = "local0",
                          severity: str = "info") -> Optional[str]:
        """
        Wrap CEF payload in an RFC3164 syslog envelope.

        Output: <PRI>TIMESTAMP HOSTNAME CEF:0|H3C|Comware|…
        This is the format recommended for firewall→SGBox integration.
        """
        msg = self.format_cef(parsed)
        if not msg:
            return None

        pri = self._calculate_pri(facility, severity)
        # CEF-02: Sanitize hostname to prevent log injection via crafted
        # newlines, pipes, or control chars in the syslog envelope.
        raw_hostname = parsed.get("hostname", "h3c-firewall")
        hostname = re.sub(r'[\x00-\x1f\x7f|<>\\\n\r]', '', raw_hostname)[:253]
        timestamp = parsed.get("_csv_timestamp", "") or parsed.get("_syslog_timestamp", "")
        # Sanitize timestamp too (same injection vector)
        timestamp = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', timestamp)[:64]

        match (self.include_timestamp, bool(timestamp)):
            case (True, True):
                result = f"<{pri}>{timestamp} {hostname} {msg}"
            case _:
                result = f"<{pri}>{hostname} {msg}"

        print(f"[FORMATTER] ✓ Syslog/CEF: <{pri}> host={hostname} ({len(result)} bytes)")
        return result

    @staticmethod
    def _sanitize_value(value: str) -> str:
        """
        Sanitize a field value for safe inclusion in key=value output.
        Strips non-printable chars, ANSI escapes, and log-forging characters.
        """
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        sanitized = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', sanitized)
        sanitized = sanitized.replace(" ", "_")
        sanitized = sanitized.replace(";", "")
        sanitized = sanitized.replace("=", "")
        sanitized = sanitized.replace("\n", "")
        sanitized = sanitized.replace("\r", "")
        sanitized = sanitized.replace("\t", "")
        return sanitized

    @staticmethod
    def _sanitize_cef_value(value: str) -> str:
        """
        Sanitize a field value for inclusion in CEF extension key=value pairs.
        CEF spec: escape backslash and equals sign in extension values.
        Newlines must also be escaped as \\n.
        """
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        sanitized = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', sanitized)
        # CEF extension value escaping (order matters: \ first)
        sanitized = sanitized.replace("\\", "\\\\")   # \ → \\
        sanitized = sanitized.replace("=", "\\=")     # = → \=
        sanitized = sanitized.replace("\n", "\\n")    # newline → \n
        sanitized = sanitized.replace("\r", "\\n")    # CR → \n
        return sanitized

    @staticmethod
    def _sanitize_cef_header(value: str) -> str:
        """
        Sanitize a value for inclusion in the CEF pipe-delimited header.
        CEF spec: escape pipe (|) and backslash (\\) in header fields.
        """
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
        sanitized = sanitized.replace("\\", "\\\\")   # \ → \\
        sanitized = sanitized.replace("|", "\\|")     # | → \|
        return sanitized

    @staticmethod
    def _calculate_pri(facility: str, severity: str) -> int:
        """Calculate syslog PRI value from facility and severity names."""
        # M2: Uses module-level constants instead of rebuilding dicts per call
        fac = _SYSLOG_FACILITIES.get(facility.lower(), 16)
        sev = _SYSLOG_SEVERITIES.get(severity.lower(), 6)
        pri = (fac * 8) + sev
        print(f"[FORMATTER] PRI={pri} (facility={facility}/{fac}, severity={severity}/{sev})")
        return pri
