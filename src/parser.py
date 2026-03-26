"""
H3C Firewall Log Parser

Parses raw H3C syslog messages from the Comware platform into structured
dictionaries. Handles the H3C key(id)=value;... format used by NAT, firewall,
and session log modules.

Supports multiple syslog header formats:
  - RFC 3164 with PRI prefix: <189>IP FACILITY HOSTNAME %%N ...
  - RFC 3164 with BSD timestamp: <189>Mar 13 16:20:09 IP FACILITY HOSTNAME ...
  - RFC 5424 with ISO timestamp: <189>1 2026-03-13T16:20:09Z HOSTNAME ...
  - H3C native: IP FACILITY HOSTNAME %%N [VsysId:N] MODULE:
  - Raw key(id)=value payload (no header)

Dependencies: structlog
"""

import csv
import io
import ipaddress
import os
import re
import threading
from datetime import datetime, timezone

import structlog
from typing import Dict, Optional

logger = structlog.get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────
# H3C Field ID → Internal Key Mapping
# ──────────────────────────────────────────────────────────────────────
FIELD_MAP = {
    # ── Session / NAT fields (1001–1049) ──────────────────────────
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
    "Action(1053)":             "fw_action",

    # ── Firewall / Policy fields (1060–1080) ──────────────────────
    "HitCount(1068)":           "hit_count",
    "MatchCount(1069)":         "match_count",
    "PolicyName(1070)":         "policy_name",
    "SrcZone(1071)":            "src_zone",
    "DstZone(1072)":            "dst_zone",
    "UserName(1073)":           "user",

    # ── Extended metadata (1174+) ─────────────────────────────────
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
    "3":  "drop",       # Packet dropped
    "4":  "drop",       # Packet dropped (rate limit)
    "5":  "reset",      # Connection reset
    "6":  "redirect",   # Session redirected
    "7":  "log",        # Log only
    "8":  "permit",     # Session created
    "9":  "close",      # Session deleted/closed
    "10": "close",      # Session aged out
    "11": "permit",     # Session matched
    "12": "deny",       # Session denied (auth)
}

# ──────────────────────────────────────────────────────────────────────
# Regex patterns — multi-format syslog header parsing
# ──────────────────────────────────────────────────────────────────────

# Strip RFC 3164/5424 PRI prefix: <NNN>
PRI_RE = re.compile(r'^<(\d{1,3})>')

# BSD timestamp: Mar 13 16:20:09 or Mar  3 16:20:09
BSD_TS_RE = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
)

# RFC 5424 timestamp: 2026-03-13T16:20:09Z or with offset
ISO_TS_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+'
)

# RFC 5424 version prefix (just "1 " after PRI)
RFC5424_VER_RE = re.compile(r'^(\d)\s+')

# H3C marker: %%NN  (1–4 digits)
H3C_MARKER_RE = re.compile(r'%%(\d{1,4})\s+')

# Original syslog header (works when marker is already located)
# Matches: IP FACILITY HOSTNAME %%N [VsysId:N] MODULE:
SYSLOG_HEADER_RE = re.compile(
    r'^(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<facility>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'%%\d{1,4}\s+'
    r'(?:VsysId:\d+\s+)?'
    r'(?P<module>\S+):\s*'
)

# Relaxed header: HOSTNAME %%N [VsysId:N] MODULE:  (no IP, no facility)
RELAXED_HEADER_RE = re.compile(
    r'^(?P<hostname>\S+)\s+'
    r'%%\d{1,4}\s+'
    r'(?:VsysId:\d+\s+)?'
    r'(?P<module>\S+):\s*'
)

# Module after VsysId or directly after %%N marker
MODULE_AFTER_MARKER_RE = re.compile(
    r'(?:VsysId:\d+\s+)?(?P<module>\S+):\s*'
)

# Field extractor: Key(NNN)=value;
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
        - Any payload with key(id)=value fields

    Supports syslog header formats:
        - RFC 3164 with <PRI> prefix
        - RFC 3164 with BSD timestamp
        - RFC 5424 with ISO timestamp
        - H3C native (IP FACILITY HOSTNAME %%N ...)
        - Raw key(id)=value payload only

    Thread-safe: stats counters are protected by a lock.
    """

    # C1: Max failed log file size (50 MB) and rotation count
    _FAILED_LOG_MAX_BYTES = 50 * 1024 * 1024
    _FAILED_LOG_MAX_FILES = 5
    # C2: Batch failed lines in memory, flush every N lines
    _FAILED_FLUSH_INTERVAL = 100

    def __init__(self, failed_log_dir: str = "/var/log/h3c-translator/failed"):
        self._field_map = FIELD_MAP.copy()
        self._stats_lock = threading.Lock()
        self._stats = {
            "parsed": 0,
            "failed": 0,
            "total": 0,
        }

        # ── Failed-to-parse log directory ──────────────────────────
        self._failed_log_dir = failed_log_dir
        self._failed_buffer: list[str] = []  # C2: in-memory batch buffer
        self._failed_buffer_lock = threading.Lock()
        try:
            os.makedirs(self._failed_log_dir, exist_ok=True)
            print(f"[PARSER] Failed-to-parse dir: {self._failed_log_dir}")
        except OSError as e:
            print(f"[PARSER] ⚠ Cannot create failed log dir {self._failed_log_dir}: {e}")
            logger.warning("parser.failed_log_dir_error",
                           path=self._failed_log_dir, error=str(e))

        print(f"[PARSER] Initialized with {len(self._field_map)} field mappings")

    @property
    def stats(self) -> Dict[str, int]:
        """Return parsing statistics."""
        with self._stats_lock:
            return self._stats.copy()

    def parse(self, raw_line: str) -> Optional[Dict[str, str]]:
        """
        Parse a single raw H3C syslog line into a structured dictionary.

        Progressively strips RFC 3164/5424 headers, PRI values, and
        timestamps before extracting key(id)=value fields.

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
            print(f"[PARSER] ✗ Empty line received, skipping")
            self._save_failed_line(raw_line or "", reason="empty_line")
            return None

        line = raw_line.strip()
        result: dict[str, str] = {}

        # ── Phase 1: Strip PRI prefix <NNN> ────────────────────────
        remaining = line
        pri_match = PRI_RE.match(remaining)
        if pri_match:
            result["_pri"] = pri_match.group(1)
            remaining = remaining[pri_match.end():]
            print(f"[PARSER] Stripped PRI=<{result['_pri']}>")

        # ── Phase 2: Strip RFC 5424 version digit ──────────────────
        ver_match = RFC5424_VER_RE.match(remaining)
        if ver_match:
            # Only strip if followed by an ISO timestamp (avoid false positives)
            after_ver = remaining[ver_match.end():]
            if ISO_TS_RE.match(after_ver):
                result["_rfc5424_ver"] = ver_match.group(1)
                remaining = after_ver
                print(f"[PARSER] Stripped RFC5424 version={result['_rfc5424_ver']}")

        # ── Phase 3: Strip timestamps (BSD or ISO) ─────────────────
        bsd_match = BSD_TS_RE.match(remaining)
        if bsd_match:
            result["_syslog_timestamp"] = bsd_match.group(1)
            remaining = remaining[bsd_match.end():]
            print(f"[PARSER] Stripped BSD timestamp={result['_syslog_timestamp']}")
        else:
            iso_match = ISO_TS_RE.match(remaining)
            if iso_match:
                result["_syslog_timestamp"] = iso_match.group(1)
                remaining = remaining[iso_match.end():]
                print(f"[PARSER] Stripped ISO timestamp={result['_syslog_timestamp']}")

        # ── Phase 4: Match H3C syslog header ───────────────────────
        payload = None

        # Strategy A: Full header — IP FACILITY HOSTNAME %%N [VsysId:N] MODULE:
        header_match = SYSLOG_HEADER_RE.match(remaining)
        if header_match:
            result["_src_ip"] = header_match.group("src_ip")
            result["hostname"] = header_match.group("hostname")
            result["_module"] = header_match.group("module")
            payload = remaining[header_match.end():]
            print(f"[PARSER] Header(full): src_ip={result['_src_ip']} "
                  f"hostname={result['hostname']} module={result['_module']}")
        else:
            # Strategy B: Relaxed — HOSTNAME %%N [VsysId:N] MODULE:
            relaxed_match = RELAXED_HEADER_RE.match(remaining)
            if relaxed_match:
                result["hostname"] = relaxed_match.group("hostname")
                result["_module"] = relaxed_match.group("module")
                payload = remaining[relaxed_match.end():]
                print(f"[PARSER] Header(relaxed): hostname={result['hostname']} "
                      f"module={result['_module']}")
            else:
                # Strategy C: Find %%N marker anywhere and extract module after it
                marker_match = H3C_MARKER_RE.search(remaining)
                if marker_match:
                    after_marker = remaining[marker_match.end():]
                    mod_match = MODULE_AFTER_MARKER_RE.match(after_marker)
                    if mod_match:
                        result["_module"] = mod_match.group("module")
                        payload = after_marker[mod_match.end():]
                        print(f"[PARSER] Header(marker): module={result['_module']}")

                        # Try to extract hostname from text before markers
                        before_marker = remaining[:marker_match.start()].strip()
                        parts = before_marker.split()
                        if parts:
                            # Last word before %%N is usually the hostname
                            result["hostname"] = parts[-1]
                            # First word might be an IP
                            if len(parts) >= 1 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                                result["_src_ip"] = parts[0]
                    else:
                        # Marker found but no module — payload starts after marker
                        payload = after_marker
                        print(f"[PARSER] Header(marker-only): no module found")

        # Strategy D: No header matched — treat entire remaining as payload
        if payload is None:
            print(f"[PARSER] No syslog header found, parsing raw payload")
            payload = remaining

        # ── Phase 5: Extract key(id)=value fields ──────────────────
        fields_found = 0
        for match in FIELD_RE.finditer(payload):
            raw_key = match.group("key")
            raw_value = match.group("value").strip()

            mapped_key = self._field_map.get(raw_key)
            match mapped_key:
                case None:
                    result["_raw_" + raw_key] = raw_value
                case _ if mapped_key in _IP_FIELDS and raw_value:
                    if not self._is_valid_ip(raw_value):
                        print(f"[PARSER] ✗ Invalid IP for {mapped_key}: {raw_value[:40]}")
                        logger.warning("parser.invalid_ip",
                                        field=mapped_key,
                                        value=raw_value[:40])
                        continue
                    result[mapped_key] = raw_value
                    fields_found += 1
                    print(f"[PARSER]   {mapped_key}={raw_value}")
                case _:
                    result[mapped_key] = raw_value
                    fields_found += 1
                    print(f"[PARSER]   {mapped_key}={raw_value}")

        if fields_found == 0:
            with self._stats_lock:
                self._stats["failed"] += 1
            print(f"[PARSER] ✗ No recognized fields found in: {line[:120]}")
            logger.debug("parser.no_fields", line=line[:120])
            self._save_failed_line(line, reason="no_recognized_fields")
            return None

        # ── Phase 6: Derive action from Event or Action field ──────
        event_raw = result.get("event", "")
        fw_action = result.get("fw_action", "")
        if fw_action:
            # Direct action field takes precedence
            result["action"] = fw_action.lower().strip()
            print(f"[PARSER] ✓ Direct fw_action={result['action']}")
        else:
            result["action"] = self._derive_action(event_raw)

        print(f"[PARSER] ✓ Parsed {fields_found} fields, action={result['action']}")

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
            print(f"[PARSER] Skipping CSV header or empty line")
            return None

        # Use stdlib csv.reader for correct parsing
        try:
            reader = csv.reader(io.StringIO(csv_line))
            parts = next(reader)
        except (StopIteration, csv.Error) as e:
            print(f"[PARSER] ✗ CSV parse failed ({e}), discarding malformed line")
            logger.warning("parser.csv_parse_failed", error=str(e))
            return None

        if len(parts) >= 3:
            timestamp = parts[0].strip()
            hostname = parts[1].strip()  # L2: len>=3 guarantees index 1 exists
            raw_data = parts[2].strip()
            print(f"[PARSER] CSV: timestamp={timestamp} hostname={hostname}")
            result = self.parse(raw_data)
            if result:
                result["_csv_timestamp"] = timestamp
                if hostname and "hostname" not in result:
                    result["hostname"] = hostname
            else:
                # M1: Save original CSV line context on parse failure
                self._save_failed_line(csv_line, reason="csv_payload_unparsable")
            return result

        print(f"[PARSER] CSV has <3 fields, trying raw parse")
        result = self.parse(csv_line)
        if not result:
            # M1: Save original CSV line context on fallback failure
            self._save_failed_line(csv_line, reason="csv_insufficient_fields")
        return result

    def _derive_action(self, event_raw: str) -> str:
        """
        Map H3C Event field to a clean action string.

        "(8)Session created"  → "permit"
        "(9)Session deleted"  → "close"
        "(1)Session denied"   → "deny"
        """
        match_obj = EVENT_CODE_RE.match(event_raw)
        match match_obj:
            case None:
                pass  # Fall through to text-based matching
            case _:
                code = match_obj.group(1)
                action = EVENT_ACTION_MAP.get(code, "unknown")
                print(f"[PARSER] Event code ({code}) → action={action}")
                return action

        # Fallback: try to infer from text
        event_lower = event_raw.lower()
        match event_lower:
            case s if "created" in s or "permit" in s or "allow" in s:
                print(f"[PARSER] Event text '{event_raw}' → action=permit")
                return "permit"
            case s if "denied" in s or "deny" in s or "block" in s or "reject" in s:
                print(f"[PARSER] Event text '{event_raw}' → action=deny")
                return "deny"
            case s if "deleted" in s or "closed" in s or "teardown" in s:
                print(f"[PARSER] Event text '{event_raw}' → action=close")
                return "close"
            case s if "drop" in s:
                print(f"[PARSER] Event text '{event_raw}' → action=drop")
                return "drop"
            case s if "reset" in s:
                print(f"[PARSER] Event text '{event_raw}' → action=reset")
                return "reset"
            case _:
                print(f"[PARSER] Event text '{event_raw}' → action=unknown")
                return "unknown"

        # L1: Explicit safety return (should never be reached, but satisfies type checker)
        return "unknown"

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """Validate that a string is a legitimate IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _save_failed_line(self, raw_line: str, reason: str = "unknown") -> None:
        """
        Buffer a failed-to-parse line in memory, flushing to disk periodically.

        C2: Avoids per-line file I/O that blocks the event loop.
        C1: Rotates log files when they exceed _FAILED_LOG_MAX_BYTES.

        File format: failed_YYYY-MM-DD.txt
        Each entry: ISO timestamp | reason | raw line
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"{timestamp} | {reason} | {raw_line}\n"

        with self._failed_buffer_lock:
            self._failed_buffer.append(entry)
            if len(self._failed_buffer) >= self._FAILED_FLUSH_INTERVAL:
                self._flush_failed_buffer()

    def _flush_failed_buffer(self) -> None:
        """
        Flush buffered failed lines to disk. Called under _failed_buffer_lock.
        C1: Rotates when file exceeds max size.
        """
        if not self._failed_buffer:
            return

        try:
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            filename = os.path.join(self._failed_log_dir, f"failed_{today}.txt")

            # C1: Rotate if file exceeds max size
            if os.path.exists(filename):
                size = os.path.getsize(filename)
                if size >= self._FAILED_LOG_MAX_BYTES:
                    self._rotate_failed_log(filename)

            with open(filename, "a", encoding="utf-8") as f:
                f.writelines(self._failed_buffer)

            count = len(self._failed_buffer)
            self._failed_buffer.clear()
            print(f"[PARSER] Flushed {count} failed lines to {filename}")
        except OSError as e:
            self._failed_buffer.clear()  # Don't let buffer grow on persistent errors
            print(f"[PARSER] ⚠ Could not flush failed lines: {e}")
            logger.warning("parser.flush_failed_error", error=str(e))

    def _rotate_failed_log(self, filepath: str) -> None:
        """Rotate a failed log file: .txt → .txt.1 → .txt.2 ... up to max files."""
        try:
            for i in range(self._FAILED_LOG_MAX_FILES - 1, 0, -1):
                src = f"{filepath}.{i}" if i > 1 else f"{filepath}.1"
                dst = f"{filepath}.{i + 1}"
                if os.path.exists(src):
                    if i + 1 >= self._FAILED_LOG_MAX_FILES:
                        os.remove(src)  # Delete oldest
                    else:
                        os.rename(src, dst)
            if os.path.exists(filepath):
                os.rename(filepath, f"{filepath}.1")
            print(f"[PARSER] Rotated failed log: {filepath}")
        except OSError as e:
            print(f"[PARSER] ⚠ Failed log rotation error: {e}")

    def flush_remaining(self) -> None:
        """Flush any remaining buffered failed lines (call on shutdown)."""
        with self._failed_buffer_lock:
            self._flush_failed_buffer()
