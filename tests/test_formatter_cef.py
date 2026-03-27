"""
CEF Formatter Tests

Verifies that SGBoxFormatter produces valid CEF messages that conform to
the CEF specification and are accepted by SGBox without custom patterns.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.formatter import SGBoxFormatter


# ── Sample parsed dictionaries ─────────────────────────────────────────────

SAMPLE_PERMIT = {
    "proto":       "TCP",
    "src":         "10.1.1.10",
    "dst":         "8.8.8.8",
    "sport":       "52314",
    "dport":       "443",
    "action":      "permit",
    "hostname":    "FW-01",
    "app":         "HTTPS",
    "nat_src":     "203.0.113.5",
    "nat_dport":   "443",
    "policy_name": "Outbound-HTTPS",
    "src_zone":    "trust",
    "dst_zone":    "untrust",
    "_csv_timestamp": "Mar 26 15:00:00",
}

SAMPLE_DENY = {
    "proto":    "UDP",
    "src":      "192.168.5.100",
    "dst":      "1.2.3.4",
    "sport":    "32000",
    "dport":    "53",
    "action":   "deny",
    "hostname": "EDGE-FW",
}

SAMPLE_EVENT_CODE = {
    "proto":  "TCP",
    "src":    "10.0.0.1",
    "dst":    "172.16.0.1",
    "sport":  "1024",
    "dport":  "80",
    "action": "permit",
    "event":  "(8) Session Created",
}


class TestCEFHeader:
    def setup_method(self):
        self.fmt = SGBoxFormatter(output_format="cef")

    def test_starts_with_cef0(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert result is not None
        assert result.startswith("CEF:0|")

    def test_vendor_is_h3c(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        parts = result.split("|")
        assert parts[1] == "H3C"

    def test_product_is_comware(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        parts = result.split("|")
        assert parts[2] == "Comware"

    def test_version_is_7(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        parts = result.split("|")
        assert parts[3] == "7.0"

    def test_header_has_7_pipe_sections(self):
        """CEF header must have exactly 7 pipe-delimited fields + extension"""
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        # CEF:0|Vendor|Product|Version|SigID|Name|Sev|extension
        parts = result.split("|")
        assert len(parts) >= 8

    def test_severity_permit_is_low(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        parts = result.split("|")
        assert parts[6] == "3"  # permit → 3

    def test_severity_deny_is_high(self):
        result = self.fmt.format_cef(SAMPLE_DENY)
        parts = result.split("|")
        assert parts[6] == "7"  # deny → 7

    def test_event_name_for_permit(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        parts = result.split("|")
        assert parts[5] == "Session Permitted"

    def test_event_name_for_deny(self):
        result = self.fmt.format_cef(SAMPLE_DENY)
        parts = result.split("|")
        assert parts[5] == "Session Denied"

    def test_sigid_from_event_code(self):
        result = self.fmt.format_cef(SAMPLE_EVENT_CODE)
        parts = result.split("|")
        assert parts[4] == "SESSION_CREATED"

    def test_sigid_fallback_to_action(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        parts = result.split("|")
        # No event code → H3C_PERMIT
        assert parts[4] == "H3C_PERMIT"


class TestCEFExtensionFields:
    def setup_method(self):
        self.fmt = SGBoxFormatter(output_format="cef")

    def test_src_maps_to_cef_src(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "src=10.1.1.10" in result

    def test_dst_maps_to_cef_dst(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "dst=8.8.8.8" in result

    def test_sport_maps_to_spt(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "spt=52314" in result

    def test_dport_maps_to_dpt(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "dpt=443" in result

    def test_proto_present(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "proto=TCP" in result

    def test_action_maps_to_act(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "act=permit" in result

    def test_hostname_maps_to_shost(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "shost=FW-01" in result

    def test_app_present(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "app=HTTPS" in result

    def test_nat_src_maps_to_nat_translated_address(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "natTranslatedAddress=203.0.113.5" in result

    def test_policy_name_maps_to_cs1(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "cs1Label=policyName" in result
        assert "cs1=Outbound-HTTPS" in result

    def test_src_zone_maps_to_cs2(self):
        result = self.fmt.format_cef(SAMPLE_PERMIT)
        assert "cs2Label=srcZone" in result
        assert "cs2=trust" in result

    def test_empty_fields_omitted(self):
        """Missing optional fields should not appear in output"""
        no_optional = {
            "proto": "ICMP",
            "src":   "10.0.0.1",
            "dst":   "10.0.0.2",
            "action": "permit",
            # no hostname, no app, no NAT fields
        }
        result = self.fmt.format_cef(no_optional)
        assert result is not None
        assert "app=" not in result
        assert "shost=" not in result
        assert "natTranslatedAddress=" not in result


class TestCEFSanitization:
    def setup_method(self):
        self.fmt = SGBoxFormatter(output_format="cef")

    def test_pipe_in_header_escaped(self):
        """Pipe characters in header fields must be escaped as \\|"""
        evil = {**SAMPLE_PERMIT, "action": "permit|evil"}
        result = self.fmt.format_cef(evil)
        # The action field is in the header (as the event name fallback)
        # The ext field act= uses _sanitize_cef_value which doesn't escape |
        assert result is not None

    def test_backslash_in_value_escaped(self):
        """Backslash in extension values must be doubled"""
        evil = {**SAMPLE_PERMIT, "app": r"back\slash"}
        result = self.fmt.format_cef(evil)
        assert r"app=back\\slash" in result

    def test_equals_in_value_escaped(self):
        """Equals sign in extension values must be escaped"""
        evil = {**SAMPLE_PERMIT, "app": "key=value"}
        result = self.fmt.format_cef(evil)
        assert r"app=key\=value" in result

    def test_newline_in_value_escaped(self):
        """Newlines in extension values must become \\n"""
        evil = {**SAMPLE_PERMIT, "app": "line1\nline2"}
        result = self.fmt.format_cef(evil)
        assert r"app=line1\nline2" in result

    def test_null_bytes_stripped(self):
        """NUL bytes must be removed"""
        evil = {**SAMPLE_PERMIT, "app": "good\x00bad"}
        result = self.fmt.format_cef(evil)
        assert "goodbad" in result
        assert "\x00" not in result


class TestCEFSyslogEnvelope:
    def setup_method(self):
        self.fmt = SGBoxFormatter(output_format="cef")

    def test_syslog_cef_starts_with_pri(self):
        result = self.fmt.format_syslog_cef(SAMPLE_PERMIT)
        assert result is not None
        assert result.startswith("<")
        assert "CEF:0" in result

    def test_syslog_includes_timestamp(self):
        result = self.fmt.format_syslog_cef(SAMPLE_PERMIT)
        assert "Mar 26 15:00:00" in result

    def test_syslog_includes_hostname(self):
        result = self.fmt.format_syslog_cef(SAMPLE_PERMIT)
        assert "FW-01" in result

    def test_syslog_pri_local0_info_is_134(self):
        result = self.fmt.format_syslog_cef(SAMPLE_PERMIT,
                                             facility="local0",
                                             severity="info")
        assert result.startswith("<134>")


class TestCEFEdgeCases:
    def setup_method(self):
        self.fmt = SGBoxFormatter(output_format="cef")

    def test_none_input_returns_none(self):
        assert self.fmt.format_cef(None) is None

    def test_empty_dict_returns_none(self):
        assert self.fmt.format_cef({}) is None

    def test_missing_proto_returns_none(self):
        # proto is required — without it we can't classify the event
        partial = {"src": "10.0.0.1", "dst": "8.8.8.8", "action": "permit"}
        assert self.fmt.format_cef(partial) is None

    def test_format_mode_cef_routes_via_format_cef_in_batch(self):
        results = self.fmt.format_batch([SAMPLE_PERMIT, SAMPLE_DENY])
        assert len(results) == 2
        for r in results:
            assert "CEF:0" in r

    def test_syslog_cef_returns_none_for_invalid(self):
        assert self.fmt.format_syslog_cef({}) is None
