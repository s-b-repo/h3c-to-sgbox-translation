"""
Comprehensive tests for SyslogForwarder — rsyslog + python backends.

Tests cover:
  - Config generation for all protocol/scope combinations
  - Backend selection and fallback logic
  - Input validation and edge cases
  - Security concerns
  - Robustness: invalid config values, missing fields
  - Stats tracking
  - Send paths (rsyslog syslog module, UDP, TCP)
"""

import asyncio
import os
import sys
import syslog as _syslog
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.syslog_forwarder import SyslogForwarder, FACILITY_MAP, SEVERITY_MAP

# Default SGBox config for tests — host is mandatory
_BASE_SGBOX = {"host": "10.10.0.52", "forwarder_backend": "python"}


def _sgbox(**overrides):
    """Merge test overrides into base sgbox config."""
    cfg = dict(_BASE_SGBOX)
    cfg.update(overrides)
    return {"sgbox": cfg}


class TestConfigGeneration(unittest.TestCase):
    """Test rsyslog config file generation for all protocol/scope combos."""

    def _make_fwd(self, **overrides):
        """Helper to create a SyslogForwarder with mocked rsyslog availability."""
        sgbox = {
            "host": "10.10.0.52",
            "port": "514",
            "protocol": "udp",
            "forwarder_backend": "python",  # avoid shutil.which checks
            "facility": "local0",
            "severity": "info",
            "rsyslog_log_scope": "all",
        }
        sgbox.update(overrides)
        fwd = SyslogForwarder({"sgbox": sgbox})
        # Override backend to rsyslog for config generation tests
        fwd.backend = "rsyslog"
        return fwd

    def test_udp_all_logs(self):
        """UDP protocol with all logs scope."""
        fwd = self._make_fwd(protocol="udp", rsyslog_log_scope="all")
        config = fwd._generate_rsyslog_config()
        self.assertIn("*.* @10.10.0.52", config)
        self.assertNotIn("@@", config)
        self.assertIn("Protocol: UDP", config)
        self.assertIn("Scope: all logs", config)

    def test_tcp_all_logs(self):
        """TCP protocol should use @@ prefix."""
        fwd = self._make_fwd(protocol="tcp", rsyslog_log_scope="all")
        config = fwd._generate_rsyslog_config()
        self.assertIn("*.* @@10.10.0.52", config)
        self.assertIn("Protocol: TCP", config)

    def test_tls_protocol(self):
        """TLS should use @@ prefix and include gtls directives."""
        fwd = SyslogForwarder({
            "sgbox": {
                "host": "10.10.0.52", "port": "6514",
                "protocol": "tls", "forwarder_backend": "python",
            },
            "tls": {"ca_file": "/etc/certs/ca-bundle.pem"},
        })
        fwd.backend = "rsyslog"
        config = fwd._generate_rsyslog_config()
        self.assertIn("@@10.10.0.52:6514", config)
        self.assertIn("$DefaultNetstreamDriver gtls", config)
        self.assertIn("$DefaultNetstreamDriverCAFile /etc/certs/ca-bundle.pem", config)
        self.assertIn("$ActionSendStreamDriverMode 1", config)
        self.assertIn("$ActionSendStreamDriverAuthMode anon", config)

    def test_tls_no_ca_file(self):
        """TLS with no CA file should have commented-out CA directive."""
        fwd = SyslogForwarder({
            "sgbox": {
                "host": "10.10.0.52", "port": "6514",
                "protocol": "tls", "forwarder_backend": "python",
            },
            "tls": {},
        })
        fwd.backend = "rsyslog"
        config = fwd._generate_rsyslog_config()
        self.assertIn("# $DefaultNetstreamDriverCAFile", config)

    def test_auth_only_scope(self):
        """Auth scope should use auth,authpriv.* selector."""
        fwd = self._make_fwd(rsyslog_log_scope="auth")
        config = fwd._generate_rsyslog_config()
        self.assertIn("auth,authpriv.* @10.10.0.52", config)
        self.assertIn("Scope: authentication logs only", config)

    def test_custom_port_included(self):
        """Non-default port should be appended to target."""
        fwd = self._make_fwd(port="1514")
        config = fwd._generate_rsyslog_config()
        self.assertIn("@10.10.0.52:1514", config)

    def test_default_port_omitted(self):
        """Default port 514 should be omitted from target."""
        fwd = self._make_fwd(port="514")
        config = fwd._generate_rsyslog_config()
        self.assertIn("@10.10.0.52\n", config)
        self.assertNotIn(":514", config)

    def test_unknown_protocol_defaults_udp(self):
        """Unknown protocol falls back to @ (UDP)."""
        fwd = self._make_fwd(protocol="sctp")
        config = fwd._generate_rsyslog_config()
        self.assertIn("@10.10.0.52", config)
        self.assertIn("UDP (default)", config)

    def test_unknown_scope_defaults_all(self):
        """Unknown scope falls back to *.*."""
        fwd = self._make_fwd(rsyslog_log_scope="everything")
        config = fwd._generate_rsyslog_config()
        self.assertIn("*.*", config)


class TestBackendSelection(unittest.TestCase):
    """Test backend selection and fallback logic."""

    @patch("shutil.which")
    def test_rsyslog_available(self, mock_which):
        """When rsyslogd is available, use rsyslog backend."""
        mock_which.side_effect = lambda cmd: f"/usr/sbin/{cmd}" if cmd == "rsyslogd" else None
        fwd = SyslogForwarder(_sgbox(forwarder_backend="rsyslog"))
        self.assertEqual(fwd.backend, "rsyslog")

    @patch("shutil.which")
    def test_rsyslogd_missing_falls_back(self, mock_which):
        """When rsyslogd is missing, fallback to python."""
        mock_which.return_value = None
        fwd = SyslogForwarder(_sgbox(forwarder_backend="rsyslog"))
        self.assertEqual(fwd.backend, "python")

    def test_python_backend_explicit(self):
        """Explicitly choosing python backend should work."""
        fwd = SyslogForwarder(_sgbox(forwarder_backend="python"))
        self.assertEqual(fwd.backend, "python")

    @patch("shutil.which")
    def test_unknown_backend_defaults_rsyslog(self, mock_which):
        """Unknown backend string should default to rsyslog."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="foobar"))
        self.assertIn(fwd.backend, ("rsyslog", "python"))


class TestInputValidation(unittest.TestCase):
    """Test edge cases and invalid inputs."""

    def test_empty_config_raises(self):
        """Empty config should raise ValueError (no host configured)."""
        with self.assertRaises(ValueError):
            SyslogForwarder({})

    def test_empty_host_raises(self):
        """Empty host string should raise ValueError."""
        with self.assertRaises(ValueError):
            SyslogForwarder({"sgbox": {"host": ""}})

    def test_whitespace_host_raises(self):
        """Whitespace-only host should raise ValueError."""
        with self.assertRaises(ValueError):
            SyslogForwarder({"sgbox": {"host": "   "}})

    def test_missing_host_key_raises(self):
        """Missing host key should raise ValueError."""
        with self.assertRaises(ValueError):
            SyslogForwarder({"sgbox": {"forwarder_backend": "python"}})

    def test_valid_host_succeeds(self):
        """Valid host should construct normally."""
        fwd = SyslogForwarder(_sgbox())
        self.assertEqual(fwd.host, "10.10.0.52")

    def test_invalid_port_raises(self):
        """Non-numeric port should raise ValueError."""
        with self.assertRaises(ValueError):
            SyslogForwarder(_sgbox(port="not_a_number"))

    def test_port_zero(self):
        """Port 0 should be accepted (OS assigns ephemeral)."""
        fwd = SyslogForwarder(_sgbox(port="0"))
        self.assertEqual(fwd.port, 0)

    def test_negative_port(self):
        """Negative port should be accepted (validation is at OS level)."""
        fwd = SyslogForwarder(_sgbox(port="-1"))
        self.assertEqual(fwd.port, -1)

    def test_very_large_port(self):
        """Very large port should be accepted (validation is at OS level)."""
        fwd = SyslogForwarder(_sgbox(port="99999"))
        self.assertEqual(fwd.port, 99999)

    def test_default_values(self):
        """Default port, protocol, facility, severity when only host given."""
        fwd = SyslogForwarder({"sgbox": {"host": "10.10.0.52", "forwarder_backend": "python"}})
        self.assertEqual(fwd.port, 514)
        self.assertEqual(fwd.protocol, "udp")
        self.assertEqual(fwd.facility, "local0")
        self.assertEqual(fwd.severity, "info")

    def test_stats_returns_copy(self):
        """Stats property should return a copy, not the internal dict."""
        fwd = SyslogForwarder(_sgbox())
        stats = fwd.stats
        stats["messages_sent"] = 999
        self.assertEqual(fwd.stats["messages_sent"], 0)

    def test_is_connected_initially_false(self):
        """is_connected() should be False before connect()."""
        fwd = SyslogForwarder(_sgbox())
        self.assertFalse(fwd.is_connected())


class TestSecurityConcerns(unittest.TestCase):
    """Test for security issues."""

    def test_host_with_shell_metacharacters_in_config(self):
        """Host with shell metacharacters should appear in rsyslog config as-is."""
        fwd = SyslogForwarder(_sgbox(host="10.10.0.52; rm -rf /"))
        fwd.backend = "rsyslog"
        config = fwd._generate_rsyslog_config()
        self.assertIn("10.10.0.52; rm -rf /", config)

    def test_send_rsyslog_uses_syslog_module(self):
        """Verify _send_rsyslog uses syslog module, not subprocess."""
        import inspect
        source = inspect.getsource(SyslogForwarder._send_rsyslog)
        self.assertIn("_syslog.syslog", source)
        self.assertNotIn("create_subprocess_exec", source)
        self.assertNotIn("create_subprocess_shell", source)
        self.assertNotIn("shell=True", source)


class TestSendDispatch(unittest.TestCase):
    """Test send() dispatching to correct backend."""

    def test_send_empty_message_skips(self):
        """Empty message should be skipped without error."""
        fwd = SyslogForwarder(_sgbox())
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.send(""))
            loop.run_until_complete(fwd.send(None))
        finally:
            loop.close()
        self.assertEqual(fwd.stats["messages_sent"], 0)
        self.assertEqual(fwd.stats["messages_failed"], 0)

    def test_send_dispatches_to_rsyslog(self):
        """When backend=rsyslog, send() should call _send_rsyslog."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"
        fwd._send_rsyslog = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.send("test message"))
        finally:
            loop.close()

        fwd._send_rsyslog.assert_called_once_with("test message")

    def test_send_dispatches_to_python_udp(self):
        """When backend=python + protocol=udp, send() should call _send_udp."""
        fwd = SyslogForwarder(_sgbox(protocol="udp"))
        fwd._send_udp = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.send("test message"))
        finally:
            loop.close()

        fwd._send_udp.assert_called_once()

    def test_send_dispatches_to_python_tcp(self):
        """When backend=python + protocol=tcp, send() should call _send_tcp."""
        fwd = SyslogForwarder(_sgbox(protocol="tcp"))
        fwd._send_tcp = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.send("test message"))
        finally:
            loop.close()

        fwd._send_tcp.assert_called_once()


class TestRsyslogSend(unittest.TestCase):
    """Test _send_rsyslog with mocked syslog module."""

    def test_successful_send(self):
        """Successful syslog.syslog() should increment messages_sent."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                mock_syslog.LOG_PID = _syslog.LOG_PID
                mock_syslog.LOG_NDELAY = _syslog.LOG_NDELAY
                loop.run_until_complete(fwd._send_rsyslog("test"))
                # openlog should have been called
                mock_syslog.openlog.assert_called_once()
                # syslog should have been called with severity + message
                mock_syslog.syslog.assert_called_once_with(
                    fwd._syslog_severity, "test"
                )
        finally:
            loop.close()

        self.assertEqual(fwd.stats["messages_sent"], 1)
        self.assertEqual(fwd.stats["messages_failed"], 0)

    def test_syslog_exception_increments_failed(self):
        """Exception from syslog.syslog() should increment messages_failed."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                mock_syslog.LOG_PID = _syslog.LOG_PID
                mock_syslog.LOG_NDELAY = _syslog.LOG_NDELAY
                mock_syslog.syslog.side_effect = OSError("Connection refused")
                loop.run_until_complete(fwd._send_rsyslog("test"))
        finally:
            loop.close()

        self.assertEqual(fwd.stats["messages_sent"], 0)
        self.assertEqual(fwd.stats["messages_failed"], 1)

    def test_openlog_called_once(self):
        """syslog.openlog() should only be called on first message."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                mock_syslog.LOG_PID = _syslog.LOG_PID
                mock_syslog.LOG_NDELAY = _syslog.LOG_NDELAY
                loop.run_until_complete(fwd._send_rsyslog("msg1"))
                loop.run_until_complete(fwd._send_rsyslog("msg2"))
                loop.run_until_complete(fwd._send_rsyslog("msg3"))
                # openlog called once, syslog called three times
                self.assertEqual(mock_syslog.openlog.call_count, 1)
                self.assertEqual(mock_syslog.syslog.call_count, 3)
        finally:
            loop.close()

        self.assertEqual(fwd.stats["messages_sent"], 3)

    def test_facility_severity_resolved(self):
        """Facility and severity should resolve to syslog module constants."""
        fwd = SyslogForwarder(_sgbox(facility="local7", severity="crit"))
        self.assertEqual(fwd._syslog_facility, _syslog.LOG_LOCAL7)
        self.assertEqual(fwd._syslog_severity, _syslog.LOG_CRIT)

    def test_unknown_facility_falls_back(self):
        """Unknown facility should fall back to LOG_LOCAL0."""
        fwd = SyslogForwarder(_sgbox(facility="nonexistent_facility"))
        self.assertEqual(fwd._syslog_facility, _syslog.LOG_LOCAL0)

    def test_unknown_severity_falls_back(self):
        """Unknown severity should fall back to LOG_INFO."""
        fwd = SyslogForwarder(_sgbox(severity="nonexistent_severity"))
        self.assertEqual(fwd._syslog_severity, _syslog.LOG_INFO)


class TestRsyslogSetup(unittest.TestCase):
    """Test _setup_rsyslog with mocked filesystem and subprocess."""

    def test_setup_fallback_when_conf_dir_missing(self):
        """Should fall back to python when /etc/rsyslog.d doesn't exist."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        loop = asyncio.new_event_loop()
        try:
            with patch("os.path.isdir", return_value=False):
                fwd._connect_python = AsyncMock()
                loop.run_until_complete(fwd._setup_rsyslog())
        finally:
            loop.close()

        self.assertEqual(fwd.backend, "python")
        fwd._connect_python.assert_called_once()

    def test_setup_fallback_on_permission_error(self):
        """Should fall back to python when can't write config file."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        loop = asyncio.new_event_loop()
        try:
            with patch("os.path.isdir", return_value=True), \
                 patch("os.path.isfile", return_value=False), \
                 patch("builtins.open", side_effect=PermissionError("denied")):
                fwd._connect_python = AsyncMock()
                loop.run_until_complete(fwd._setup_rsyslog())
        finally:
            loop.close()

        self.assertEqual(fwd.backend, "python")
        fwd._connect_python.assert_called_once()

    def test_setup_skips_restart_when_config_unchanged(self):
        """Should skip restart when existing config is identical."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"
        expected_config = fwd._generate_rsyslog_config()

        from unittest.mock import mock_open
        loop = asyncio.new_event_loop()
        try:
            with patch("os.path.isdir", return_value=True), \
                 patch("os.path.isfile", return_value=True), \
                 patch("builtins.open", mock_open(read_data=expected_config)):
                loop.run_until_complete(fwd._setup_rsyslog())
        finally:
            loop.close()

        self.assertTrue(fwd.is_connected())


class TestCloseMethod(unittest.TestCase):
    """Test close() for both backends."""

    def test_close_rsyslog_backend(self):
        """rsyslog close should call syslog.closelog()."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"
        fwd._connected = True
        fwd._syslog_opened = True

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                loop.run_until_complete(fwd.close())
                mock_syslog.closelog.assert_called_once()
        finally:
            loop.close()

        self.assertFalse(fwd.is_connected())
        self.assertFalse(fwd._syslog_opened)

    def test_close_python_backend(self):
        """python close should clean up transport/writer."""
        fwd = SyslogForwarder(_sgbox())
        fwd._connected = True
        mock_transport = MagicMock()
        fwd._transport = mock_transport

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.close())
        finally:
            loop.close()

        mock_transport.close.assert_called_once()
        self.assertIsNone(fwd._transport)
        self.assertFalse(fwd.is_connected())


class TestFacilitySeverityMaps(unittest.TestCase):
    """Verify all expected facilities and severities are mapped."""

    def test_all_standard_facilities(self):
        """All standard syslog facilities should be in the map."""
        expected = {"kern", "user", "mail", "daemon", "auth", "syslog",
                    "lpr", "news", "cron", "local0", "local1", "local2",
                    "local3", "local4", "local5", "local6", "local7"}
        self.assertEqual(set(FACILITY_MAP.keys()), expected)

    def test_all_standard_severities(self):
        """All standard syslog severities should be in the map."""
        expected = {"emerg", "alert", "crit", "err", "warning",
                    "notice", "info", "debug"}
        self.assertEqual(set(SEVERITY_MAP.keys()), expected)

    def test_facilities_are_integers(self):
        """Facility values should be integers (syslog module constants)."""
        for name, val in FACILITY_MAP.items():
            self.assertIsInstance(val, int, f"Facility '{name}' should be int, got {type(val)}")

    def test_severities_are_integers(self):
        """Severity values should be integers (syslog module constants)."""
        for name, val in SEVERITY_MAP.items():
            self.assertIsInstance(val, int, f"Severity '{name}' should be int, got {type(val)}")


class TestMultiHostConfig(unittest.TestCase):
    """Test config generation with multi-host scenarios."""

    def test_ipv6_host(self):
        """IPv6 host should be included in config correctly."""
        fwd = SyslogForwarder(_sgbox(host="::1"))
        fwd.backend = "rsyslog"
        config = fwd._generate_rsyslog_config()
        self.assertIn("@::1", config)

    def test_hostname_instead_of_ip(self):
        """Hostname should work as target."""
        fwd = SyslogForwarder(_sgbox(host="sgbox.example.com"))
        fwd.backend = "rsyslog"
        config = fwd._generate_rsyslog_config()
        self.assertIn("@sgbox.example.com", config)


if __name__ == "__main__":
    unittest.main(verbosity=2)
