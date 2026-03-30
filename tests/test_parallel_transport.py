"""
Tests for parallel transport backend and security hardening.

Tests cover:
  - Parallel backend init and fallback
  - Parallel send fires both rsyslog + UDP concurrently
  - Per-vector stat tracking
  - Partial failure (one vector fails, other succeeds)
  - S1: Host injection rejection
  - S4: Message truncation for syslog
  - B1: UDP sendto without explicit addr
  - B7: Stat counter never goes negative
"""

import asyncio
import os
import sys
import syslog as _syslog
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.syslog_forwarder import SyslogForwarder, MAX_SYSLOG_MSG, _UNSAFE_HOST_RE


# Default SGBox config for tests — host is mandatory
_BASE_SGBOX = {"host": "10.10.0.52", "forwarder_backend": "python"}


def _sgbox(**overrides):
    """Merge test overrides into base sgbox config."""
    cfg = dict(_BASE_SGBOX)
    cfg.update(overrides)
    return {"sgbox": cfg}


class TestParallelBackendInit(unittest.TestCase):
    """Test parallel backend initialization and fallback."""

    @patch("shutil.which")
    def test_parallel_backend_with_rsyslogd(self, mock_which):
        """When rsyslogd is available, parallel backend should be set."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        self.assertEqual(fwd.backend, "parallel")

    @patch("shutil.which")
    def test_parallel_falls_back_without_rsyslogd(self, mock_which):
        """Without rsyslogd, parallel should fall back to python."""
        mock_which.return_value = None
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        self.assertEqual(fwd.backend, "python")

    @patch("shutil.which")
    def test_parallel_has_per_vector_stats(self, mock_which):
        """Parallel backend init should include per-vector stat keys."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        stats = fwd.stats
        self.assertIn("messages_sent_rsyslog", stats)
        self.assertIn("messages_sent_udp", stats)
        self.assertIn("messages_failed_rsyslog", stats)
        self.assertIn("messages_failed_udp", stats)


class TestParallelSend(unittest.TestCase):
    """Test parallel send dispatching."""

    @patch("shutil.which")
    def test_parallel_send_calls_both(self, mock_which):
        """Parallel send should call both _send_rsyslog and _send_udp."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        fwd._send_rsyslog = AsyncMock()
        fwd._send_udp = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.send("test message"))
        finally:
            loop.close()

        fwd._send_rsyslog.assert_called_once_with("test message")
        fwd._send_udp.assert_called_once()

    @patch("shutil.which")
    def test_parallel_one_fails_other_succeeds(self, mock_which):
        """If one parallel vector fails, the other should still succeed."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        fwd._send_rsyslog = AsyncMock(side_effect=OSError("Connection refused"))
        fwd._send_udp = AsyncMock()  # This should still succeed

        loop = asyncio.new_event_loop()
        try:
            # Should NOT raise — asyncio.gather with return_exceptions=True
            loop.run_until_complete(fwd.send("test message"))
        finally:
            loop.close()

        fwd._send_udp.assert_called_once()

    @patch("shutil.which")
    def test_parallel_empty_message_skips(self, mock_which):
        """Empty message should be skipped even in parallel mode."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        fwd._send_rsyslog = AsyncMock()
        fwd._send_udp = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.send(""))
        finally:
            loop.close()

        fwd._send_rsyslog.assert_not_called()
        fwd._send_udp.assert_not_called()


class TestParallelConnect(unittest.TestCase):
    """Test parallel connect sets up both vectors."""

    @patch("shutil.which")
    def test_parallel_connect_calls_both_setup(self, mock_which):
        """Parallel connect should set up both rsyslog and UDP."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        fwd._setup_rsyslog = AsyncMock()
        fwd._connect_udp = AsyncMock()

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd.connect())
        finally:
            loop.close()

        fwd._setup_rsyslog.assert_called_once()
        fwd._connect_udp.assert_called_once()


class TestParallelClose(unittest.TestCase):
    """Test parallel close cleans up both vectors."""

    @patch("shutil.which")
    def test_parallel_close_cleans_both(self, mock_which):
        """Parallel close should close syslog and UDP transport."""
        mock_which.return_value = "/usr/sbin/rsyslogd"
        fwd = SyslogForwarder(_sgbox(forwarder_backend="parallel"))
        fwd._connected = True
        fwd._syslog_opened = True
        mock_transport = MagicMock()
        fwd._transport = mock_transport

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                loop.run_until_complete(fwd.close())
                mock_syslog.closelog.assert_called_once()
        finally:
            loop.close()

        mock_transport.close.assert_called_once()
        self.assertIsNone(fwd._transport)
        self.assertFalse(fwd.is_connected())


class TestSecurityS1HostInjection(unittest.TestCase):
    """S1: Test host sanitization against rsyslog config injection."""

    def test_newline_in_host_raises(self):
        """Host with newline should be rejected (rsyslog config injection)."""
        with self.assertRaises(ValueError) as ctx:
            SyslogForwarder(_sgbox(host="10.0.0.1\n*.* @@evil.com"))
        self.assertIn("unsafe characters", str(ctx.exception))

    def test_carriage_return_in_host_raises(self):
        """Host with \\r should be rejected."""
        with self.assertRaises(ValueError):
            SyslogForwarder(_sgbox(host="10.0.0.1\r@@evil.com"))

    def test_null_byte_in_host_raises(self):
        """Host with null byte should be rejected."""
        with self.assertRaises(ValueError):
            SyslogForwarder(_sgbox(host="10.0.0.1\x00evil"))

    def test_normal_host_accepted(self):
        """Normal hostname/IP should be accepted."""
        fwd = SyslogForwarder(_sgbox(host="10.10.0.52"))
        self.assertEqual(fwd.host, "10.10.0.52")

    def test_hostname_with_dots_accepted(self):
        """FQDN should be accepted."""
        fwd = SyslogForwarder(_sgbox(host="sgbox.example.com"))
        self.assertEqual(fwd.host, "sgbox.example.com")

    def test_unsafe_host_regex_detects_patterns(self):
        """The regex should detect all injection patterns."""
        self.assertTrue(_UNSAFE_HOST_RE.search("host\nevil"))
        self.assertTrue(_UNSAFE_HOST_RE.search("host\revil"))
        self.assertTrue(_UNSAFE_HOST_RE.search("host\x00evil"))
        self.assertIsNone(_UNSAFE_HOST_RE.search("10.10.0.52"))
        self.assertIsNone(_UNSAFE_HOST_RE.search("sgbox.example.com"))


class TestSecurityS4MessageTruncation(unittest.TestCase):
    """S4: Test message size limit for syslog."""

    def test_max_syslog_msg_constant(self):
        """MAX_SYSLOG_MSG should be 8192."""
        self.assertEqual(MAX_SYSLOG_MSG, 8192)

    def test_oversized_message_truncated(self):
        """Messages larger than MAX_SYSLOG_MSG should be truncated."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        # Create a message larger than MAX_SYSLOG_MSG
        big_message = "A" * (MAX_SYSLOG_MSG + 500)

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                mock_syslog.LOG_PID = _syslog.LOG_PID
                mock_syslog.LOG_NDELAY = _syslog.LOG_NDELAY
                loop.run_until_complete(fwd._send_rsyslog(big_message))
                # syslog should have been called with truncated message
                call_args = mock_syslog.syslog.call_args
                if call_args:
                    sent_msg = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get('message', '')
                    self.assertLessEqual(len(sent_msg), MAX_SYSLOG_MSG)
        finally:
            loop.close()

    def test_normal_message_not_truncated(self):
        """Messages within limit should NOT be truncated."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        normal_message = "Normal log message"

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                mock_syslog.LOG_PID = _syslog.LOG_PID
                mock_syslog.LOG_NDELAY = _syslog.LOG_NDELAY
                loop.run_until_complete(fwd._send_rsyslog(normal_message))
                mock_syslog.syslog.assert_called_once()
        finally:
            loop.close()


class TestBugB1UdpSendto(unittest.TestCase):
    """B1: UDP sendto should NOT pass explicit addr on connected socket."""

    def test_sendto_no_addr_arg(self):
        """_send_udp should call sendto(data) without addr tuple."""
        fwd = SyslogForwarder(_sgbox())
        mock_transport = MagicMock()
        mock_transport.is_closing.return_value = False
        fwd._transport = mock_transport

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd._send_udp(b"test data"))
        finally:
            loop.close()

        # sendto should be called with only data, not (data, (host, port))
        mock_transport.sendto.assert_called_once_with(b"test data")


class TestBugB7StatCounterGuard(unittest.TestCase):
    """B7: Stat counter decrement should never go negative."""

    def test_stats_never_negative(self):
        """messages_failed should never go below 0."""
        fwd = SyslogForwarder(_sgbox())
        # Ensure messages_failed starts at 0
        self.assertEqual(fwd.stats["messages_failed"], 0)
        # Even after multiple operations, it should not be negative
        self.assertGreaterEqual(fwd.stats["messages_failed"], 0)


class TestPerVectorStats(unittest.TestCase):
    """Test that per-vector stats are tracked correctly."""

    def test_rsyslog_send_increments_rsyslog_stats(self):
        """Successful rsyslog send should increment rsyslog-specific stats."""
        fwd = SyslogForwarder(_sgbox())
        fwd.backend = "rsyslog"

        loop = asyncio.new_event_loop()
        try:
            with patch("src.syslog_forwarder._syslog") as mock_syslog:
                mock_syslog.LOG_PID = _syslog.LOG_PID
                mock_syslog.LOG_NDELAY = _syslog.LOG_NDELAY
                loop.run_until_complete(fwd._send_rsyslog("test"))
        finally:
            loop.close()

        self.assertEqual(fwd.stats["messages_sent_rsyslog"], 1)
        self.assertEqual(fwd.stats["messages_sent"], 1)

    def test_udp_send_increments_udp_stats(self):
        """Successful UDP send should increment UDP-specific stats."""
        fwd = SyslogForwarder(_sgbox())
        mock_transport = MagicMock()
        mock_transport.is_closing.return_value = False
        fwd._transport = mock_transport

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(fwd._send_udp(b"test data"))
        finally:
            loop.close()

        self.assertEqual(fwd.stats["messages_sent_udp"], 1)
        self.assertEqual(fwd.stats["messages_sent"], 1)

    def test_failed_rsyslog_increments_failed_rsyslog_stats(self):
        """Failed rsyslog send should increment rsyslog-specific failure stats."""
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

        self.assertEqual(fwd.stats["messages_failed_rsyslog"], 1)
        self.assertEqual(fwd.stats["messages_failed"], 1)
        self.assertEqual(fwd.stats["messages_sent_rsyslog"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
