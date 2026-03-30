"""
Async Syslog Forwarder

Forwards translated log messages to the SGBox SIEM server via:
  - rsyslog backend (DEFAULT) — writes to local rsyslog, which handles delivery
  - python backend (LEGACY)  — direct UDP/TCP/TLS sockets from Python
  - parallel backend          — sends via BOTH rsyslog AND direct UDP concurrently

The rsyslog backend follows the SGBox Debian integration guide:
  1. Install rsyslog:  apt-get -y install rsyslog
  2. Generate /etc/rsyslog.d/h3c-sgbox.conf with forwarding rule
  3. Restart rsyslog daemon
  4. Send messages via Python syslog module

Dependencies: structlog, tenacity
"""

import asyncio
import functools
import os
import re
import shutil
import ssl
import syslog as _syslog

import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

logger = structlog.get_logger(__name__)

# rsyslog drop-in config path
RSYSLOG_CONF_DIR = "/etc/rsyslog.d"
RSYSLOG_CONF_FILE = os.path.join(RSYSLOG_CONF_DIR, "h3c-sgbox.conf")

# S4: Maximum syslog message size (bytes) — kernel /dev/log limit
MAX_SYSLOG_MSG = 8192

# S1: Regex to detect rsyslog config injection attempts in host values
_UNSAFE_HOST_RE = re.compile(r'[\n\r\x00]')

# Syslog facility codes (from syslog module)
FACILITY_MAP = {
    "kern": _syslog.LOG_KERN, "user": _syslog.LOG_USER,
    "mail": _syslog.LOG_MAIL, "daemon": _syslog.LOG_DAEMON,
    "auth": _syslog.LOG_AUTH, "syslog": _syslog.LOG_SYSLOG,
    "lpr": _syslog.LOG_LPR, "news": _syslog.LOG_NEWS,
    "cron": _syslog.LOG_CRON, "local0": _syslog.LOG_LOCAL0,
    "local1": _syslog.LOG_LOCAL1, "local2": _syslog.LOG_LOCAL2,
    "local3": _syslog.LOG_LOCAL3, "local4": _syslog.LOG_LOCAL4,
    "local5": _syslog.LOG_LOCAL5, "local6": _syslog.LOG_LOCAL6,
    "local7": _syslog.LOG_LOCAL7,
}

# Syslog severity codes (from syslog module)
SEVERITY_MAP = {
    "emerg": _syslog.LOG_EMERG, "alert": _syslog.LOG_ALERT,
    "crit": _syslog.LOG_CRIT, "err": _syslog.LOG_ERR,
    "warning": _syslog.LOG_WARNING, "notice": _syslog.LOG_NOTICE,
    "info": _syslog.LOG_INFO, "debug": _syslog.LOG_DEBUG,
}


class SyslogForwarder:
    """
    Async syslog forwarder to SGBox.

    Supports three backends:
        - rsyslog (default): Configures system rsyslog to forward to SGBox,
          sends messages via Python syslog module. Recommended for Debian/SGBox.
        - python (legacy): Direct async UDP/TCP/TLS sockets with tenacity retry.
        - parallel: Sends via BOTH rsyslog AND direct UDP concurrently for
          maximum delivery reliability.

    Features:
        - Automatic rsyslog configuration generation and deployment
        - Fallback to direct Python sockets when rsyslog is unavailable
        - Parallel multi-vector delivery (UDP + rsyslog)
        - Message queueing and retry (python backend)
        - Connection health monitoring
    """

    def __init__(self, config: dict):
        sgbox = config.get("sgbox", {})
        self.host = sgbox.get("host", "").strip()
        if not self.host:
            print(f"[FORWARDER] ✗ FATAL: No SGBox host configured in [sgbox] section")
            print(f"[FORWARDER]   Set 'host = <SGBox-IP>' in translator.config")
            raise ValueError("SGBox host not configured — set 'host' in [sgbox] config section")

        # S1: Reject host values containing newlines/control chars (rsyslog config injection)
        if _UNSAFE_HOST_RE.search(self.host):
            print(f"[FORWARDER] ✗ FATAL: Host contains unsafe characters (newline/control)")
            print(f"[FORWARDER]   This could inject arbitrary rsyslog directives.")
            raise ValueError(
                "SGBox host contains unsafe characters (newline/null) — "
                "possible rsyslog config injection attempt"
            )

        self.port = int(sgbox.get("port", 514))
        self.protocol = sgbox.get("protocol", "udp").lower()
        self.facility = sgbox.get("facility", "local0")
        self.severity = sgbox.get("severity", "info")
        self.backend = sgbox.get("forwarder_backend", "rsyslog").lower()
        self.rsyslog_log_scope = sgbox.get("rsyslog_log_scope", "all").lower()

        # NOTE: SGBox syslog ingestion does NOT use API keys.
        # API keys are only for SGBox REST API integrations.
        _legacy_key = sgbox.get("sgbox_api_key", "").strip()
        if _legacy_key and _legacy_key not in ("", "CHANGE_ME_SET_YOUR_SGBOX_API_KEY"):
            print(f"[FORWARDER] ⚠ WARNING: sgbox_api_key is configured but NOT used")
            print(f"[FORWARDER]   SGBox syslog (UDP/TCP/TLS) does not require API keys.")
            print(f"[FORWARDER]   The API key config option has been removed.")

        self._tls_config = config.get("tls", {})
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._connected = False
        self._lock = asyncio.Lock()

        self._stats = {
            "messages_sent": 0,
            "messages_failed": 0,
            "reconnections": 0,
            "messages_sent_rsyslog": 0,
            "messages_sent_udp": 0,
            "messages_failed_rsyslog": 0,
            "messages_failed_udp": 0,
        }
        # MED-04: Lock for thread-safe stats updates
        self._stats_lock = asyncio.Lock()

        # Resolve syslog facility/severity to numeric codes for syslog module
        self._syslog_facility = FACILITY_MAP.get(self.facility, _syslog.LOG_LOCAL0)
        self._syslog_severity = SEVERITY_MAP.get(self.severity, _syslog.LOG_INFO)
        self._syslog_opened = False

        # Validate backend choice
        match self.backend:
            case "rsyslog":
                # Check if rsyslog is available on this system
                if not shutil.which("rsyslogd"):
                    print(f"[FORWARDER] ⚠ rsyslogd not found on PATH — falling back to python backend")
                    print(f"[FORWARDER]   Install rsyslog: apt-get -y install rsyslog")
                    self.backend = "python"
            case "parallel":
                # Parallel mode: rsyslog + direct UDP simultaneously
                if not shutil.which("rsyslogd"):
                    print(f"[FORWARDER] ⚠ rsyslogd not found for parallel mode — falling back to python")
                    self.backend = "python"
                else:
                    print(f"[FORWARDER] ✓ Parallel mode: rsyslog + direct UDP")
            case "python":
                pass  # Legacy mode, no extra checks
            case _:
                print(f"[FORWARDER] ⚠ Unknown backend '{self.backend}', defaulting to rsyslog")
                self.backend = "rsyslog"

        print(f"[FORWARDER] Initialized")
        print(f"[FORWARDER]   Backend:      {self.backend.upper()}")
        print(f"[FORWARDER]   Protocol:     {self.protocol.upper()}")
        print(f"[FORWARDER]   Target:       {self.host}:{self.port}")
        print(f"[FORWARDER]   Facility:     {self.facility}")
        print(f"[FORWARDER]   Severity:     {self.severity}")
        if self.backend in ("rsyslog", "parallel"):
            print(f"[FORWARDER]   Log scope:    {self.rsyslog_log_scope}")

    @property
    def stats(self) -> dict[str, int]:
        # LOW-05: Return a copy (lock is asyncio.Lock, can't await in property)
        return self._stats.copy()

    # ══════════════════════════════════════════════════════════════════
    #  Connect / Setup
    # ══════════════════════════════════════════════════════════════════

    async def connect(self):
        """Establish connection or configure rsyslog for SGBox forwarding."""
        print(f"\n[FORWARDER] Setting up forwarding to SGBox at {self.host}:{self.port}...")
        match self.backend:
            case "rsyslog":
                await self._setup_rsyslog()
            case "parallel":
                # Set up BOTH rsyslog and direct UDP simultaneously
                print(f"[FORWARDER] Parallel mode: setting up rsyslog + direct UDP...")
                await self._setup_rsyslog()
                await self._connect_udp()
                print(f"[FORWARDER] ✓ Parallel vectors ready (rsyslog + UDP)")
            case "python":
                await self._connect_python()

    # ── rsyslog backend ────────────────────────────────────────────────

    def _generate_rsyslog_config(self) -> str:
        """
        Generate rsyslog forwarding config content for SGBox.

        Following the SGBox Debian integration guide:
          - @ prefix  = UDP forwarding
          - @@ prefix = TCP forwarding
        """
        # Determine forwarding prefix based on protocol
        match self.protocol:
            case "udp":
                prefix = "@"
                proto_comment = "UDP"
            case "tcp":
                prefix = "@@"
                proto_comment = "TCP"
            case "tls":
                prefix = "@@"
                proto_comment = "TCP/TLS"
            case _:
                prefix = "@"
                proto_comment = "UDP (default)"

        # Determine log scope
        match self.rsyslog_log_scope:
            case "auth":
                selector = "auth,authpriv.*"
                scope_comment = "authentication logs only"
            case _:
                selector = "*.*"
                scope_comment = "all logs"

        # Build target with optional port (omit if default 514)
        if self.port != 514:
            target = f"{prefix}{self.host}:{self.port}"
        else:
            target = f"{prefix}{self.host}"

        lines = [
            "# ──────────────────────────────────────────────────────────────",
            "# H3C-to-SGBox Translator — rsyslog forwarding config",
            "# Auto-generated by h3c-sgbox-translator",
            f"# Protocol: {proto_comment} | Scope: {scope_comment}",
            "# ──────────────────────────────────────────────────────────────",
            "",
        ]

        # Add TLS configuration if protocol is TLS
        if self.protocol == "tls":
            ca_file = self._tls_config.get("ca_file", "")
            lines.extend([
                "# TLS configuration for encrypted syslog forwarding",
                '$DefaultNetstreamDriver gtls',
                f'$DefaultNetstreamDriverCAFile {ca_file}' if ca_file else '# $DefaultNetstreamDriverCAFile /path/to/ca.pem',
                '$ActionSendStreamDriver gtls',
                '$ActionSendStreamDriverMode 1',
                '$ActionSendStreamDriverAuthMode anon',
                "",
            ])

        lines.append(f"{selector} {target}")
        lines.append("")

        return "\n".join(lines)

    async def _setup_rsyslog(self):
        """
        Install rsyslog forwarding config and restart the daemon.

        Creates /etc/rsyslog.d/h3c-sgbox.conf with the appropriate
        forwarding rule pointing at the SGBox SIEM server.
        """
        print(f"[FORWARDER] Configuring rsyslog for SGBox forwarding...")

        config_content = self._generate_rsyslog_config()
        print(f"[FORWARDER] Generated rsyslog config:")
        for line in config_content.strip().split("\n"):
            print(f"[FORWARDER]   {line}")

        # Check if config directory exists
        if not os.path.isdir(RSYSLOG_CONF_DIR):
            print(f"[FORWARDER] ✗ rsyslog config dir not found: {RSYSLOG_CONF_DIR}")
            print(f"[FORWARDER]   Falling back to python backend for this session")
            self.backend = "python"
            await self._connect_python()
            return

        # Write the config file
        try:
            # Check if existing config is identical (skip restart if unchanged)
            if os.path.isfile(RSYSLOG_CONF_FILE):
                with open(RSYSLOG_CONF_FILE, "r") as f:
                    existing = f.read()
                if existing.strip() == config_content.strip():
                    print(f"[FORWARDER] ✓ rsyslog config unchanged, skipping restart")
                    self._connected = True
                    return

            with open(RSYSLOG_CONF_FILE, "w") as f:
                f.write(config_content)
            print(f"[FORWARDER] ✓ Config written to {RSYSLOG_CONF_FILE}")
        except PermissionError:
            print(f"[FORWARDER] ✗ Permission denied writing {RSYSLOG_CONF_FILE}")
            print(f"[FORWARDER]   Run as root or use: sudo python3 -m src.translator ...")
            print(f"[FORWARDER]   Falling back to python backend for this session")
            self.backend = "python"
            await self._connect_python()
            return
        except OSError as e:
            print(f"[FORWARDER] ✗ Failed to write rsyslog config: {e}")
            self.backend = "python"
            await self._connect_python()
            return

        # Restart rsyslog to load the new config
        print(f"[FORWARDER] Restarting rsyslog daemon...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "restart", "rsyslog",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            match proc.returncode:
                case 0:
                    print(f"[FORWARDER] ✓ rsyslog restarted successfully")
                    self._connected = True
                    logger.info("forwarder.rsyslog_configured",
                                host=self.host, port=self.port,
                                protocol=self.protocol,
                                config_file=RSYSLOG_CONF_FILE)
                case _:
                    err_msg = stderr.decode().strip() if stderr else "unknown error"
                    print(f"[FORWARDER] ✗ rsyslog restart FAILED (exit {proc.returncode}): {err_msg}")
                    # Try service command as fallback (non-systemd systems)
                    await self._restart_rsyslog_service()
        except asyncio.TimeoutError:
            print(f"[FORWARDER] ✗ rsyslog restart TIMED OUT (15s)")
            await self._restart_rsyslog_service()
        except FileNotFoundError:
            print(f"[FORWARDER] systemctl not found, trying 'service' command...")
            await self._restart_rsyslog_service()

    async def _restart_rsyslog_service(self):
        """Fallback: restart rsyslog via 'service' command (non-systemd)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "service", "rsyslog", "restart",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            match proc.returncode:
                case 0:
                    print(f"[FORWARDER] ✓ rsyslog restarted via 'service' command")
                    self._connected = True
                case _:
                    err_msg = stderr.decode().strip() if stderr else "unknown error"
                    print(f"[FORWARDER] ✗ 'service rsyslog restart' FAILED: {err_msg}")
                    print(f"[FORWARDER]   rsyslog config was written but daemon not restarted")
                    print(f"[FORWARDER]   Manually run: service rsyslog restart")
                    # Config is written, mark as connected — it will work after manual restart
                    self._connected = True
        except Exception as e:
            print(f"[FORWARDER] ✗ Service restart failed: {e}")
            print(f"[FORWARDER]   Config written to {RSYSLOG_CONF_FILE}")
            print(f"[FORWARDER]   Manually run: service rsyslog restart")
            self._connected = True

    # ── python backend (legacy) ────────────────────────────────────────

    async def _connect_python(self):
        """Establish async connection to SGBox (legacy python backend)."""
        print(f"\n[FORWARDER] Connecting to SGBox at {self.host}:{self.port} via {self.protocol.upper()} (python backend)...")
        match self.protocol:
            case "udp":
                await self._connect_udp()
            case "tcp":
                await self._connect_tcp()
            case "tls":
                await self._connect_tcp()
            case _:
                print(f"[FORWARDER] ✗ Unknown protocol '{self.protocol}', defaulting to UDP")
                await self._connect_udp()

    async def _connect_udp(self):
        """Set up UDP transport."""
        print(f"[FORWARDER] Setting up UDP transport to {self.host}:{self.port}...")

        loop = asyncio.get_running_loop()

        class _UDPProtocol(asyncio.DatagramProtocol):
            def error_received(self, exc):
                print(f"[FORWARDER] ✗ UDP error: {exc}")

        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                _UDPProtocol,
                remote_addr=(self.host, self.port),
            )
            self._connected = True
            print(f"[FORWARDER] ✓ UDP transport ready to {self.host}:{self.port}")
            logger.info("forwarder.udp_ready", host=self.host, port=self.port)
        except Exception as e:
            print(f"[FORWARDER] ✗ UDP setup FAILED: {e}")
            raise

    @retry(
        stop=stop_after_attempt(10),
        wait=wait_exponential(multiplier=1, min=5, max=60),
        retry=retry_if_exception_type((OSError, ConnectionError)),
        reraise=True,
    )
    async def _connect_tcp(self):
        """Async TCP/TLS connection with tenacity retry."""
        print(f"[FORWARDER] Connecting {self.protocol.upper()} to {self.host}:{self.port}...")
        logger.info("forwarder.connecting", protocol=self.protocol.upper(),
                    host=self.host, port=self.port)

        ssl_ctx = None
        server_hostname = None
        match self.protocol:
            case "tls":
                print(f"[FORWARDER] Creating TLS context for outbound connection...")
                ssl_ctx = self._create_ssl_context()
                server_hostname = self.host
                print(f"[FORWARDER] ✓ TLS context created, server_hostname={server_hostname}")
            case _:
                print(f"[FORWARDER] Plain TCP mode (no encryption)")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host=self.host,
                    port=self.port,
                    ssl=ssl_ctx,
                    server_hostname=server_hostname,
                ),
                timeout=10.0,
            )
            self._connected = True
            print(f"[FORWARDER] ✓ {self.protocol.upper()} connected to {self.host}:{self.port}")
            logger.info("forwarder.connected",
                         protocol=self.protocol.upper(),
                         host=self.host, port=self.port)
        except asyncio.TimeoutError:
            print(f"[FORWARDER] ✗ Connection TIMED OUT (10s) to {self.host}:{self.port}")
            raise ConnectionError(f"Connection timed out to {self.host}:{self.port}")
        except ssl.SSLError as e:
            print(f"[FORWARDER] ✗ TLS HANDSHAKE FAILED to {self.host}:{self.port}: {e}")
            raise
        except OSError as e:
            print(f"[FORWARDER] ✗ Connection FAILED to {self.host}:{self.port}: {e}")
            raise

    # ══════════════════════════════════════════════════════════════════
    #  Send
    # ══════════════════════════════════════════════════════════════════

    async def send(self, message: str):
        """
        Send a single syslog message to SGBox (async).

        Dispatches to rsyslog, python, or parallel backend.
        In parallel mode, fires rsyslog + direct UDP concurrently.
        """
        if not message:
            print(f"[FORWARDER] ✗ Empty message, skipping")
            return

        match self.backend:
            case "rsyslog":
                await self._send_rsyslog(message)
            case "parallel":
                # Fire BOTH vectors concurrently — one failure doesn't block the other
                data = (message + "\n").encode("utf-8")
                print(f"[FORWARDER] Sending via PARALLEL (rsyslog + UDP {len(data)}B)")
                results = await asyncio.gather(
                    self._send_rsyslog(message),
                    self._send_udp(data),
                    return_exceptions=True,
                )
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        vector = "rsyslog" if i == 0 else "udp"
                        print(f"[FORWARDER] ✗ Parallel vector {vector} failed: {result}")
            case "python":
                # Send as clean syslog — SGBox syslog ingestion does NOT use API keys
                data = (message + "\n").encode("utf-8")
                print(f"[FORWARDER] Sending {len(data)}B via {self.protocol.upper()} (python)")
                match self.protocol:
                    case "udp":
                        await self._send_udp(data)
                    case _:
                        await self._send_tcp(data)

    # ── rsyslog send ───────────────────────────────────────────────────

    async def _send_rsyslog(self, message: str):
        """
        Send message directly to rsyslog via Python's syslog module.

        Writes to /dev/log (Unix domain socket) — zero subprocess overhead.
        rsyslog then forwards to SGBox per /etc/rsyslog.d/h3c-sgbox.conf.

        B3: syslog.syslog() is a blocking C call, so we run it in the default
        executor to avoid stalling the event loop under high throughput.
        """
        # Open syslog connection if not already open
        if not self._syslog_opened:
            _syslog.openlog(
                ident="h3c-translator",
                logoption=_syslog.LOG_PID | _syslog.LOG_NDELAY,
                facility=self._syslog_facility,
            )
            self._syslog_opened = True
            print(f"[FORWARDER] ✓ syslog socket opened (facility={self.facility})")

        # S4: Truncate oversized messages to kernel syslog limit
        if len(message.encode("utf-8", errors="replace")) > MAX_SYSLOG_MSG:
            message = message[:MAX_SYSLOG_MSG].rstrip()
            print(f"[FORWARDER] ⚠ Message truncated to {MAX_SYSLOG_MSG}B for syslog")

        try:
            # B3: Run blocking syslog.syslog() in executor to avoid stalling event loop
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                functools.partial(_syslog.syslog, self._syslog_severity, message),
            )
            async with self._stats_lock:
                self._stats["messages_sent"] += 1
                self._stats["messages_sent_rsyslog"] += 1
            print(f"[FORWARDER] ✓ rsyslog message sent ({len(message)}B)")
        except Exception as e:
            async with self._stats_lock:
                self._stats["messages_failed"] += 1
                self._stats["messages_failed_rsyslog"] += 1
            print(f"[FORWARDER] ✗ syslog send error: {e}")
            logger.error("forwarder.rsyslog_send_error", error=str(e))

    # ── python send (legacy) ───────────────────────────────────────────

    async def _send_udp(self, data: bytes):
        """Send message via async UDP transport."""
        try:
            if not self._transport or self._transport.is_closing():
                print(f"[FORWARDER] UDP transport not ready, reconnecting...")
                await self._connect_udp()

            # B1: Connected UDP endpoint (remote_addr set at creation) —
            # do NOT pass addr to sendto(), it raises OSError on some OS.
            self._transport.sendto(data)
            async with self._stats_lock:
                self._stats["messages_sent"] += 1
                self._stats["messages_sent_udp"] += 1
            print(f"[FORWARDER] ✓ UDP message sent ({len(data)}B)")
        except Exception as e:
            async with self._stats_lock:
                self._stats["messages_failed"] += 1
                self._stats["messages_failed_udp"] += 1
            print(f"[FORWARDER] ✗ UDP send FAILED: {e}")
            logger.error("forwarder.udp_send_failed",
                          host=self.host, port=self.port, error=str(e))

    async def _send_tcp(self, data: bytes):
        """Send via async TCP/TLS stream with auto-reconnect."""
        async with self._lock:
            if not self._connected or not self._writer:
                print(f"[FORWARDER] Not connected, attempting reconnect...")
                try:
                    await self._connect_tcp()
                    async with self._stats_lock:  # H4: consistent locking
                        self._stats["reconnections"] += 1
                    print(f"[FORWARDER] ✓ Reconnected (total reconnections: {self._stats['reconnections']})")
                except Exception as e:
                    async with self._stats_lock:  # H4: consistent locking
                        self._stats["messages_failed"] += 1
                    print(f"[FORWARDER] ✗ Reconnect FAILED: {e} — message DROPPED")
                    return

            try:
                self._writer.write(data)
                await self._writer.drain()
                async with self._stats_lock:
                    self._stats["messages_sent"] += 1
                print(f"[FORWARDER] ✓ {self.protocol.upper()} message sent ({len(data)}B)")
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                self._connected = False
                async with self._stats_lock:
                    self._stats["messages_failed"] += 1
                print(f"[FORWARDER] ✗ Connection LOST during send: {e}")
                logger.warning("forwarder.connection_lost",
                               host=self.host, port=self.port, error=str(e))
                await self._safe_close()

                # Attempt immediate reconnect and resend
                print(f"[FORWARDER] Attempting immediate reconnect + resend...")
                try:
                    await self._connect_tcp()
                    self._writer.write(data)
                    await self._writer.drain()
                    async with self._stats_lock:  # H4: consistent locking
                        self._stats["messages_sent"] += 1
                        # B7: Only decrement if positive to prevent negative counters
                        if self._stats["messages_failed"] > 0:
                            self._stats["messages_failed"] -= 1
                        self._stats["reconnections"] += 1
                    print(f"[FORWARDER] ✓ Reconnected and resent successfully")
                except Exception as e2:
                    print(f"[FORWARDER] ✗ Reconnect + resend FAILED: {e2} — message LOST")

    # ══════════════════════════════════════════════════════════════════
    #  TLS / Cleanup
    # ══════════════════════════════════════════════════════════════════

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for outbound TLS connection to SGBox."""
        print(f"[FORWARDER] Building outbound TLS context...")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= ssl.OP_NO_COMPRESSION

        ca_file = self._tls_config.get("ca_file", "")
        match bool(ca_file):
            case True:
                if not os.path.isfile(ca_file):
                    print(f"[FORWARDER] ✗ CA file NOT FOUND: {ca_file}")
                    print(f"[FORWARDER]   Re-run install.sh to fetch the CA bundle")
                    logger.error("forwarder.ca_file_not_found",
                                 ca_file=ca_file,
                                 hint="Re-run install.sh to fetch the CA bundle")
                    raise ValueError(
                        f"CA bundle not found: {ca_file}. "
                        f"Re-run install.sh or manually fetch: "
                        f"curl -sSL https://pki.goog/roots.pem > {ca_file}"
                    )
                try:
                    ctx.load_verify_locations(cafile=ca_file)
                    print(f"[FORWARDER] ✓ CA loaded: {ca_file}")
                    logger.debug("forwarder.ca_loaded", ca_file=ca_file)
                except ssl.SSLError as e:
                    print(f"[FORWARDER] ✗ CA load FAILED: {e}")
                    logger.error("forwarder.ca_load_failed",
                                 ca_file=ca_file, error=str(e),
                                 hint="CA bundle may be corrupted. Re-run install.sh")
                    raise
            case False:
                ctx.set_default_verify_paths()
                print(f"[FORWARDER] Using system default CA paths")
                logger.debug("forwarder.using_system_cas")

        print(f"[FORWARDER] ✓ Outbound TLS context ready")
        return ctx

    async def _safe_close(self):
        """Safely close the current async writer/transport."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
                print(f"[FORWARDER] Writer closed")
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def close(self):
        """Close the forwarder connection."""
        print(f"[FORWARDER] Closing connection...")
        async with self._lock:
            match self.backend:
                case "rsyslog":
                    # Close syslog socket
                    if self._syslog_opened:
                        _syslog.closelog()
                        self._syslog_opened = False
                    # rsyslog keeps running — we don't remove the config
                    # so forwarding continues even after translator stops
                    print(f"[FORWARDER] rsyslog backend — config persists at {RSYSLOG_CONF_FILE}")
                    print(f"[FORWARDER]   To stop forwarding: rm {RSYSLOG_CONF_FILE} && service rsyslog restart")
                case "parallel":
                    # Close BOTH vectors
                    if self._syslog_opened:
                        _syslog.closelog()
                        self._syslog_opened = False
                    if self._transport:
                        self._transport.close()
                        self._transport = None
                    print(f"[FORWARDER] Parallel backend closed (rsyslog + UDP)")
                    print(f"[FORWARDER]   rsyslog config persists at {RSYSLOG_CONF_FILE}")
                    print(f"[FORWARDER]   To stop forwarding: rm {RSYSLOG_CONF_FILE} && service rsyslog restart")
                case "python":
                    if self._transport:
                        self._transport.close()
                        self._transport = None
                        print(f"[FORWARDER] UDP transport closed")
                    await self._safe_close()

            self._connected = False
            print(f"[FORWARDER] ✓ Forwarder closed. Final stats: {self._stats}")
            logger.info("forwarder.closed")

    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._connected
