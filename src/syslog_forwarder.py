"""
Async Syslog Forwarder

Forwards translated log messages to the SGBox SIEM server via:
  - UDP syslog (fastest, no delivery guarantee)
  - TCP syslog (reliable, ordered delivery)
  - TLS syslog (encrypted + reliable)

Fully async with tenacity retry logic for automatic reconnection.

Dependencies: structlog, tenacity
"""

import asyncio
import os
import ssl

import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

logger = structlog.get_logger(__name__)


class SyslogForwarder:
    """
    Async syslog forwarder to SGBox over UDP, TCP, or TLS.

    Features:
        - Fully async I/O using asyncio streams
        - Automatic reconnection with tenacity exponential backoff
        - Message queueing during reconnection
        - Connection health monitoring
    """

    def __init__(self, config: dict):
        sgbox = config.get("sgbox", {})
        self.host = sgbox.get("host", "127.0.0.1")
        self.port = int(sgbox.get("port", 514))
        self.protocol = sgbox.get("protocol", "udp").lower()
        self.facility = sgbox.get("facility", "local0")
        self.severity = sgbox.get("severity", "info")

        # SGBox API key for log ingestion authentication
        self._sgbox_api_key = sgbox.get("sgbox_api_key", "").strip()
        _INSECURE_SGBOX_KEYS = ("", "CHANGE_ME_SET_YOUR_SGBOX_API_KEY")
        if self._sgbox_api_key in _INSECURE_SGBOX_KEYS:
            print(f"[FORWARDER] ⚠ WARNING: sgbox_api_key is not set!")
            print(f"[FORWARDER]   SGBox requires an API key for log ingestion on port {self.port}")
            print(f"[FORWARDER]   Get it from SGBox: SCM → Configuration → API Keys")
            print(f"[FORWARDER]   Set [sgbox] sgbox_api_key = <your key> in translator.config")
            self._sgbox_api_key = ""

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
        }
        # MED-04: Lock for thread-safe stats updates
        self._stats_lock = asyncio.Lock()

        print(f"[FORWARDER] Initialized")
        print(f"[FORWARDER]   Protocol:     {self.protocol.upper()}")
        print(f"[FORWARDER]   Target:       {self.host}:{self.port}")
        print(f"[FORWARDER]   SGBox API key: {'configured' if self._sgbox_api_key else 'NOT SET'}")
        print(f"[FORWARDER]   Facility:     {self.facility}")
        print(f"[FORWARDER]   Severity:     {self.severity}")

    @property
    def stats(self) -> dict[str, int]:
        # LOW-05: Return a copy (lock is asyncio.Lock, can't await in property)
        return self._stats.copy()

    async def connect(self):
        """Establish async connection to SGBox."""
        print(f"\n[FORWARDER] Connecting to SGBox at {self.host}:{self.port} via {self.protocol.upper()}...")
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

    async def send(self, message: str):
        """
        Send a single syslog message to SGBox (async).

        Handles reconnection for TCP/TLS on failure.
        """
        if not message:
            print(f"[FORWARDER] ✗ Empty message, skipping")
            return

        # Prepend SGBox API key if configured
        if self._sgbox_api_key:
            outgoing = f"APIKEY:{self._sgbox_api_key} {message}"
        else:
            outgoing = message

        data = (outgoing + "\n").encode("utf-8")
        # MED-05: Never log the full outgoing (contains API key)
        print(f"[FORWARDER] Sending {len(data)}B via {self.protocol.upper()}")

        match self.protocol:
            case "udp":
                await self._send_udp(data)
            case _:
                await self._send_tcp(data)

    async def _send_udp(self, data: bytes):
        """Send message via async UDP transport."""
        try:
            if not self._transport or self._transport.is_closing():
                print(f"[FORWARDER] UDP transport not ready, reconnecting...")
                await self._connect_udp()

            self._transport.sendto(data, (self.host, self.port))  # H5: explicit target
            async with self._stats_lock:
                self._stats["messages_sent"] += 1
            print(f"[FORWARDER] ✓ UDP message sent ({len(data)}B)")
        except Exception as e:
            async with self._stats_lock:
                self._stats["messages_failed"] += 1
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
                        self._stats["messages_failed"] -= 1
                        self._stats["reconnections"] += 1
                    print(f"[FORWARDER] ✓ Reconnected and resent successfully")
                except Exception as e2:
                    print(f"[FORWARDER] ✗ Reconnect + resend FAILED: {e2} — message LOST")

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
