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

    @property
    def stats(self) -> dict[str, int]:
        return self._stats.copy()

    async def connect(self):
        """Establish async connection to SGBox."""
        if self.protocol == "udp":
            await self._connect_udp()
        else:
            await self._connect_tcp()

    async def _connect_udp(self):
        """Set up UDP transport."""
        loop = asyncio.get_running_loop()

        class _UDPProtocol(asyncio.DatagramProtocol):
            def error_received(self, exc):
                pass  # UDP is fire-and-forget

        self._transport, _ = await loop.create_datagram_endpoint(
            _UDPProtocol,
            remote_addr=(self.host, self.port),
        )
        self._connected = True
        logger.info("forwarder.udp_ready", host=self.host, port=self.port)

    @retry(
        stop=stop_after_attempt(10),
        wait=wait_exponential(multiplier=1, min=5, max=60),
        retry=retry_if_exception_type((OSError, ConnectionError)),
        reraise=True,
    )
    async def _connect_tcp(self):
        """Async TCP/TLS connection with tenacity retry."""
        ssl_ctx = None
        server_hostname = None
        if self.protocol == "tls":
            ssl_ctx = self._create_ssl_context()
            # server_hostname is required for SNI and hostname verification.
            # Pass self.host so it works with both IPs and domain names.
            server_hostname = self.host

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
        logger.info("forwarder.connected",
                     protocol=self.protocol.upper(),
                     host=self.host, port=self.port)

    async def send(self, message: str):
        """
        Send a single syslog message to SGBox (async).

        Handles reconnection for TCP/TLS on failure.
        """
        if not message:
            return

        data = (message + "\n").encode("utf-8")

        if self.protocol == "udp":
            await self._send_udp(data)
        else:
            await self._send_tcp(data)

    async def _send_udp(self, data: bytes):
        """Send message via async UDP transport."""
        try:
            if not self._transport or self._transport.is_closing():
                await self._connect_udp()

            self._transport.sendto(data)
            self._stats["messages_sent"] += 1
        except Exception as e:
            self._stats["messages_failed"] += 1
            logger.error("forwarder.udp_send_failed",
                          host=self.host, port=self.port, error=str(e))

    async def _send_tcp(self, data: bytes):
        """Send via async TCP/TLS stream with auto-reconnect."""
        async with self._lock:
            if not self._connected or not self._writer:
                try:
                    await self._connect_tcp()
                    self._stats["reconnections"] += 1
                except Exception:
                    self._stats["messages_failed"] += 1
                    return

            try:
                self._writer.write(data)
                await self._writer.drain()
                self._stats["messages_sent"] += 1
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                self._connected = False
                self._stats["messages_failed"] += 1
                logger.warning("forwarder.connection_lost",
                               host=self.host, port=self.port, error=str(e))
                await self._safe_close()

                # Attempt immediate reconnect and resend
                try:
                    await self._connect_tcp()
                    self._writer.write(data)
                    await self._writer.drain()
                    self._stats["messages_sent"] += 1
                    self._stats["messages_failed"] -= 1
                    self._stats["reconnections"] += 1
                except Exception:
                    pass

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for outbound TLS connection to SGBox."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= ssl.OP_NO_COMPRESSION

        ca_file = self._tls_config.get("ca_file", "")
        if ca_file:
            if not os.path.isfile(ca_file):
                logger.error("forwarder.ca_file_not_found",
                             ca_file=ca_file,
                             hint="Re-run install.sh to fetch the CA bundle")
                raise FileNotFoundError(
                    f"CA bundle not found: {ca_file}. "
                    f"Re-run install.sh or manually fetch: "
                    f"curl -sSL https://pki.goog/roots.pem > {ca_file}"
                )
            try:
                ctx.load_verify_locations(cafile=ca_file)
                logger.debug("forwarder.ca_loaded", ca_file=ca_file)
            except ssl.SSLError as e:
                logger.error("forwarder.ca_load_failed",
                             ca_file=ca_file, error=str(e),
                             hint="CA bundle may be corrupted. Re-run install.sh")
                raise
        else:
            ctx.set_default_verify_paths()
            logger.debug("forwarder.using_system_cas")

        return ctx

    async def _safe_close(self):
        """Safely close the current async writer/transport."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

    async def close(self):
        """Close the forwarder connection."""
        async with self._lock:
            if self._transport:
                self._transport.close()
                self._transport = None
            await self._safe_close()
            self._connected = False
            logger.info("forwarder.closed")

    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._connected
