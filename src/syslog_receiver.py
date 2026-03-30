"""
Async TLS/TCP/UDP Syslog Receiver

Listens for incoming H3C syslog messages over:
  - TLS (port 6514) — encrypted, with optional client cert verification
  - TCP (port 514)  — plaintext fallback
  - UDP (port 514)  — standard syslog (most H3C devices use this)

Supports multiple concurrent connections with IP whitelist filtering.

Dependencies: structlog, pyOpenSSL (optional, for enhanced TLS)
"""

import asyncio
import ipaddress
import ssl

import structlog
from typing import Callable, Dict, Optional, Set

logger = structlog.get_logger(__name__)

# Maximum syslog message line size (bytes). Limits StreamReader buffering.
MAX_SYSLOG_LINE = 8192  # 8 KB — RFC 5424 recommends ≤ 2048, generous margin

# UDP rate limiting: max datagrams per source IP per window
_UDP_RATE_LIMIT = 500      # max msgs per window
_UDP_RATE_WINDOW = 10.0    # seconds
_UDP_RATE_MAX_IPS = 10_000 # HIGH-07: cap tracked IPs to prevent OOM


class _UDPSyslogProtocol(asyncio.DatagramProtocol):
    """
    Async UDP datagram protocol for receiving syslog messages.

    Each received datagram is treated as a single syslog message,
    validated against the IP whitelist, and passed to the message handler.
    """

    def __init__(self, receiver: "SyslogReceiver"):
        self._receiver = receiver
        self._transport: asyncio.DatagramTransport | None = None
        # LOW-01: Per-source UDP rate limiter
        self._rate_counts: dict[str, int] = {}
        self._rate_reset_handle: asyncio.TimerHandle | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._transport = transport
        # Schedule periodic rate counter reset
        loop = transport.get_extra_info("loop") or asyncio.get_running_loop()  # L3
        self._schedule_rate_reset(loop)
        print(f"[UDP] Datagram endpoint ready")

    def _schedule_rate_reset(self, loop: asyncio.AbstractEventLoop):
        """Reset rate counters every window."""
        self._rate_counts.clear()
        self._rate_reset_handle = loop.call_later(
            _UDP_RATE_WINDOW, self._schedule_rate_reset, loop
        )

    def datagram_received(self, data: bytes, addr: tuple):
        client_ip = addr[0]

        # LOW-01 + HIGH-07: Per-source rate limiting with IP cap
        count = self._rate_counts.get(client_ip, 0)
        if count >= _UDP_RATE_LIMIT:
            return  # Silently drop
        if client_ip not in self._rate_counts and len(self._rate_counts) >= _UDP_RATE_MAX_IPS:
            return  # HIGH-07: table full, drop unknown IPs
        self._rate_counts[client_ip] = count + 1

        # IP whitelist check
        if not self._receiver._is_ip_allowed(client_ip):
            self._receiver._increment_stat("connections_rejected_ip")
            return

        message = data.decode("utf-8", errors="replace").strip()
        if not message:
            return

        self._receiver._increment_stat("messages_received")

        # LOW-06: create_task instead of deprecated ensure_future; store ref
        task = asyncio.get_running_loop().create_task(self._handle(message, client_ip))
        task.add_done_callback(self._task_done)

    @staticmethod
    def _task_done(task: asyncio.Task):
        """LOW-06: Log exceptions from fire-and-forget UDP handler tasks."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            logger.error("receiver.udp_task_error", error=str(exc))

    async def _handle(self, message: str, client_ip: str):
        try:
            await self._receiver.message_handler(message, client_ip)
        except Exception as e:
            logger.error("receiver.udp_handler_error",
                         client_ip=client_ip, error=str(e))

    def error_received(self, exc: Exception):
        print(f"[UDP] ✗ Protocol error received: {exc}")
        logger.warning("receiver.udp_error", error=str(exc))

    def connection_lost(self, exc: Exception | None):
        # Cancel the rate reset timer
        if self._rate_reset_handle:
            self._rate_reset_handle.cancel()
        match exc:
            case None:
                print(f"[UDP] Datagram endpoint closed normally")
            case _:
                print(f"[UDP] ✗ Datagram endpoint lost: {exc}")
                logger.warning("receiver.udp_connection_lost", error=str(exc))


class SyslogReceiver:
    """
    Async TLS/TCP/UDP syslog receiver with IP whitelist and connection limits.

    Features:
        - UDP syslog listener (standard H3C firewall default)
        - TLS 1.2+ enforcement with configurable cert paths
        - TCP plaintext fallback
        - IP whitelist via CIDR notation
        - Configurable max concurrent connections via asyncio.Semaphore
        - Per-connection stats tracking
        - Graceful shutdown
    """

    def __init__(self, config: dict, message_handler: Callable):
        """
        Args:
            config: Parsed config dictionary with 'server', 'tls', 'security' sections.
            message_handler: Async callable(message: str, client_ip: str) for each log line.
        """
        self.config = config
        self.message_handler = message_handler
        self._servers: list[asyncio.Server] = []
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._active_connections: Set[str] = set()
        self._max_connections = int(config.get("server", {}).get("max_connections", 100))
        self._connection_semaphore: Optional[asyncio.Semaphore] = None
        self._active_count: int = 0
        self._allowed_networks = self._parse_allowed_ips(
            config.get("security", {}).get("allowed_ips", "0.0.0.0/0")
        )
        # HIGH-08: Lock for all stats mutations
        self._stats_lock = asyncio.Lock()
        self._stats: Dict[str, int] = {
            "connections_total": 0,
            "connections_rejected_ip": 0,
            "connections_rejected_limit": 0,
            "messages_received": 0,
            "tls_errors": 0,
        }

        print(f"[RECEIVER] Initialized")
        print(f"[RECEIVER]   Max connections: {self._max_connections}")
        print(f"[RECEIVER]   Allowed networks: {[str(n) for n in self._allowed_networks]}")

    def _increment_stat(self, key: str) -> None:
        """HIGH-08: Thread-safe stat increment (sync, for UDP protocol callbacks)."""
        # Safe because asyncio is single-threaded; lock is for coroutine interleaving
        self._stats[key] = self._stats.get(key, 0) + 1

    @property
    def stats(self) -> Dict[str, int]:
        return self._stats.copy()

    async def start(self):
        """Start all configured syslog listeners (UDP + TCP + TLS)."""
        self._connection_semaphore = asyncio.Semaphore(self._max_connections)

        tls_config = self.config.get("tls", {})
        server_config = self.config.get("server", {})
        bind_address = server_config.get("bind_address", "0.0.0.0")

        print(f"\n{'='*60}")
        print(f"[RECEIVER] Starting syslog listeners on {bind_address}")
        print(f"{'='*60}")

        # ── Start UDP listener (standard syslog) ──────────────────
        udp_port = int(server_config.get("syslog_udp_port",
                       server_config.get("syslog_tcp_port", 514)))
        print(f"\n[RECEIVER] Starting UDP listener on {bind_address}:{udp_port}...")
        try:
            loop = asyncio.get_running_loop()
            self._udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPSyslogProtocol(self),
                local_addr=(bind_address, udp_port),
            )
            print(f"[RECEIVER] ✓ UDP listener STARTED on {bind_address}:{udp_port}")
            logger.info("receiver.udp_started", port=udp_port, bind=bind_address)
        except Exception as e:
            print(f"[RECEIVER] ✗ UDP listener FAILED on {bind_address}:{udp_port}: {e}")
            logger.error("receiver.udp_failed", port=udp_port, error=str(e))

        # ── Start TLS listener ─────────────────────────────────────
        tls_port = int(server_config.get("syslog_tls_port", 6514))
        print(f"\n[RECEIVER] Starting TLS listener on {bind_address}:{tls_port}...")
        try:
            ssl_ctx = self._create_ssl_context(tls_config)
            tls_server = await asyncio.start_server(
                self._handle_client,
                host=bind_address,
                port=tls_port,
                ssl=ssl_ctx,
                limit=MAX_SYSLOG_LINE,
            )
            self._servers.append(tls_server)
            print(f"[RECEIVER] ✓ TLS listener STARTED on {bind_address}:{tls_port}")
            logger.info("receiver.tls_started", port=tls_port)
        except Exception as e:
            print(f"[RECEIVER] ✗ TLS listener FAILED on {bind_address}:{tls_port}: {e}")
            logger.error("receiver.tls_failed", port=tls_port, error=str(e))

        # ── Start TCP listener (plaintext) ─────────────────────────
        tcp_port = int(server_config.get("syslog_tcp_port", 514))
        print(f"\n[RECEIVER] Starting TCP listener on {bind_address}:{tcp_port}...")
        try:
            tcp_server = await asyncio.start_server(
                self._handle_client,
                host=bind_address,
                port=tcp_port,
                limit=MAX_SYSLOG_LINE,
            )
            self._servers.append(tcp_server)
            print(f"[RECEIVER] ✓ TCP listener STARTED on {bind_address}:{tcp_port}")
            logger.info("receiver.tcp_started", port=tcp_port)
        except Exception as e:
            print(f"[RECEIVER] ✗ TCP listener FAILED on {bind_address}:{tcp_port}: {e}")
            logger.error("receiver.tcp_failed", port=tcp_port, error=str(e))

        if not self._servers and not self._udp_transport:
            print(f"[RECEIVER] ✗✗ FATAL: No syslog listeners could be started!")
            raise RuntimeError("No syslog listeners could be started")

        print(f"\n[RECEIVER] ✓ Receiver ready — {len(self._servers)} TCP/TLS + "
              f"{'1 UDP' if self._udp_transport else '0 UDP'} listeners active")

    async def stop(self):
        """Gracefully stop all listeners."""
        print(f"\n[RECEIVER] Stopping all listeners...")

        # Stop UDP
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
            print(f"[RECEIVER] ✓ UDP listener stopped")
            logger.info("receiver.udp_stopped")

        # Stop TCP/TLS
        for server in self._servers:
            server.close()
            await server.wait_closed()
        print(f"[RECEIVER] ✓ All TCP/TLS listeners stopped")
        logger.info("receiver.all_stopped")

        print(f"[RECEIVER] Final stats: {self._stats}")

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
        """Handle a single TCP/TLS client connection."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        client_port = peername[1] if peername else 0
        ssl_obj = writer.get_extra_info("ssl_object")
        proto_label = "TLS" if ssl_obj else "TCP"

        print(f"[{proto_label}] New connection from {client_ip}:{client_port}")

        # ── IP whitelist check ─────────────────────────────────────
        if not self._is_ip_allowed(client_ip):
            self._increment_stat("connections_rejected_ip")
            print(f"[{proto_label}] ✗ REJECTED — IP {client_ip} not in whitelist")
            logger.warning("receiver.ip_rejected", client_ip=client_ip)
            writer.close()
            await writer.wait_closed()
            return

        # CRIT-04: Atomic semaphore acquire — no TOCTOU race
        try:
            await asyncio.wait_for(self._connection_semaphore.acquire(), timeout=0.1)
        except asyncio.TimeoutError:
            self._increment_stat("connections_rejected_limit")
            print(f"[{proto_label}] ✗ REJECTED — Max connections reached ({self._max_connections})")
            logger.warning("receiver.max_connections",
                            client_ip=client_ip,
                            max=self._max_connections)
            writer.close()
            await writer.wait_closed()
            return

        self._active_count += 1
        self._increment_stat("connections_total")
        conn_id = f"{client_ip}:{client_port}"
        self._active_connections.add(conn_id)
        print(f"[{proto_label}] ✓ Connected {conn_id} (active: {self._active_count})")
        logger.info("receiver.connected",
                      client_ip=client_ip, active=self._active_count)

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.readline(), timeout=300.0  # 5 min timeout
                    )
                except asyncio.TimeoutError:
                    print(f"[{proto_label}] Timeout (5min) for {client_ip}, closing")
                    logger.debug("receiver.timeout", client_ip=client_ip)
                    break
                except asyncio.LimitOverrunError:
                    # HIGH-02: Disconnect abuser instead of trying to consume
                    # (prevents infinite loop if attacker sends endless data without newline)
                    print(f"[{proto_label}] ✗ Line too long from {client_ip} (>{MAX_SYSLOG_LINE}B), disconnecting")
                    logger.warning("receiver.line_too_long",
                                    client_ip=client_ip,
                                    limit=MAX_SYSLOG_LINE)
                    break

                if not data:
                    print(f"[{proto_label}] Connection closed by {client_ip}")
                    break  # Connection closed

                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    self._increment_stat("messages_received")
                    print(f"[{proto_label}] Message from {client_ip} ({len(message)} bytes)")
                    try:
                        await self.message_handler(message, client_ip)
                    except Exception as e:
                        print(f"[{proto_label}] ✗ Handler FAILED for {client_ip}: {e}")
                        logger.error("receiver.handler_error",
                                      client_ip=client_ip, error=str(e))

        except ssl.SSLError as e:
            self._increment_stat("tls_errors")
            print(f"[{proto_label}] ✗ TLS ERROR from {client_ip}: {e}")
            logger.error("receiver.tls_error", client_ip=client_ip, error=str(e))
        except ConnectionResetError:
            print(f"[{proto_label}] Connection RESET by {client_ip}")
            logger.debug("receiver.connection_reset", client_ip=client_ip)
        except Exception as e:
            print(f"[{proto_label}] ✗ UNEXPECTED ERROR from {client_ip}: {e}")
            logger.error("receiver.unexpected_error",
                          client_ip=client_ip, error=str(e))
        finally:
            self._connection_semaphore.release()
            self._active_count -= 1
            self._active_connections.discard(conn_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            print(f"[{proto_label}] Disconnected {conn_id} (active: {self._active_count})")
            logger.info("receiver.disconnected",
                          client_ip=client_ip, active=self._active_count)

    def _create_ssl_context(self, tls_config: dict) -> ssl.SSLContext:
        """
        Create a secure SSL context for the syslog receiver.

        Enforces TLS 1.2+ and loads configured certificates.
        """
        print(f"[TLS] Creating SSL context...")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Enforce minimum TLS version
        min_version = tls_config.get("min_tls_version", "TLSv1.2")
        match min_version:
            case "TLSv1.3" if hasattr(ssl.TLSVersion, "TLSv1_3"):
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                print(f"[TLS] Minimum version: TLSv1.3")
            case _:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                print(f"[TLS] Minimum version: TLSv1.2")

        # Disable compression (CRIME attack mitigation)
        ctx.options |= ssl.OP_NO_COMPRESSION
        print(f"[TLS] Compression disabled (CRIME mitigation)")

        # Load server certificate and key
        cert_file = tls_config.get("cert_file", "")
        key_file = tls_config.get("key_file", "")
        if cert_file and key_file:
            print(f"[TLS] Loading cert: {cert_file}")
            print(f"[TLS] Loading key:  {key_file}")
            ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
            print(f"[TLS] ✓ Certificate chain loaded")
        else:
            print(f"[TLS] ✗ FAILED — cert_file and key_file are REQUIRED")
            raise ValueError("TLS cert_file and key_file are required in config")

        # Load CA for client cert verification
        ca_file = tls_config.get("ca_file", "")
        require_client = tls_config.get("require_client_cert", "false").lower() == "true"
        if ca_file:
            print(f"[TLS] Loading CA: {ca_file}")
            ctx.load_verify_locations(cafile=ca_file)
            print(f"[TLS] ✓ CA loaded")

        match require_client:
            case True:
                ctx.verify_mode = ssl.CERT_REQUIRED
                print(f"[TLS] Client certificate: REQUIRED")
            case False:
                ctx.verify_mode = ssl.CERT_NONE
                print(f"[TLS] Client certificate: not required")

        print(f"[TLS] ✓ SSL context ready")
        return ctx

    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if an IP address is in the whitelist."""
        if not self._allowed_networks:
            return True

        try:
            addr = ipaddress.ip_address(client_ip)
            allowed = any(addr in net for net in self._allowed_networks)
            return allowed
        except ValueError:
            print(f"[RECEIVER] ✗ Invalid IP address format: {client_ip}")
            logger.warning("receiver.invalid_ip", ip=client_ip)
            return False

    @staticmethod
    def _parse_allowed_ips(allowed_str: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse comma-separated IP list into network objects."""
        # Treat 0.0.0.0 as allow-all (empty list = no filtering)
        if allowed_str.strip() in ("0.0.0.0", "0.0.0.0/0"):
            print(f"[RECEIVER] Allowed IPs: ALL (0.0.0.0)")
            return []

        networks = []
        for entry in allowed_str.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                match "/" in entry:
                    case True:
                        networks.append(ipaddress.ip_network(entry, strict=False))
                    case False:
                        networks.append(ipaddress.ip_network(entry + "/32", strict=False))
                print(f"[RECEIVER] ✓ Allowed IP: {entry}")
            except ValueError as e:
                print(f"[RECEIVER] ✗ Invalid IP entry '{entry}': {e}")
                structlog.get_logger().warning("receiver.invalid_cidr",
                                                entry=entry, error=str(e))
        return networks
