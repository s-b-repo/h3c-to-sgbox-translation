"""
Async TLS Syslog Receiver

Listens for incoming H3C syslog messages over:
  - TLS (port 6514) — encrypted, with optional client cert verification
  - TCP (port 514)  — plaintext fallback

Supports multiple concurrent connections with IP whitelist filtering.

Dependencies: structlog, pyOpenSSL (optional, for enhanced TLS)
"""

import asyncio
import ipaddress
import ssl

import structlog
from typing import Callable, Dict, List, Optional, Set

logger = structlog.get_logger(__name__)


class SyslogReceiver:
    """
    Async TLS/TCP syslog receiver with IP whitelist and connection limits.

    Features:
        - TLS 1.2+ enforcement with configurable cert paths
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
        self._active_connections: Set[str] = set()
        self._max_connections = int(config.get("server", {}).get("max_connections", 100))
        self._connection_semaphore: Optional[asyncio.Semaphore] = None
        self._allowed_networks = self._parse_allowed_ips(
            config.get("security", {}).get("allowed_ips", "0.0.0.0/0")
        )
        self._stats: Dict[str, int] = {
            "connections_total": 0,
            "connections_rejected_ip": 0,
            "connections_rejected_limit": 0,
            "messages_received": 0,
            "tls_errors": 0,
        }

    @property
    def stats(self) -> Dict[str, int]:
        return self._stats.copy()

    async def start(self):
        """Start all configured syslog listeners."""
        self._connection_semaphore = asyncio.Semaphore(self._max_connections)

        tls_config = self.config.get("tls", {})
        server_config = self.config.get("server", {})
        bind_address = server_config.get("bind_address", "0.0.0.0")

        # ── Start TLS listener ─────────────────────────────────────
        tls_port = int(server_config.get("syslog_tls_port", 6514))
        try:
            ssl_ctx = self._create_ssl_context(tls_config)
            tls_server = await asyncio.start_server(
                self._handle_client,
                host=bind_address,
                port=tls_port,
                ssl=ssl_ctx,
            )
            self._servers.append(tls_server)
            logger.info("receiver.tls_started", port=tls_port)
        except Exception as e:
            logger.error("receiver.tls_failed", port=tls_port, error=str(e))

        # ── Start TCP listener (plaintext) ─────────────────────────
        tcp_port = int(server_config.get("syslog_tcp_port", 514))
        try:
            tcp_server = await asyncio.start_server(
                self._handle_client,
                host=bind_address,
                port=tcp_port,
            )
            self._servers.append(tcp_server)
            logger.info("receiver.tcp_started", port=tcp_port)
        except Exception as e:
            logger.error("receiver.tcp_failed", port=tcp_port, error=str(e))

        if not self._servers:
            raise RuntimeError("No syslog listeners could be started")

    async def stop(self):
        """Gracefully stop all listeners."""
        for server in self._servers:
            server.close()
            await server.wait_closed()
        logger.info("receiver.all_stopped")

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
        """Handle a single client connection."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        # ── IP whitelist check ─────────────────────────────────────
        if not self._is_ip_allowed(client_ip):
            self._stats["connections_rejected_ip"] += 1
            logger.warning("receiver.ip_rejected", client_ip=client_ip)
            writer.close()
            await writer.wait_closed()
            return

        # ── Connection limit check (atomic via semaphore) ──────────
        if not self._connection_semaphore._value:
            self._stats["connections_rejected_limit"] += 1
            logger.warning("receiver.max_connections",
                            client_ip=client_ip,
                            max=self._max_connections)
            writer.close()
            await writer.wait_closed()
            return

        await self._connection_semaphore.acquire()
        self._stats["connections_total"] += 1
        conn_id = f"{client_ip}:{peername[1] if peername else 0}"
        self._active_connections.add(conn_id)
        active_count = self._max_connections - self._connection_semaphore._value
        logger.info("receiver.connected",
                      client_ip=client_ip, active=active_count)

        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.readline(), timeout=300.0  # 5 min timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug("receiver.timeout", client_ip=client_ip)
                    break

                if not data:
                    break  # Connection closed

                message = data.decode("utf-8", errors="replace").strip()
                if message:
                    self._stats["messages_received"] += 1
                    try:
                        await self.message_handler(message, client_ip)
                    except Exception as e:
                        logger.error("receiver.handler_error",
                                      client_ip=client_ip, error=str(e))

        except ssl.SSLError as e:
            self._stats["tls_errors"] += 1
            logger.error("receiver.tls_error", client_ip=client_ip, error=str(e))
        except ConnectionResetError:
            logger.debug("receiver.connection_reset", client_ip=client_ip)
        except Exception as e:
            logger.error("receiver.unexpected_error",
                          client_ip=client_ip, error=str(e))
        finally:
            self._connection_semaphore.release()
            self._active_connections.discard(conn_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            active = self._max_connections - self._connection_semaphore._value
            logger.info("receiver.disconnected",
                          client_ip=client_ip, active=active)

    def _create_ssl_context(self, tls_config: dict) -> ssl.SSLContext:
        """
        Create a secure SSL context for the syslog receiver.

        Enforces TLS 1.2+ and loads configured certificates.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Enforce minimum TLS version (Python 3.11+)
        min_version = tls_config.get("min_tls_version", "TLSv1.2")
        if min_version == "TLSv1.3" and hasattr(ssl.TLSVersion, "TLSv1_3"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable compression (CRIME attack mitigation)
        ctx.options |= ssl.OP_NO_COMPRESSION

        # Load server certificate and key
        cert_file = tls_config.get("cert_file", "")
        key_file = tls_config.get("key_file", "")
        if cert_file and key_file:
            ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        else:
            raise ValueError("TLS cert_file and key_file are required in config")

        # Load CA for client cert verification
        ca_file = tls_config.get("ca_file", "")
        require_client = tls_config.get("require_client_cert", "false").lower() == "true"
        if ca_file:
            ctx.load_verify_locations(cafile=ca_file)
        if require_client:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE

        return ctx

    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if an IP address is in the whitelist."""
        if not self._allowed_networks:
            return True

        try:
            addr = ipaddress.ip_address(client_ip)
            return any(addr in net for net in self._allowed_networks)
        except ValueError:
            logger.warning("receiver.invalid_ip", ip=client_ip)
            return False

    @staticmethod
    def _parse_allowed_ips(allowed_str: str) -> list[ipaddress.IPv4Network]:
        """Parse comma-separated IP/CIDR list into network objects."""
        networks = []
        for entry in allowed_str.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                else:
                    networks.append(ipaddress.ip_network(entry + "/32", strict=False))
            except ValueError as e:
                structlog.get_logger().warning("receiver.invalid_cidr",
                                                entry=entry, error=str(e))
        return networks
