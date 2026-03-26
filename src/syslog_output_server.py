"""
Async Syslog Output Server — serves translated logs to SGBox collectors.

SGBox pulls logs by connecting to this server's TCP port.
When SGBox connects, it receives all translated log messages as they arrive.
Multiple collectors can connect simultaneously.

Architecture:
    H3C → SyslogReceiver → Parser → Formatter → SyslogOutputServer ← SGBox connects here

Dependencies: structlog
"""

import asyncio
import ipaddress
import ssl

import structlog

logger = structlog.get_logger(__name__)


class SyslogOutputServer:
    """
    Async TCP syslog server that SGBox collectors connect to and pull translated logs.

    When translated messages arrive (via ``send()``), they are streamed to all
    currently connected SGBox collectors.

    Fully async: ``send()`` is an async method.
    """

    def __init__(self, config: dict):
        self.config = config
        sgbox_cfg = config.get("sgbox", {})
        server_cfg = config.get("server", {})
        security_cfg = config.get("security", {})

        self._port = int(sgbox_cfg.get("output_port", sgbox_cfg.get("port", "1514")))
        self._bind = server_cfg.get("bind_address", "0.0.0.0")

        # HIGH-03: Apply same IP whitelist as receiver
        self._allowed_networks = self._parse_allowed_ips(
            security_cfg.get("allowed_ips", "0.0.0.0/0")
        )

        # Connected SGBox collectors
        self._clients: dict[str, asyncio.StreamWriter] = {}
        self._clients_lock = asyncio.Lock()

        self._server: asyncio.Server | None = None

        self._stats = {
            "collectors_connected": 0,
            "collectors_total": 0,
            "collectors_rejected_ip": 0,
            "messages_sent": 0,
            "messages_dropped": 0,
        }
        # M4: Lock for thread-safe stats updates
        self._stats_lock = asyncio.Lock()

        print(f"[OUTPUT] Initialized")
        print(f"[OUTPUT]   Bind: {self._bind}:{self._port}")
        print(f"[OUTPUT]   IP whitelist: {len(self._allowed_networks) if self._allowed_networks else 'disabled'}")

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    async def start(self):
        """Start listening for SGBox collector connections."""
        tls_config = self.config.get("tls", {})
        ssl_ctx = None

        # Optional TLS for output (if SGBox collector uses TLS)
        cert_file = tls_config.get("cert_file")
        key_file = tls_config.get("key_file")
        match (bool(cert_file), bool(key_file)):
            case (True, True):
                try:
                    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ssl_ctx.load_cert_chain(cert_file, key_file)
                    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ssl_ctx.options |= ssl.OP_NO_COMPRESSION
                    print(f"[OUTPUT] ✓ TLS enabled for output server")
                    print(f"[OUTPUT]   Cert: {cert_file}")
                    print(f"[OUTPUT]   Key:  {key_file}")
                    logger.info("output.tls_enabled")
                except Exception as e:
                    print(f"[OUTPUT] ✗ TLS setup FAILED: {e}")
                    print(f"[OUTPUT]   Falling back to plain TCP")
                    logger.warning("output.tls_failed", error=str(e),
                                    msg="Falling back to plain TCP")
                    ssl_ctx = None
            case _:
                print(f"[OUTPUT] No TLS certs configured, using plain TCP")

        print(f"[OUTPUT] Starting output server on {self._bind}:{self._port}...")
        try:
            self._server = await asyncio.start_server(
                self._handle_collector,
                host=self._bind,
                port=self._port,
                ssl=ssl_ctx,
            )
            proto = "TLS" if ssl_ctx else "TCP"
            print(f"[OUTPUT] ✓ Output server STARTED on {self._bind}:{self._port} ({proto})")
            logger.info("output.started", bind=self._bind, port=self._port)
        except Exception as e:
            print(f"[OUTPUT] ✗ Output server FAILED to start: {e}")
            raise

    async def _handle_collector(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter):
        """Handle an incoming SGBox collector connection."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        client_id = f"{client_ip}:{peername[1] if peername else 0}"

        # HIGH-03: IP whitelist check
        if not self._is_ip_allowed(client_ip):
            async with self._stats_lock:  # M4
                self._stats["collectors_rejected_ip"] += 1
            print(f"[OUTPUT] ✗ Collector REJECTED — IP {client_ip} not in whitelist")
            logger.warning("output.collector_ip_rejected", client_ip=client_ip)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        print(f"[OUTPUT] ✓ Collector CONNECTED: {client_id}")
        logger.info("output.collector_connected", client_id=client_id)

        async with self._clients_lock:
            self._clients[client_id] = writer
        async with self._stats_lock:  # M4
            self._stats["collectors_connected"] += 1
            self._stats["collectors_total"] += 1

        print(f"[OUTPUT] Active collectors: {self._stats['collectors_connected']}")

        try:
            # Keep connection alive — wait for disconnect
            while True:
                data = await reader.read(1024)
                if not data:
                    print(f"[OUTPUT] Collector {client_id} disconnected (EOF)")
                    break
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError) as e:
            print(f"[OUTPUT] Collector {client_id} disconnected: {e}")
        finally:
            async with self._clients_lock:
                self._clients.pop(client_id, None)
            async with self._stats_lock:  # M4
                self._stats["collectors_connected"] -= 1
            await self._safe_close_writer(writer)
            print(f"[OUTPUT] Collector {client_id} removed. Active: {self._stats['collectors_connected']}")
            logger.info("output.collector_disconnected", client_id=client_id)

    async def _safe_close_writer(self, writer: asyncio.StreamWriter):
        """Safely close an async writer, catching ConnectionResetError."""
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionResetError, OSError, Exception):
            pass

    async def send(self, message: str):
        """
        Send a translated syslog message to all connected SGBox collectors.

        Fully async — uses asyncio lock and drain.
        """
        if not self._clients:
            return

        syslog_line = message if message.endswith("\n") else message + "\n"
        data = syslog_line.encode("utf-8")

        async with self._clients_lock:
            clients_snapshot = dict(self._clients)

        print(f"[OUTPUT] Broadcasting to {len(clients_snapshot)} collector(s): {message[:100]}...")

        # M3: Parallel drain — one slow collector doesn't block others
        async def _send_to_client(client_id: str, writer: asyncio.StreamWriter):
            try:
                writer.write(data)
                await writer.drain()
                async with self._stats_lock:  # M4
                    self._stats["messages_sent"] += 1
                print(f"[OUTPUT] ✓ Sent to {client_id}")
                return None  # Success
            except Exception as e:
                async with self._stats_lock:  # M4
                    self._stats["messages_dropped"] += 1
                print(f"[OUTPUT] ✗ FAILED to send to {client_id}: {e}")
                return client_id  # Mark as dead

        results = await asyncio.gather(
            *[_send_to_client(cid, w) for cid, w in clients_snapshot.items()],
            return_exceptions=True,
        )

        # Remove dead connections
        dead_clients = [r for r in results if isinstance(r, str)]
        if dead_clients:
            async with self._clients_lock:
                for client_id in dead_clients:
                    self._clients.pop(client_id, None)
            print(f"[OUTPUT] Removed {len(dead_clients)} dead collector(s)")

    async def stop(self):
        """Shutdown the output server and disconnect all collectors."""
        print(f"[OUTPUT] Stopping output server...")
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        async with self._clients_lock:
            for client_id, writer in self._clients.items():
                try:
                    writer.close()
                    await writer.wait_closed()
                    print(f"[OUTPUT] Disconnected collector: {client_id}")
                except Exception:
                    pass
            self._clients.clear()

        print(f"[OUTPUT] ✓ Output server stopped. Final stats: {self._stats}")
        logger.info("output.stopped")

    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if an IP address is in the whitelist."""
        if not self._allowed_networks:
            return True
        try:
            addr = ipaddress.ip_address(client_ip)
            return any(addr in net for net in self._allowed_networks)
        except ValueError:
            return False

    @staticmethod
    def _parse_allowed_ips(allowed_str: str) -> list:
        """Parse comma-separated IP list into network objects."""
        if allowed_str.strip() in ("0.0.0.0", "0.0.0.0/0"):
            return []
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
            except ValueError:
                pass
        return networks
