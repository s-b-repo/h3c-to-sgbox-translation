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

        self._port = int(sgbox_cfg.get("output_port", sgbox_cfg.get("port", "1514")))
        self._bind = server_cfg.get("bind_address", "0.0.0.0")

        # Connected SGBox collectors
        self._clients: dict[str, asyncio.StreamWriter] = {}
        self._clients_lock = asyncio.Lock()

        self._server: asyncio.Server | None = None

        self._stats = {
            "collectors_connected": 0,
            "collectors_total": 0,
            "messages_sent": 0,
            "messages_dropped": 0,
        }

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
        if cert_file and key_file:
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(cert_file, key_file)
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ssl_ctx.options |= ssl.OP_NO_COMPRESSION
                logger.info("output.tls_enabled")
            except Exception as e:
                logger.warning("output.tls_failed", error=str(e),
                                msg="Falling back to plain TCP")
                ssl_ctx = None

        self._server = await asyncio.start_server(
            self._handle_collector,
            host=self._bind,
            port=self._port,
            ssl=ssl_ctx,
        )
        logger.info("output.started", bind=self._bind, port=self._port)

    async def _handle_collector(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter):
        """Handle an incoming SGBox collector connection."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        client_id = f"{client_ip}:{peername[1] if peername else 0}"

        logger.info("output.collector_connected", client_id=client_id)

        async with self._clients_lock:
            self._clients[client_id] = writer
        self._stats["collectors_connected"] += 1
        self._stats["collectors_total"] += 1

        try:
            # Keep connection alive — wait for disconnect
            while True:
                data = await reader.read(1024)
                if not data:
                    break
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            async with self._clients_lock:
                self._clients.pop(client_id, None)
            self._stats["collectors_connected"] -= 1
            await self._safe_close_writer(writer)
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

        dead_clients = []
        for client_id, writer in clients_snapshot.items():
            try:
                writer.write(data)
                await writer.drain()
                self._stats["messages_sent"] += 1
            except Exception:
                self._stats["messages_dropped"] += 1
                dead_clients.append(client_id)

        # Remove dead connections
        if dead_clients:
            async with self._clients_lock:
                for client_id in dead_clients:
                    self._clients.pop(client_id, None)

    async def stop(self):
        """Shutdown the output server and disconnect all collectors."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        async with self._clients_lock:
            for client_id, writer in self._clients.items():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
            self._clients.clear()

        logger.info("output.stopped")
