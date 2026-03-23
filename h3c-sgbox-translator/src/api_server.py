"""
Async HTTPS REST API Server (aiohttp)

Provides HTTP API endpoints for:
  - POST /api/v1/translate      — translate a single H3C log line
  - POST /api/v1/translate/bulk  — translate multiple log lines
  - GET  /api/v1/health          — health check
  - GET  /api/v1/stats           — translation statistics

Security features:
  - API key authentication (X-API-Key header) via middleware
  - IP whitelist enforcement via middleware
  - Rate limiting (per-IP) via middleware
  - TLS required by default (aiohttp SSLContext)
  - Security headers (HSTS, CSP, X-Frame-Options, Cache-Control)
  - CORS policy
  - Generic error messages (no internal state leakage)
  - Bulk request size cap

Uses aiohttp — the most popular async HTTP framework for Python.
"""

import asyncio
import hmac
import ipaddress
import ssl
import time

import structlog
from aiohttp import web

from .parser import H3CLogParser
from .formatter import SGBoxFormatter

logger = structlog.get_logger(__name__)

# ── Constants ──────────────────────────────────────────────────────────
MAX_BULK_LINES = 1000          # cap bulk array size
MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB
RATE_LIMIT_WINDOW = 60         # seconds
RATE_LIMIT_MAX_REQUESTS = 120  # per IP per window


class _RateLimiter:
    """Async-safe per-IP sliding-window rate limiter."""

    def __init__(self, window: int = RATE_LIMIT_WINDOW,
                 max_requests: int = RATE_LIMIT_MAX_REQUESTS):
        self._window = window
        self._max = max_requests
        self._lock = asyncio.Lock()
        self._hits: dict[str, list[float]] = {}

    async def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            timestamps = self._hits.get(client_ip, [])
            timestamps = [t for t in timestamps if now - t < self._window]
            if len(timestamps) >= self._max:
                self._hits[client_ip] = timestamps
                return False
            timestamps.append(now)
            self._hits[client_ip] = timestamps
            return True


class APIServer:
    """
    Async HTTPS API server for the H3C-to-SGBox translator.

    Built on aiohttp — runs on the existing asyncio event loop.
    No background thread needed.
    """

    def __init__(self, config: dict, parser: H3CLogParser,
                 formatter: SGBoxFormatter, stats_provider=None):
        self.config = config
        self.parser = parser
        self.formatter = formatter
        self.stats_provider = stats_provider
        self._rate_limiter = _RateLimiter()
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

        # Parse security config once
        security_config = config.get("security", {})
        self._api_key: str = security_config.get("api_key", "")
        self._allowed_networks = self._parse_allowed_ips(
            security_config.get("allowed_ips", "")
        )

    async def start(self):
        """Start the aiohttp API server on the running event loop."""
        server_config = self.config.get("server", {})
        tls_config = self.config.get("tls", {})
        security_config = self.config.get("security", {})

        port = int(server_config.get("api_port", 8443))
        bind_address = server_config.get("bind_address", "127.0.0.1")

        # ── Build aiohttp application ──────────────────────────────
        self._app = web.Application(
            middlewares=[
                self._ip_whitelist_middleware,
                self._auth_middleware,
                self._rate_limit_middleware,
                self._security_headers_middleware,
            ],
            client_max_size=MAX_BODY_SIZE,
        )

        # Register routes
        self._app.router.add_get("/api/v1/health", self._handle_health)
        self._app.router.add_get("/api/v1/stats", self._handle_stats)
        self._app.router.add_post("/api/v1/translate", self._handle_translate)
        self._app.router.add_post("/api/v1/translate/bulk", self._handle_translate_bulk)
        self._app.router.add_route("OPTIONS", "/{path:.*}", self._handle_options)

        # ── TLS setup ──────────────────────────────────────────────
        ssl_ctx = None
        cert_file = tls_config.get("cert_file", "")
        key_file = tls_config.get("key_file", "")
        allow_plaintext = security_config.get("allow_plaintext", "false").lower() == "true"

        if cert_file and key_file:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_ctx.options |= ssl.OP_NO_COMPRESSION
            ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
            logger.info("api.tls_enabled", bind=bind_address, port=port)
        elif allow_plaintext:
            logger.warning(
                "api.tls_disabled",
                bind=bind_address, port=port,
                msg="Running on PLAIN HTTP — insecure, dev only",
            )
        else:
            raise RuntimeError(
                "TLS cert_file/key_file not configured and allow_plaintext is "
                "not enabled. Refusing to start API server over plain HTTP. "
                "Set [security] allow_plaintext = true to override."
            )

        if self._api_key:
            logger.info("api.auth_enabled")
        else:
            logger.warning("api.auth_disabled", msg="No api_key configured")

        if self._allowed_networks:
            logger.info("api.ip_whitelist_enabled",
                        networks=len(self._allowed_networks))

        # ── Start server ───────────────────────────────────────────
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(
            self._runner,
            host=bind_address,
            port=port,
            ssl_context=ssl_ctx,
        )
        await self._site.start()
        protocol = "HTTPS" if ssl_ctx else "HTTP"
        logger.info("api.started", protocol=protocol, bind=bind_address, port=port)

    async def stop(self):
        """Gracefully stop the API server."""
        if self._runner:
            await self._runner.cleanup()
            logger.info("api.stopped")

    # ── Middlewares ─────────────────────────────────────────────────

    @web.middleware
    async def _ip_whitelist_middleware(self, request: web.Request, handler):
        """Enforce IP whitelist on every request."""
        if self._allowed_networks:
            client_ip = request.remote
            try:
                addr = ipaddress.ip_address(client_ip)
                allowed = any(addr in net for net in self._allowed_networks)
            except ValueError:
                allowed = False

            if not allowed:
                logger.warning("api.ip_rejected", client_ip=client_ip)
                raise web.HTTPForbidden(
                    text='{"error": "Forbidden"}',
                    content_type="application/json",
                )
        return await handler(request)

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler):
        """Validate API key from X-API-Key header."""
        if self._api_key:
            provided = request.headers.get("X-API-Key", "")
            if not provided or not hmac.compare_digest(provided, self._api_key):
                logger.warning("api.auth_failure", client_ip=request.remote)
                raise web.HTTPUnauthorized(
                    text='{"error": "Unauthorized"}',
                    content_type="application/json",
                )
        return await handler(request)

    @web.middleware
    async def _rate_limit_middleware(self, request: web.Request, handler):
        """Per-IP rate limiting."""
        client_ip = request.remote
        if not await self._rate_limiter.is_allowed(client_ip):
            logger.warning("api.rate_limited", client_ip=client_ip)
            raise web.HTTPTooManyRequests(
                text='{"error": "Too many requests"}',
                content_type="application/json",
            )
        return await handler(request)

    @web.middleware
    async def _security_headers_middleware(self, request: web.Request, handler):
        """Add security headers to all responses."""
        response = await handler(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        # CORS
        response.headers["Access-Control-Allow-Origin"] = "null"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
        return response

    # ── Route handlers ─────────────────────────────────────────────

    async def _handle_health(self, request: web.Request) -> web.Response:
        """GET /api/v1/health — health check."""
        return web.json_response({
            "status": "healthy",
            "service": "h3c-sgbox-translator",
            "version": "2.0.0",
        })

    async def _handle_stats(self, request: web.Request) -> web.Response:
        """GET /api/v1/stats — translation statistics."""
        stats: dict = {}
        if self.parser:
            stats["parser"] = self.parser.stats
        if self.formatter:
            stats["formatter"] = self.formatter.stats
        if self.stats_provider:
            stats.update(self.stats_provider())
        return web.json_response(stats)

    async def _handle_translate(self, request: web.Request) -> web.Response:
        """POST /api/v1/translate — translate a single H3C log line."""
        try:
            body = await request.text()
        except Exception:
            logger.error("api.read_body_failed", client_ip=request.remote)
            raise web.HTTPBadRequest(
                text='{"error": "Failed to read request body"}',
                content_type="application/json",
            )

        if not body:
            raise web.HTTPBadRequest(
                text='{"error": "Empty request body"}',
                content_type="application/json",
            )

        try:
            import json
            data = json.loads(body)
            raw_line = data.get("raw", "")
        except (ValueError, AttributeError):
            raw_line = body

        if not raw_line:
            raise web.HTTPBadRequest(
                text='{"error": "Missing \'raw\' field or empty body"}',
                content_type="application/json",
            )

        parsed = self.parser.parse(raw_line)
        if not parsed:
            return web.json_response(
                {"error": "Could not parse H3C log line"},
                status=422,
            )

        formatted = self.formatter.format(parsed)
        return web.json_response({
            "translated": formatted,
            "parsed_fields": {k: v for k, v in parsed.items()
                              if not k.startswith("_")},
        })

    async def _handle_translate_bulk(self, request: web.Request) -> web.Response:
        """POST /api/v1/translate/bulk — translate multiple H3C log lines."""
        try:
            data = await request.json()
        except Exception:
            raise web.HTTPBadRequest(
                text='{"error": "Invalid JSON body"}',
                content_type="application/json",
            )

        lines = data.get("lines", [])
        if not lines:
            raise web.HTTPBadRequest(
                text='{"error": "Missing \'lines\' array"}',
                content_type="application/json",
            )

        if len(lines) > MAX_BULK_LINES:
            raise web.HTTPBadRequest(
                text=f'{{"error": "Bulk request exceeds maximum of {MAX_BULK_LINES} lines"}}',
                content_type="application/json",
            )

        results = []
        for line in lines:
            parsed = self.parser.parse(line)
            if parsed:
                formatted = self.formatter.format(parsed)
                results.append({
                    "input": line[:100],
                    "translated": formatted,
                })
            else:
                results.append({
                    "input": line[:100],
                    "translated": None,
                    "error": "unparsable",
                })

        return web.json_response({
            "count": len(results),
            "translated": len([r for r in results if r.get("translated")]),
            "results": results,
        })

    async def _handle_options(self, request: web.Request) -> web.Response:
        """OPTIONS — CORS pre-flight."""
        return web.Response(
            status=204,
            headers={
                "Allow": "GET, POST, HEAD, OPTIONS",
            },
        )

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _parse_allowed_ips(allowed_str: str) -> list | None:
        """Parse comma-separated IP/CIDR list into network objects."""
        if not allowed_str or allowed_str.strip() == "0.0.0.0/0":
            return None

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
                logger.warning("api.invalid_ip_cidr", entry=entry, error=str(e))
        return networks or None
