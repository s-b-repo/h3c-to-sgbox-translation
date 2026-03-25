"""
Async HTTPS REST API Server (aiohttp)

Provides HTTP API endpoints for:
  - POST /api/v1/translate      — translate a single H3C log line
  - POST /api/v1/translate/bulk — translate multiple log lines
  - GET  /api/v1/health         — health check
  - GET  /api/v1/stats          — translation statistics

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
import json
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
MAX_SINGLE_BODY = 64 * 1024    # 64 KB for single translate
RATE_LIMIT_WINDOW = 60         # seconds
RATE_LIMIT_MAX_REQUESTS = 120  # per IP per window
RATE_LIMIT_MAX_IPS = 10_000    # max tracked IPs (OOM prevention)


class _RateLimiter:
    """Async-safe per-IP sliding-window rate limiter with OOM protection."""

    def __init__(self, window: int = RATE_LIMIT_WINDOW,
                 max_requests: int = RATE_LIMIT_MAX_REQUESTS,
                 max_ips: int = RATE_LIMIT_MAX_IPS):
        self._window = window
        self._max = max_requests
        self._max_ips = max_ips
        self._lock = asyncio.Lock()
        self._hits: dict[str, list[float]] = {}

    async def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            # Evict stale IPs when the table exceeds the cap
            if len(self._hits) > self._max_ips:
                self._evict_stale(now)

            timestamps = self._hits.get(client_ip, [])
            timestamps = [t for t in timestamps if now - t < self._window]
            if len(timestamps) >= self._max:
                self._hits[client_ip] = timestamps
                print(f"[API] ✗ Rate limit hit for {client_ip} ({len(timestamps)}/{self._max})")
                return False
            timestamps.append(now)
            self._hits[client_ip] = timestamps
            return True

    def _evict_stale(self, now: float):
        """Remove IPs whose timestamps have all expired (called under lock)."""
        stale_keys = [
            ip for ip, ts in self._hits.items()
            if not ts or all(now - t >= self._window for t in ts)
        ]
        for key in stale_keys:
            del self._hits[key]
        if stale_keys:
            print(f"[API] Evicted {len(stale_keys)} stale IPs from rate limiter")


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
        raw_api_key: str = security_config.get("api_key", "")

        # CRIT-01: Block startup on default/empty API key
        _INSECURE_KEYS = ("", "CHANGE_ME_GENERATE_A_SECURE_KEY", "changeme", "test")
        if raw_api_key in _INSECURE_KEYS:
            print(f"[API] ✗ FATAL: API key is not configured or uses a default placeholder!")
            print(f"[API]   Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"")
            print(f"[API]   Then set [security] api_key = <your key> in translator.config")
            raise RuntimeError(
                "Insecure API key detected. Set a strong [security] api_key in config. "
                "Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        self._api_key: str = raw_api_key

        self._allowed_networks = self._parse_allowed_ips(
            security_config.get("allowed_ips", "")
        )
        self._trusted_proxies = self._parse_allowed_ips(
            security_config.get("trusted_proxies", "")
        )

        print(f"[API] Initialized")
        print(f"[API]   API key:   configured ({len(self._api_key)} chars)")
        print(f"[API]   Whitelist: {len(self._allowed_networks) if self._allowed_networks else 'disabled'} network(s)")

    async def start(self):
        """Start the aiohttp API server on the running event loop."""
        server_config = self.config.get("server", {})
        tls_config = self.config.get("tls", {})
        security_config = self.config.get("security", {})

        port = int(server_config.get("api_port", 8443))
        bind_address = server_config.get("bind_address", "127.0.0.1")

        print(f"\n[API] Starting API server on {bind_address}:{port}...")

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
        print(f"[API] ✓ Routes registered: /health, /stats, /translate, /translate/bulk")

        # ── TLS setup ──────────────────────────────────────────────
        ssl_ctx = None
        cert_file = tls_config.get("cert_file", "")
        key_file = tls_config.get("key_file", "")
        allow_plaintext = security_config.get("allow_plaintext", "false").lower() == "true"

        match (bool(cert_file and key_file), allow_plaintext):
            case (True, _):
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ssl_ctx.options |= ssl.OP_NO_COMPRESSION
                ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
                print(f"[API] ✓ TLS enabled")
                print(f"[API]   Cert: {cert_file}")
                print(f"[API]   Key:  {key_file}")
                logger.info("api.tls_enabled", bind=bind_address, port=port)
            case (False, True):
                print(f"[API] ⚠ Running on PLAIN HTTP — insecure, dev only!")
                logger.warning(
                    "api.tls_disabled",
                    bind=bind_address, port=port,
                    msg="Running on PLAIN HTTP — insecure, dev only",
                )
            case (False, False):
                print(f"[API] ✗ FATAL: No TLS certs and allow_plaintext=false")
                print(f"[API]   Set [security] allow_plaintext = true to override")
                raise RuntimeError(
                    "TLS cert_file/key_file not configured and allow_plaintext is "
                    "not enabled. Refusing to start API server over plain HTTP. "
                    "Set [security] allow_plaintext = true to override."
                )

        match bool(self._api_key):
            case True:
                print(f"[API] ✓ API key authentication enabled")
                logger.info("api.auth_enabled")
            case False:
                print(f"[API] ⚠ No api_key configured — API is unauthenticated!")
                logger.warning("api.auth_disabled", msg="No api_key configured")

        if self._allowed_networks:
            print(f"[API] ✓ IP whitelist enabled ({len(self._allowed_networks)} networks)")
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
        print(f"[API] ✓ API server STARTED on {protocol}://{bind_address}:{port}")
        logger.info("api.started", protocol=protocol, bind=bind_address, port=port)

    async def stop(self):
        """Gracefully stop the API server."""
        print(f"[API] Stopping API server...")
        if self._runner:
            await self._runner.cleanup()
            print(f"[API] ✓ API server stopped")
            logger.info("api.stopped")

    # ── Middlewares ─────────────────────────────────────────────────

    def _get_client_ip(self, request: web.Request) -> str:
        """Resolve the real client IP, respecting X-Forwarded-For behind trusted proxies."""
        peer_ip = request.remote
        if self._trusted_proxies:
            try:
                peer_addr = ipaddress.ip_address(peer_ip)
                is_trusted = any(peer_addr in net for net in self._trusted_proxies)
            except ValueError:
                is_trusted = False

            match is_trusted:
                case True:
                    xff = request.headers.get("X-Forwarded-For", "")
                    if xff:
                        forwarded_ip = xff.split(",")[0].strip()
                        try:
                            ipaddress.ip_address(forwarded_ip)
                            print(f"[API] Trusted proxy {peer_ip}, using forwarded IP: {forwarded_ip}")
                            return forwarded_ip
                        except ValueError:
                            print(f"[API] ✗ Invalid X-Forwarded-For IP: {forwarded_ip}")
                case False:
                    pass
        return peer_ip

    @web.middleware
    async def _ip_whitelist_middleware(self, request: web.Request, handler):
        """Enforce IP whitelist on every request."""
        if self._allowed_networks:
            client_ip = self._get_client_ip(request)
            try:
                addr = ipaddress.ip_address(client_ip)
                allowed = any(addr in net for net in self._allowed_networks)
            except ValueError:
                allowed = False

            match allowed:
                case False:
                    print(f"[API] ✗ IP REJECTED: {client_ip} (not in whitelist)")
                    logger.warning("api.ip_rejected", client_ip=client_ip)
                    raise web.HTTPForbidden(
                        text='{"error": "Forbidden"}',
                        content_type="application/json",
                    )
                case True:
                    pass
        return await handler(request)

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler):
        """Validate API key from X-API-Key header (timing-safe)."""
        if self._api_key:
            provided = request.headers.get("X-API-Key", "")
            # MED-01: Always call compare_digest to prevent timing side-channel
            # Pad empty input to same length to avoid short-circuit leak
            if not hmac.compare_digest(
                provided.encode("utf-8") if provided else b"\x00",
                self._api_key.encode("utf-8"),
            ):
                client_ip = self._get_client_ip(request)
                print(f"[API] ✗ AUTH FAILED from {client_ip} on {request.method} {request.path}")
                logger.warning("api.auth_failure", client_ip=client_ip)
                raise web.HTTPUnauthorized(
                    text='{"error": "Unauthorized"}',
                    content_type="application/json",
                )
        return await handler(request)

    @web.middleware
    async def _rate_limit_middleware(self, request: web.Request, handler):
        """Per-IP rate limiting."""
        client_ip = self._get_client_ip(request)
        if not await self._rate_limiter.is_allowed(client_ip):
            print(f"[API] ✗ RATE LIMITED: {client_ip}")
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
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
        return response

    # ── Route handlers ─────────────────────────────────────────────

    async def _handle_health(self, request: web.Request) -> web.Response:
        """GET /api/v1/health — health check."""
        print(f"[API] Health check from {self._get_client_ip(request)}")
        return web.json_response({
            "status": "healthy",
            "service": "h3c-sgbox-translator",
            "version": "2.0.0",
        })

    async def _handle_stats(self, request: web.Request) -> web.Response:
        """GET /api/v1/stats — translation statistics."""
        client_ip = self._get_client_ip(request)
        print(f"[API] Stats request from {client_ip}")
        stats: dict = {}
        if self.parser:
            stats["parser"] = self.parser.stats
        if self.formatter:
            stats["formatter"] = self.formatter.stats
        if self.stats_provider:
            stats.update(self.stats_provider())
        print(f"[API] ✓ Returning stats: {stats}")
        return web.json_response(stats)

    async def _handle_translate(self, request: web.Request) -> web.Response:
        """POST /api/v1/translate — translate a single H3C log line."""
        client_ip = self._get_client_ip(request)
        print(f"[API] Translate request from {client_ip}")

        # MED-03: Check content-length before reading body into memory
        content_length = request.content_length
        if content_length is not None and content_length > MAX_SINGLE_BODY:
            print(f"[API] ✗ Content-Length too large: {content_length} > {MAX_SINGLE_BODY}")
            raise web.HTTPRequestEntityTooLarge(
                max_size=MAX_SINGLE_BODY,
                actual_size=content_length,
                text='{"error": "Request body too large for single translate"}',
            )

        try:
            # Read with size limit to prevent memory exhaustion
            raw_bytes = await request.content.read(MAX_SINGLE_BODY + 1)
            if len(raw_bytes) > MAX_SINGLE_BODY:
                print(f"[API] ✗ Body too large: >{MAX_SINGLE_BODY}")
                raise web.HTTPRequestEntityTooLarge(
                    max_size=MAX_SINGLE_BODY,
                    actual_size=len(raw_bytes),
                    text='{"error": "Request body too large for single translate"}',
                )
            body = raw_bytes.decode("utf-8", errors="replace")
        except web.HTTPRequestEntityTooLarge:
            raise
        except Exception as e:
            print(f"[API] ✗ Failed to read request body: {e}")
            logger.error("api.read_body_failed", client_ip=client_ip)
            raise web.HTTPBadRequest(
                text='{"error": "Failed to read request body"}',
                content_type="application/json",
            )

        if not body:
            print(f"[API] ✗ Empty request body")
            raise web.HTTPBadRequest(
                text='{"error": "Empty request body"}',
                content_type="application/json",
            )

        try:
            data = json.loads(body)
            raw_line = data.get("raw", "")
        except (ValueError, AttributeError):
            raw_line = body

        if not raw_line:
            print(f"[API] ✗ Missing 'raw' field or empty body")
            raise web.HTTPBadRequest(
                text='{"error": "Missing \'raw\' field or empty body"}',
                content_type="application/json",
            )

        print(f"[API] Parsing: {raw_line[:100]}...")

        # Offload CPU-bound parsing/formatting to thread pool
        loop = asyncio.get_running_loop()
        parsed = await loop.run_in_executor(
            None, self.parser.parse, raw_line
        )
        if not parsed:
            print(f"[API] ✗ Could not parse H3C log line")
            return web.json_response(
                {"error": "Could not parse H3C log line"},
                status=422,
            )

        formatted = await loop.run_in_executor(
            None, self.formatter.format, parsed
        )
        print(f"[API] ✓ Translated: {formatted[:100] if formatted else 'None'}...")
        return web.json_response({
            "translated": formatted,
            "parsed_fields": {k: v for k, v in parsed.items()
                              if not k.startswith("_")},
        })

    async def _handle_translate_bulk(self, request: web.Request) -> web.Response:
        """POST /api/v1/translate/bulk — translate multiple H3C log lines."""
        client_ip = self._get_client_ip(request)
        print(f"[API] Bulk translate request from {client_ip}")

        try:
            data = await request.json()
        except Exception as e:
            print(f"[API] ✗ Invalid JSON body: {e}")
            raise web.HTTPBadRequest(
                text='{"error": "Invalid JSON body"}',
                content_type="application/json",
            )

        lines = data.get("lines", [])
        if not lines:
            print(f"[API] ✗ Missing 'lines' array")
            raise web.HTTPBadRequest(
                text='{"error": "Missing \'lines\' array"}',
                content_type="application/json",
            )

        if len(lines) > MAX_BULK_LINES:
            print(f"[API] ✗ Bulk request too large: {len(lines)} > {MAX_BULK_LINES}")
            raise web.HTTPBadRequest(
                text=f'{{"error": "Bulk request exceeds maximum of {MAX_BULK_LINES} lines"}}',
                content_type="application/json",
            )

        print(f"[API] Processing {len(lines)} lines...")

        # Offload CPU-bound bulk translation to thread pool
        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, self._translate_bulk_sync, lines
        )

        translated_count = len([r for r in results if r.get("translated")])
        print(f"[API] ✓ Bulk complete: {translated_count}/{len(lines)} translated")

        return web.json_response({
            "count": len(results),
            "translated": translated_count,
            "results": results,
        })

    def _translate_bulk_sync(self, lines: list) -> list:
        """Synchronous bulk translation (runs in executor thread)."""
        results = []
        for i, line in enumerate(lines):
            parsed = self.parser.parse(line)
            match parsed:
                case None:
                    results.append({
                        "input": line[:100],
                        "translated": None,
                        "error": "unparsable",
                    })
                    print(f"[API] Bulk [{i+1}/{len(lines)}] ✗ unparsable")
                case _:
                    formatted = self.formatter.format(parsed)
                    results.append({
                        "input": line[:100],
                        "translated": formatted,
                    })
                    print(f"[API] Bulk [{i+1}/{len(lines)}] ✓ translated")
        return results

    async def _handle_options(self, request: web.Request) -> web.Response:
        """OPTIONS — CORS pre-flight."""
        print(f"[API] OPTIONS pre-flight from {self._get_client_ip(request)}")
        return web.Response(
            status=204,
            headers={
                "Allow": "GET, POST, HEAD, OPTIONS",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
                "Access-Control-Max-Age": "86400",
            },
        )

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _parse_allowed_ips(allowed_str: str) -> list | None:
        """Parse comma-separated IP list into network objects."""
        if not allowed_str or allowed_str.strip() in ("0.0.0.0", "0.0.0.0/0"):
            print(f"[API] Allowed IPs: ALL (no filtering)")
            return None

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
                print(f"[API] ✓ Allowed network: {entry}")
            except ValueError as e:
                print(f"[API] ✗ Invalid IP/CIDR: {entry} — {e}")
                logger.warning("api.invalid_ip_cidr", entry=entry, error=str(e))
        return networks or None
