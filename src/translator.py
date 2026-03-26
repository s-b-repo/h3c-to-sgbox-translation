"""
H3C to SGBox Log Translator — Main Entry Point (v2.0.0)

Orchestrates all components:
  1. Loads .config file
  2. Starts TLS syslog receiver (async, multi-connection)
  3. Starts syslog forwarder to SGBox (async)
  4. Starts aiohttp REST API (async)
  5. Runs as background daemon (optional)

Usage:
    # Foreground mode:
    python3 -m src.translator --config translator.config

    # Daemon mode:
    python3 -m src.translator --config translator.config --daemon

    # CLI mode (translate CSV file):
    python3 -m src.translator --config translator.config --input logs.csv --output translated.log

Dependencies: uvloop, structlog, aiohttp, tenacity, pyOpenSSL
"""

import argparse
import asyncio
import atexit
import configparser
import os
import signal
import sys
from typing import Dict

import structlog
import uvloop

from .parser import H3CLogParser
from .formatter import SGBoxFormatter
from .syslog_receiver import SyslogReceiver
from .syslog_forwarder import SyslogForwarder
from .syslog_output_server import SyslogOutputServer
from .api_server import APIServer
from .encryption import SGBoxEncryption


logger = structlog.get_logger("h3c_translator")


def setup_structlog(config: dict):
    """
    Configure structlog with JSON output in production, human-readable in dev.

    Replaces the old logging.handlers boilerplate.
    """
    log_config = config.get("logging", {})
    level_name = log_config.get("level", "INFO").upper()
    log_file = log_config.get("file", "")

    # Determine if running interactively (dev mode)
    is_dev = sys.stdout.isatty()

    print(f"[LOGGING] Setting up structured logging")
    print(f"[LOGGING]   Level: {level_name}")
    print(f"[LOGGING]   Mode:  {'dev (console)' if is_dev else 'production (JSON)'}")
    print(f"[LOGGING]   File:  {log_file or 'none'}")

    # Shared processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    match is_dev:
        case True:
            renderer = structlog.dev.ConsoleRenderer(colors=True)
            print(f"[LOGGING] ✓ Using colored console renderer")
        case False:
            renderer = structlog.processors.JSONRenderer()
            print(f"[LOGGING] ✓ Using JSON renderer")

    import logging

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.UnicodeDecoder(),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level_name.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Also set up stdlib logging for libraries that use it (aiohttp, etc.)
    import logging
    import logging.handlers

    root = logging.getLogger()
    root.setLevel(getattr(logging, level_name, logging.INFO))

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(console)

    # File handler (if configured)
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            print(f"[LOGGING] Created log directory: {log_dir}")

        max_bytes = int(log_config.get("max_size_mb", 100)) * 1024 * 1024
        backup_count = int(log_config.get("backup_count", 5))

        print(f"[LOGGING] Log file: {log_file}")
        print(f"[LOGGING]   Max size: {max_bytes // (1024*1024)} MB")
        print(f"[LOGGING]   Backups:  {backup_count}")

        file_formatter = structlog.stdlib.ProcessorFormatter(
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                structlog.processors.JSONRenderer(),
            ],
        )

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)
        print(f"[LOGGING] ✓ File handler attached")

    print(f"[LOGGING] ✓ Logging ready\n")


def load_config(config_path: str) -> Dict[str, dict]:
    """Load configuration from .config INI file."""
    print(f"[CONFIG] Loading config from: {config_path}")

    if not os.path.exists(config_path):
        print(f"[CONFIG] ✗ FATAL: Config file not found: {config_path}")
        sys.exit(1)

    cp = configparser.ConfigParser()
    cp.read(config_path)

    config: dict = {}
    for section in cp.sections():
        config[section] = dict(cp.items(section))
        print(f"[CONFIG] ✓ Loaded section [{section}] ({len(config[section])} keys)")

    print(f"[CONFIG] ✓ Config loaded ({len(config)} sections)\n")
    return config


def daemonize(pid_file: str):
    """
    Double-fork daemonize process (Unix only).

    Writes PID to pid_file for systemd/init management.
    """
    print(f"[DAEMON] Daemonizing process...")

    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            print(f"[DAEMON] First fork — parent exiting (child PID: {pid})")
            sys.exit(0)
    except OSError as e:
        print(f"[DAEMON] ✗ First fork FAILED: {e}")
        logger.error("daemon.first_fork_failed", error=str(e))
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0o027)

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            print(f"[DAEMON] Second fork — intermediate exiting (daemon PID: {pid})")
            sys.exit(0)
    except OSError as e:
        print(f"[DAEMON] ✗ Second fork FAILED: {e}")
        logger.error("daemon.second_fork_failed", error=str(e))
        sys.exit(1)

    # Redirect stdio
    sys.stdout.flush()
    sys.stderr.flush()

    devnull_fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull_fd, sys.stdin.fileno())
    os.dup2(devnull_fd, sys.stdout.fileno())
    os.dup2(devnull_fd, sys.stderr.fileno())
    os.close(devnull_fd)

    # Write PID file
    pid = os.getpid()
    pid_dir = os.path.dirname(pid_file)
    if pid_dir and not os.path.exists(pid_dir):
        os.makedirs(pid_dir, exist_ok=True)
    with open(pid_file, "w") as f:
        f.write(str(pid))

    def _cleanup_pid():
        try:
            os.remove(pid_file)
        except OSError:
            pass
    atexit.register(_cleanup_pid)

    logger.info("daemon.started", pid=pid, pid_file=pid_file)


def run_cli_mode(config: dict, input_path: str, output_path: str):
    """
    CLI mode: read a CSV/log file and translate to SGBox format.

    Useful for testing and batch processing.
    """
    print(f"\n{'='*60}")
    print(f"[CLI] Starting CLI translation mode")
    print(f"[CLI]   Input:  {input_path}")
    print(f"[CLI]   Output: {output_path}")
    print(f"{'='*60}\n")

    parser = H3CLogParser()
    fmt_config = config.get("output", {})
    formatter = SGBoxFormatter(
        output_format=fmt_config.get("format", "cef"),
        include_hostname=fmt_config.get("include_hostname", "true").lower() == "true",
        include_timestamp=fmt_config.get("include_timestamp", "true").lower() == "true",
    )

    is_csv = input_path.lower().endswith(".csv")
    print(f"[CLI] Input format: {'CSV' if is_csv else 'raw syslog'}")

    translated_count = 0
    total_count = 0

    out_file = open(output_path, "w") if output_path != "-" else sys.stdout

    try:
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total_count += 1
                line = line.strip()
                if not line:
                    continue

                match is_csv:
                    case True:
                        parsed = parser.parse_csv_line(line)
                    case False:
                        parsed = parser.parse(line)

                if parsed:
                    if formatter.output_format == "cef":
                        formatted = formatter.format_cef(parsed)
                    else:
                        formatted = formatter.format(parsed)
                    if formatted:
                        out_file.write(formatted + "\n")
                        translated_count += 1
                        if translated_count % 100 == 0:
                            print(f"[CLI] Progress: {translated_count} translated / {total_count} total")

    finally:
        if out_file != sys.stdout:
            out_file.close()

    logger.info("cli.complete",
                translated=translated_count, total=total_count)
    print(f"\n{'='*60}")
    print(f"=== Translation Summary ===")
    print(f"  Input:      {input_path}")
    print(f"  Output:     {output_path}")
    print(f"  Total:      {total_count} lines")
    print(f"  Translated: {translated_count} lines")
    print(f"  Failed:     {total_count - translated_count} lines")
    print(f"  Parser stats:    {parser.stats}")
    print(f"  Formatter stats: {formatter.stats}")
    print(f"{'='*60}")


async def probe_sgbox_connectivity(sgbox_config: dict, tls_config: dict) -> dict:
    """
    Test connectivity to SGBox via UDP, TCP, and TLS at startup.

    Returns dict: {'host:port': {'udp': bool, 'tcp': bool, 'tls': bool}}
    Server should continue if at least one protocol works for any host.
    """
    import ssl as _ssl
    import socket

    raw_hosts = sgbox_config.get("host", "")
    hosts = [h.strip() for h in raw_hosts.split(",") if h.strip()]

    # BUG-08: Safely parse ports with fallback
    try:
        port = int(sgbox_config.get("port", "514"))
    except (ValueError, TypeError):
        port = 514
        print(f"[PROBE] ⚠ Invalid port config, defaulting to {port}")

    # BUG-05: TLS uses separate port config key, default 6514
    try:
        tls_port = int(sgbox_config.get("tls_port", "6514"))
    except (ValueError, TypeError):
        tls_port = 6514

    if not hosts:
        print(f"[PROBE] ⚠ No SGBox hosts configured — skipping connectivity check")
        return {}

    print(f"\n{'─'*60}")
    print(f"[PROBE] SGBox Connectivity Check")
    print(f"[PROBE] Syslog port: {port}  |  TLS port: {tls_port}")
    print(f"{'─'*60}")

    results: dict[str, dict[str, bool]] = {}
    any_working = False

    for host in hosts:
        host_results: dict[str, bool] = {}
        target = f"{host}:{port}"
        print(f"\n[PROBE] Testing {host}...")

        # BUG-07: Set global default timeout to limit DNS resolution
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)

        # ── UDP Probe (BUG-06: use try/finally for socket cleanup) ──
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            test_msg = b"<134>h3c-translator: connectivity-probe"
            sock.sendto(test_msg, (host, port))
            host_results["udp"] = True
            any_working = True
            print(f"[PROBE]   ✓ UDP/{port}  — packet sent (connectionless, no ACK expected)")
        except Exception as e:
            host_results["udp"] = False
            print(f"[PROBE]   ✗ UDP/{port}  — {e}")
        finally:
            if sock:
                sock.close()

        # ── TCP Probe (BUG-06: use try/finally) ──────────────────────
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            host_results["tcp"] = True
            any_working = True
            print(f"[PROBE]   ✓ TCP/{port}  — connection established")
        except Exception as e:
            host_results["tcp"] = False
            print(f"[PROBE]   ✗ TCP/{port}  — {e}")
        finally:
            if sock:
                sock.close()

        # ── TLS Probe (BUG-06: use try/finally) ──────────────────────
        sock = None
        tls_sock = None
        try:
            context = _ssl.create_default_context()
            ca_file = tls_config.get("ca_file", "")
            if ca_file and os.path.exists(ca_file):
                context.load_verify_locations(ca_file)
                print(f"[PROBE]     (using CA bundle: {ca_file})")
            else:
                context.check_hostname = False
                context.verify_mode = _ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            tls_sock = context.wrap_socket(sock, server_hostname=host)
            tls_sock.connect((host, tls_port))
            peer_cert = tls_sock.getpeercert()
            tls_version = tls_sock.version()
            host_results["tls"] = True
            any_working = True
            cn_info = ""
            if peer_cert:
                try:
                    cn_info = f" (CN={peer_cert['subject'][0][0][1]})"
                except (KeyError, IndexError):
                    pass
            print(f"[PROBE]   ✓ TLS/{tls_port} — {tls_version} handshake OK{cn_info}")
        except Exception as e:
            host_results["tls"] = False
            print(f"[PROBE]   ✗ TLS/{tls_port} — {e}")
        finally:
            if tls_sock:
                tls_sock.close()
            elif sock:
                sock.close()

        # Restore default timeout
        socket.setdefaulttimeout(old_timeout)

        results[target] = host_results

        # Summary for this host
        working = [p for p, ok in host_results.items() if ok]
        failed = [p for p, ok in host_results.items() if not ok]
        if working:
            print(f"[PROBE]   → {host}: {', '.join(working)} working")
        if failed:
            print(f"[PROBE]   → {host}: {', '.join(failed)} FAILED")

    # ── Overall Summary ───────────────────────────────────────────
    print(f"\n{'─'*60}")
    if any_working:
        print(f"[PROBE] ✓ At least one protocol works — server will continue")
    else:
        print(f"[PROBE] ✗ WARNING: ALL connectivity checks FAILED!")
        print(f"[PROBE]   Server will start anyway, but logs may not reach SGBox.")
        print(f"[PROBE]   Check: firewall rules, SGBox service status, host/port config")
    print(f"{'─'*60}\n")

    return results


async def run_server(config: dict):
    """
    Run the translator server (fully async).

    Pipeline: syslog receiver → parser → formatter → output server / forwarder
    """
    print(f"\n{'='*60}")
    print(f"[SERVER] Starting H3C-to-SGBox Translator Server v2.0.0")
    print(f"{'='*60}\n")

    # ── Startup: SGBox connectivity probe ─────────────────────────
    sgbox_config = config.get("sgbox", {})
    tls_config = config.get("tls", {})
    mode = sgbox_config.get("mode", "pull").lower()

    if mode == "push":
        await probe_sgbox_connectivity(sgbox_config, tls_config)

    # ── Initialize components ──────────────────────────────────────
    print(f"[SERVER] Initializing components...")
    parser = H3CLogParser()

    fmt_config = config.get("output", {})
    formatter = SGBoxFormatter(
        output_format=fmt_config.get("format", "cef"),
        include_hostname=fmt_config.get("include_hostname", "true").lower() == "true",
        include_timestamp=fmt_config.get("include_timestamp", "true").lower() == "true",
    )

    sgbox_config = config.get("sgbox", {})
    mode = sgbox_config.get("mode", "pull").lower()
    print(f"[SERVER] Output mode: {mode}")

    # ── Initialize GPG encryption ─────────────────────────────────
    print(f"[SERVER] Initializing encryption module...")
    encryption = SGBoxEncryption(config)

    # ── Choose output mode ─────────────────────────────────────────
    output_server = None
    forwarders: list[SyslogForwarder] = []  # Multi-destination push support

    match mode:
        case "push":
            # Support comma-separated hosts for multi-destination push
            raw_hosts = sgbox_config.get("host", "")
            hosts = [h.strip() for h in raw_hosts.split(",") if h.strip()]
            if not hosts:
                print(f"[SERVER] ✗ Push mode but no hosts configured!")
                hosts = ["127.0.0.1"]

            for host in hosts:
                # Create per-destination config override
                dest_config = dict(config)
                dest_sgbox = dict(sgbox_config)
                dest_sgbox["host"] = host
                dest_config["sgbox"] = dest_sgbox
                fwd = SyslogForwarder(dest_config)
                forwarders.append(fwd)
                print(f"[SERVER] ✓ Forwarder created for {host}:{dest_sgbox.get('port', '6154')}")

            print(f"[SERVER] {len(forwarders)} push destination(s) configured")
        case "pull":
            print(f"[SERVER] Mode=pull → initializing SyslogOutputServer")
            output_server = SyslogOutputServer(config)
        case _:
            print(f"[SERVER] ✗ Unknown mode '{mode}', defaulting to pull")
            output_server = SyslogOutputServer(config)

    # Concurrency limiter for parallel message processing
    _pipeline_semaphore = asyncio.Semaphore(1000)

    # ── Message handler ────────────────────────────────────────────
    async def handle_message(message: str, client_ip: str):
        """
        Parse, format, encrypt, and fan-out a single H3C log message.

        Runs as a concurrent task — multiple sources processed in parallel.
        A semaphore caps in-flight work to prevent memory exhaustion.
        """
        async with _pipeline_semaphore:
            print(f"[PIPELINE] Processing message from {client_ip}: {message[:120]}...")

            # CPU-bound parsing runs in the calling coroutine (offloaded by
            # the receiver/API to a thread pool when needed)
            parsed = parser.parse(message)
            if not parsed:
                print(f"[PIPELINE] ✗ Parser returned None — message could not be parsed")
                return

            print(f"[PIPELINE] ✓ Parsed: proto={parsed.get('proto', '?')} "
                  f"src={parsed.get('src', '?')} dst={parsed.get('dst', '?')} "
                  f"action={parsed.get('action', '?')}")

            # Format: use CEF (SGBox native) or legacy key=value
            if formatter.output_format == "cef":
                syslog_msg = formatter.format_syslog_cef(
                    parsed,
                    facility=sgbox_config.get("facility", "local0"),
                    severity=sgbox_config.get("severity", "info"),
                )
            else:
                syslog_msg = formatter.format_syslog(
                    parsed,
                    facility=sgbox_config.get("facility", "local0"),
                    severity=sgbox_config.get("severity", "info"),
                )

            if not syslog_msg:
                print(f"[PIPELINE] ✗ Formatter returned None — missing required fields")
                return

            print(f"[PIPELINE] ✓ Formatted syslog: {syslog_msg[:120]}...")

            # Encrypt at rest if SGBox encryption is enabled
            if encryption.is_enabled:
                print(f"[PIPELINE] Encrypting message...")
                syslog_msg = await encryption.encrypt(syslog_msg)
                print(f"[PIPELINE] ✓ Encrypted ({len(syslog_msg)} bytes)")

            # Fan-out: send to ALL destinations in parallel
            if output_server:
                print(f"[PIPELINE] Sending to output server (pull mode)...")
                await output_server.send(syslog_msg)
            elif forwarders:
                if len(forwarders) == 1:
                    await forwarders[0].send(syslog_msg)
                else:
                    # Parallel push to all destinations
                    results = await asyncio.gather(
                        *[fwd.send(syslog_msg) for fwd in forwarders],
                        return_exceptions=True,
                    )
                    for i, result in enumerate(results):
                        if isinstance(result, Exception):
                            print(f"[PIPELINE] ✗ Forwarder {i} delivery failed: {result}")

            print(f"[PIPELINE] ✓ Message delivered successfully")

    # ── Start syslog receiver ──────────────────────────────────────
    print(f"\n[SERVER] Starting syslog receiver...")
    receiver = SyslogReceiver(config, handle_message)
    await receiver.start()

    # ── Start output server or connect forwarder ───────────────────
    match mode:
        case "pull":
            if output_server:
                print(f"\n[SERVER] Starting output server (pull mode)...")
                await output_server.start()
        case "push":
            # Connect ALL forwarders in parallel
            async def _init_forwarders():
                connect_tasks = []
                for fwd in forwarders:
                    connect_tasks.append(fwd.connect())
                results = await asyncio.gather(*connect_tasks, return_exceptions=True)
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        print(f"[SERVER] ✗ Forwarder {i} initial connect FAILED: {result}")
                        print(f"[SERVER]   Will retry on first message")
                        logger.error("forwarder.initial_connect_failed",
                                      index=i, error=str(result))
                    else:
                        print(f"[SERVER] ✓ Forwarder {i} connected")
            asyncio.create_task(_init_forwarders())

    # ── Start async API server ─────────────────────────────────────
    def get_stats():
        stats = {"receiver": receiver.stats}
        if output_server:
            stats["output_server"] = output_server.stats
        for i, fwd in enumerate(forwarders):
            stats[f"forwarder_{i}"] = fwd.stats
        return stats

    print(f"\n[SERVER] Starting API server...")
    api = APIServer(config, parser, formatter, stats_provider=get_stats)
    try:
        await api.start()
        print(f"[SERVER] ✓ API server started")
    except Exception as e:
        print(f"[SERVER] ✗ API server FAILED to start: {e}")
        logger.warning("api.start_failed", error=str(e))

    # ── Wait for shutdown signal ───────────────────────────────────
    shutdown_event = asyncio.Event()

    def signal_handler():
        print(f"\n[SERVER] Shutdown signal received!")
        logger.info("shutdown.signal_received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    output_port = sgbox_config.get("output_port", sgbox_config.get("port", "1514"))

    print(f"\n{'='*60}")
    print(f"[SERVER] ✓ TRANSLATOR RUNNING")
    print(f"[SERVER]   UDP port:    {config.get('server', {}).get('syslog_udp_port', '514')}")
    print(f"[SERVER]   TCP port:    {config.get('server', {}).get('syslog_tcp_port', '514')}")
    print(f"[SERVER]   TLS port:    {config.get('server', {}).get('syslog_tls_port', '6514')}")
    print(f"[SERVER]   API port:    {config.get('server', {}).get('api_port', '8443')}")
    print(f"[SERVER]   Output mode: {mode}")
    print(f"[SERVER]   Output port: {output_port}")
    print(f"[SERVER]   Encryption:  {'enabled' if encryption.is_enabled else 'disabled'}")
    print(f"{'='*60}")
    print(f"[SERVER] Waiting for syslog messages... (Ctrl+C to stop)\n")

    logger.info("translator.running",
                syslog_udp_port=config.get("server", {}).get("syslog_udp_port", "514"),
                syslog_tls_port=config.get("server", {}).get("syslog_tls_port", "6514"),
                syslog_tcp_port=config.get("server", {}).get("syslog_tcp_port", "514"),
                api_port=config.get("server", {}).get("api_port", "8443"),
                output_mode=mode,
                output_port=output_port)

    await shutdown_event.wait()

    # ── Cleanup ────────────────────────────────────────────────────
    print(f"\n[SERVER] Shutting down...")
    logger.info("translator.shutting_down")
    # Flush remaining failed log buffer
    parser.flush_remaining()
    await receiver.stop()
    await api.stop()
    if output_server:
        await output_server.stop()
    for fwd in forwarders:
        await fwd.close()

    # Final stats
    print(f"\n{'='*60}")
    print(f"[SERVER] Final Statistics:")
    print(f"  Parser:    {parser.stats}")
    print(f"  Formatter: {formatter.stats}")
    print(f"  Receiver:  {receiver.stats}")
    print(f"{'='*60}")

    logger.info("translator.final_stats",
                parser=parser.stats,
                formatter=formatter.stats,
                receiver=receiver.stats)


def main():
    """Entry point."""
    print(f"\n{'='*60}")
    print(f"  H3C-to-SGBox Secure Log Translator v2.0.0")
    print(f"{'='*60}\n")

    arg_parser = argparse.ArgumentParser(
        description="H3C to SGBox Secure Log Translator (v2.0.0 — async + Debian 13)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Run as server (foreground):
  python3 -m src.translator --config translator.config

  # Run as daemon (background):
  python3 -m src.translator --config translator.config --daemon

  # Translate a CSV file:
  python3 -m src.translator --config translator.config \\
      --input Raw_logs.csv --output translated.log

  # Translate to stdout:
  python3 -m src.translator --config translator.config \\
      --input Raw_logs.csv --output -
        """,
    )
    arg_parser.add_argument(
        "--config", "-c",
        default="translator.config",
        help="Path to .config file (default: translator.config)",
    )
    arg_parser.add_argument(
        "--daemon", "-d",
        action="store_true",
        help="Run as background daemon",
    )
    arg_parser.add_argument(
        "--input", "-i",
        help="Input file for CLI mode (CSV or raw syslog)",
    )
    arg_parser.add_argument(
        "--output", "-o",
        help="Output file for CLI mode (use '-' for stdout)",
    )

    args = arg_parser.parse_args()

    # Load config
    config = load_config(args.config)

    # Setup structlog
    setup_structlog(config)

    print(f"[MAIN] Starting translator v2.0.0")
    print(f"[MAIN] Config: {args.config}")
    logger.info("translator.starting", version="2.0.0")
    logger.info("config.loaded", path=args.config)

    # CLI mode
    if args.input:
        output = args.output or args.input.rsplit(".", 1)[0] + "_translated.log"
        print(f"[MAIN] Running in CLI mode")
        run_cli_mode(config, args.input, output)
        return

    # Daemon mode
    if args.daemon:
        pid_file = config.get("server", {}).get(
            "pid_file", "/var/run/h3c-translator.pid"
        )
        print(f"[MAIN] Running in daemon mode (PID file: {pid_file})")
        daemonize(pid_file)
    else:
        print(f"[MAIN] Running in foreground mode")

    # Server mode — use uvloop for high-performance async
    print(f"[MAIN] Using uvloop for async event loop")
    uvloop.run(run_server(config))


if __name__ == "__main__":
    main()
