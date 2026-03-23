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

    # Shared processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if is_dev:
        # Human-readable colored output for development
        renderer = structlog.dev.ConsoleRenderer(colors=True)
    else:
        # JSON output for production / journald
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.UnicodeDecoder(),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            structlog.processors._NAME_TO_LEVEL.get(level_name.lower(), 20)
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

        max_bytes = int(log_config.get("max_size_mb", 100)) * 1024 * 1024
        backup_count = int(log_config.get("backup_count", 5))

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(file_handler)


def load_config(config_path: str) -> Dict[str, dict]:
    """Load configuration from .config INI file."""
    if not os.path.exists(config_path):
        print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    cp = configparser.ConfigParser()
    cp.read(config_path)

    config: dict = {}
    for section in cp.sections():
        config[section] = dict(cp.items(section))
    return config


def daemonize(pid_file: str):
    """
    Double-fork daemonize process (Unix only).

    Writes PID to pid_file for systemd/init management.
    """
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logger.error("daemon.first_fork_failed", error=str(e))
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0o027)

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        logger.error("daemon.second_fork_failed", error=str(e))
        sys.exit(1)

    # Redirect stdio
    sys.stdout.flush()
    sys.stderr.flush()

    devnull_r = open(os.devnull, "r")
    devnull_w = open(os.devnull, "w")
    os.dup2(devnull_r.fileno(), sys.stdin.fileno())
    os.dup2(devnull_w.fileno(), sys.stdout.fileno())
    os.dup2(devnull_w.fileno(), sys.stderr.fileno())
    devnull_r.close()
    devnull_w.close()

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
    parser = H3CLogParser()
    fmt_config = config.get("output", {})
    formatter = SGBoxFormatter(
        output_format=fmt_config.get("format", "extended"),
        include_hostname=fmt_config.get("include_hostname", "true").lower() == "true",
        include_timestamp=fmt_config.get("include_timestamp", "true").lower() == "true",
    )

    is_csv = input_path.lower().endswith(".csv")

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

                if is_csv:
                    parsed = parser.parse_csv_line(line)
                else:
                    parsed = parser.parse(line)

                if parsed:
                    formatted = formatter.format(parsed)
                    if formatted:
                        out_file.write(formatted + "\n")
                        translated_count += 1

    finally:
        if out_file != sys.stdout:
            out_file.close()

    logger.info("cli.complete",
                translated=translated_count, total=total_count)
    print(f"\n=== Translation Summary ===")
    print(f"Input:      {input_path}")
    print(f"Output:     {output_path}")
    print(f"Total:      {total_count} lines")
    print(f"Translated: {translated_count} lines")
    print(f"Failed:     {total_count - translated_count} lines")
    print(f"Parser stats:    {parser.stats}")
    print(f"Formatter stats: {formatter.stats}")


async def run_server(config: dict):
    """
    Run the translator server (fully async).

    Pipeline: syslog receiver → parser → formatter → output server / forwarder
    """
    # ── Initialize components ──────────────────────────────────────
    parser = H3CLogParser()

    fmt_config = config.get("output", {})
    formatter = SGBoxFormatter(
        output_format=fmt_config.get("format", "extended"),
        include_hostname=fmt_config.get("include_hostname", "true").lower() == "true",
        include_timestamp=fmt_config.get("include_timestamp", "true").lower() == "true",
    )

    sgbox_config = config.get("sgbox", {})
    mode = sgbox_config.get("mode", "pull").lower()

    # ── Initialize GPG encryption (SGBox at-rest compatible) ───────
    encryption = SGBoxEncryption(config)

    # ── Choose output mode ─────────────────────────────────────────
    output_server = None
    forwarder = None

    if mode == "push":
        forwarder = SyslogForwarder(config)
    else:
        output_server = SyslogOutputServer(config)

    # ── Message handler (async, called for each received syslog message) ──
    async def handle_message(message: str, client_ip: str):
        """Parse, format, encrypt (if enabled), and send a single H3C log message."""
        parsed = parser.parse(message)
        if not parsed:
            return

        syslog_msg = formatter.format_syslog(
            parsed,
            facility=sgbox_config.get("facility", "local0"),
            severity=sgbox_config.get("severity", "info"),
        )

        if syslog_msg:
            # Encrypt at rest if SGBox encryption is enabled
            if encryption.is_enabled:
                syslog_msg = await encryption.encrypt(syslog_msg)

            if output_server:
                await output_server.send(syslog_msg)
            elif forwarder:
                await forwarder.send(syslog_msg)

    # ── Start syslog receiver ──────────────────────────────────────
    receiver = SyslogReceiver(config, handle_message)
    await receiver.start()

    # ── Start output server or connect forwarder ───────────────────
    if output_server:
        await output_server.start()
    elif forwarder:
        try:
            await forwarder.connect()
        except Exception as e:
            logger.error("forwarder.initial_connect_failed",
                          error=str(e),
                          msg="Will retry on first message")

    # ── Start async API server ─────────────────────────────────────
    def get_stats():
        stats = {"receiver": receiver.stats}
        if output_server:
            stats["output_server"] = output_server.stats
        if forwarder:
            stats["forwarder"] = forwarder.stats
        return stats

    api = APIServer(config, parser, formatter, stats_provider=get_stats)
    try:
        await api.start()
    except Exception as e:
        logger.warning("api.start_failed", error=str(e))

    # ── Wait for shutdown signal ───────────────────────────────────
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("shutdown.signal_received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    output_port = sgbox_config.get("output_port", sgbox_config.get("port", "1514"))
    logger.info("translator.running",
                syslog_tls_port=config.get("server", {}).get("syslog_tls_port", "6514"),
                syslog_tcp_port=config.get("server", {}).get("syslog_tcp_port", "514"),
                api_port=config.get("server", {}).get("api_port", "8443"),
                output_mode=mode,
                output_port=output_port)

    await shutdown_event.wait()

    # ── Cleanup ────────────────────────────────────────────────────
    logger.info("translator.shutting_down")
    await receiver.stop()
    await api.stop()
    if output_server:
        await output_server.stop()
    if forwarder:
        await forwarder.close()

    # Final stats
    logger.info("translator.final_stats",
                parser=parser.stats,
                formatter=formatter.stats,
                receiver=receiver.stats)


def main():
    """Entry point."""
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

    # Setup structlog (replaces old logging.handlers boilerplate)
    setup_structlog(config)

    logger.info("translator.starting", version="2.0.0")
    logger.info("config.loaded", path=args.config)

    # CLI mode
    if args.input:
        output = args.output or args.input.rsplit(".", 1)[0] + "_translated.log"
        run_cli_mode(config, args.input, output)
        return

    # Daemon mode
    if args.daemon:
        pid_file = config.get("server", {}).get(
            "pid_file", "/var/run/h3c-translator.pid"
        )
        daemonize(pid_file)

    # Server mode — use uvloop for high-performance async
    uvloop.run(run_server(config))


if __name__ == "__main__":
    main()
