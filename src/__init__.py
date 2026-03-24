# H3C to SGBox Log Translator
# Async syslog translation for H3C firewalls → SGBox SIEM
# v2.0.0 — Debian 13, aiohttp, uvloop, structlog, tenacity, pyOpenSSL
__version__ = "2.0.0"

__all__ = [
    "parser",
    "formatter",
    "syslog_receiver",
    "syslog_forwarder",
    "syslog_output_server",
    "api_server",
    "translator",
    "encryption",
]
