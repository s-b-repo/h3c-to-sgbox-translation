# H3C to SGBox Secure Log Translator

Translates H3C Comware firewall syslog messages into a clean, parsed key-value format optimized for **SGBox SIEM** ingestion. Built for **Debian 13 (Trixie)** with a fully async Python 3.12+ stack using `asyncio`, `uvloop`, `aiohttp`, and `structlog`.

> **Version 2.0.0** — async architecture, TLS syslog forwarding, auto-fetched CA bundle, GPG at-rest encryption (optional).

## High-Level Architecture

The Translator is a secure middleman between your H3C firewalls and the SGBox SIEM. It receives raw syslog, parses the proprietary H3C format, enriches the data, and delivers it to SGBox.

### Push Mode (Recommended — TLS on port 6154)

```text
┌─────────────┐    Syslog (TLS/TCP)    ┌──────────────────────────────────┐   TLS Syslog    ┌─────────┐
│ H3C Firewall │─────(Pushes logs)─────►│  H3C-SGBox Translator Server     │──(Pushes logs)──►│  SGBox  │
│              │   Port 6514 / 514     │  ┌─────────┐  ┌───────────┐     │   Port 6154     │  SIEM   │
└─────────────┘                        │  │ Parser  │→│ Formatter │     │                  └─────────┘
                                       │  └─────────┘  └───────────┘     │
                                       │  ┌──────────────────────────┐   │
                                       │  │ HTTPS API (port 8443)    │   │
                                       │  │ /api/v1/translate        │   │
                                       │  │ /api/v1/health           │   │
                                       │  │ /api/v1/stats            │   │
                                       │  └──────────────────────────┘   │
                                       └──────────────────────────────────┘
```

### Pull Mode (Legacy — SGBox connects to translator)

```text
┌─────────────┐    Syslog (TLS/TCP)    ┌──────────────────────────────────┐   TCP Socket   ┌─────────┐
│ H3C Firewall │─────(Pushes logs)─────►│  H3C-SGBox Translator Server     │◄─(Pulls logs)─┤  SGBox  │
│              │   Port 6514 / 514     │  ┌─────────┐  ┌───────────┐     │    Port 1514   │Collector│
└─────────────┘                        │  │ Parser  │→│ Formatter │     │                └─────────┘
                                       └──────────────────────────────────┘
```

## Translation Example

**Input** (H3C raw syslog):
```
Protocol(1001)=TCP;Application(1002)=cPanel;SrcIPAddr(1003)=68.183.184.83;SrcPort(1004)=46644;DstIPAddr(1007)=102.134.120.157;DstPort(1008)=22;Event(1048)=(8)Session created
```

**Output** (SGBox key=value format):
```
proto=TCP src=68.183.184.83 dst=102.134.120.157 sport=46644 dport=22 action=permit app=cPanel hostname=Gole-F1000-Firewall-01
```

## Key Features

| Feature | Description |
|---------|-------------|
| **TLS Forwarding** | Pushes logs to SGBox over TLS on port 6154 with auto-fetched Google Trust Services + system CA bundle |
| **Async Architecture** | Fully async I/O via `asyncio` + `uvloop` — handles thousands of concurrent connections |
| **GPG Encryption** | Optional at-rest GPG encryption (symmetric/asymmetric) compatible with SGBox's scheme |
| **REST API** | HTTPS API for health checks, stats, and ad-hoc translation testing |
| **IP Whitelisting** | CIDR-based whitelist enforced on all listeners |
| **Auto-Reconnect** | Tenacity exponential backoff for resilient SGBox connectivity |

## Getting Started

Run `install.sh` as root to install everything automatically:
```bash
sudo bash install.sh
```

Navigate to the [Installation](Installation) guide for manual setup details.

### Quick Links

- **[Installation Guide](Installation)**: Automated installer, system preparation, and service setup.
- **[Configuration Reference](Configuration)**: Complete `translator.config` parameter reference.
- **[SGBox & H3C Setup](SGBox-Integration)**: Configuring H3C firewalls and SGBox collectors.
- **[Security & Encryption](Security-and-Encryption)**: TLS forwarding, GPG encryption, and network hardening.
- **[API Reference](API-Reference)**: REST API endpoints for health, stats, and translation.
- **[Field Mapping Reference](Field-Mapping)**: How H3C field IDs map to SGBox keys.
- **[Troubleshooting](Troubleshooting)**: Diagnostics and common issues.
