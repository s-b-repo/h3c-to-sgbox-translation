# H3C-SGBox Translator

<div align="center">

**Secure, async syslog translator for H3C Comware firewalls → SGBox SIEM**

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Debian 13](https://img.shields.io/badge/debian-13%20Trixie-A81D33?style=for-the-badge&logo=debian&logoColor=white)
![License MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Version 2.0.0](https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge)

</div>

---

The H3C-SGBox Translator is a high-performance middleware service that bridges H3C Comware hardware firewalls and SGBox SIEM. It receives raw proprietary syslog events, parses and enriches them into SGBox-ready key-value pairs, and forwards them over **TLS-encrypted syslog** — all with a fully async Python stack.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔒 **TLS Syslog Forwarding** | Pushes translated logs to SGBox over TLS (port 6154) with auto-fetched Google Trust Services + system CA bundle |
| ⚡ **Fully Async** | Built on `asyncio` + `uvloop` for thousands of concurrent connections with minimal resource usage |
| 🔑 **GPG Encryption** | Optional at-rest GPG encryption (AES256 symmetric or asymmetric) compatible with SGBox's scheme |
| 🌐 **REST API** | HTTPS API for health checks, real-time stats, and ad-hoc log translation |
| 🛡️ **Security Hardened** | IP whitelisting, API key auth, TLS 1.2+ enforcement, rate limiting, connection caps |
| 🔄 **Auto-Reconnect** | Tenacity exponential backoff for resilient SGBox connectivity |
| 📦 **One-Command Install** | Automated `install.sh` with venv, systemd service, CA bundle fetch, and cert generation |

## 🏗️ Architecture

```text
┌─────────────┐   Syslog (TLS/TCP)   ┌──────────────────────────────────┐   TLS Syslog    ┌─────────┐
│ H3C Firewall │──────────────────────►│  H3C-SGBox Translator            │────────────────►│  SGBox  │
│              │  Port 6514 / 514     │                                  │   Port 6154     │  SIEM   │
└─────────────┘                       │  ┌────────┐  ┌───────────┐      │                  └─────────┘
                                      │  │ Parser │─►│ Formatter │      │
                                      │  └────────┘  └───────────┘      │
                                      │  ┌───────────────────────────┐  │
                                      │  │ HTTPS API (port 8443)     │  │
                                      │  │  /api/v1/health           │  │
                                      │  │  /api/v1/stats            │  │
                                      │  │  /api/v1/translate        │  │
                                      │  └───────────────────────────┘  │
                                      └──────────────────────────────────┘
```

## 🔄 Translation Example

**Input** — H3C raw syslog:
```
Protocol(1001)=TCP;Application(1002)=cPanel;SrcIPAddr(1003)=68.183.184.83;
SrcPort(1004)=46644;DstIPAddr(1007)=102.134.120.157;DstPort(1008)=22;
Event(1048)=(8)Session created
```

**Output** — SGBox key-value format:
```
proto=TCP src=68.183.184.83 dst=102.134.120.157 sport=46644 dport=22 action=permit app=cPanel hostname=Gole-F1000-Firewall-01
```

## 🚀 Quick Start

### Production Install (Debian 13)

```bash
git clone https://github.com/your-org/h3c-sgbox-translator.git
cd h3c-sgbox-translator

# Automated install — sets up everything including TLS certs + CA bundle
sudo bash install.sh

# Edit config (set SGBox IP, API key, allowed IPs)
sudo nano /etc/h3c-translator/translator.config

# Start the service
sudo systemctl start h3c-translator
sudo systemctl status h3c-translator
```

### Local Development

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run in foreground
python3 -m src.translator --config translator.config

# Run tests
pytest tests/ -v

# CLI mode — translate a log file
python3 -m src.translator -c translator.config -i logs.csv -o translated.log
```

## ⚙️ Configuration

The translator uses a single INI config file at `/etc/h3c-translator/translator.config`:

```ini
[sgbox]
mode = push              # push (TLS to SGBox) or pull (SGBox connects)
host = 192.168.1.100     # SGBox SIEM server address
port = 6154              # SGBox TLS syslog port
protocol = tls           # tls, tcp, or udp

[tls]
cert_file = /etc/h3c-translator/certs/server.crt
key_file = /etc/h3c-translator/certs/server.key
ca_file = /etc/h3c-translator/certs/ca-bundle.pem  # Auto-fetched by install.sh

[security]
allowed_ips = 10.16.18.0/24,10.13.0.0/24
api_key = CHANGE_ME_GENERATE_A_SECURE_KEY
```

> **TLS certificates are handled automatically.** The install script fetches Google Trust Services root CAs and merges them with the system CA bundle — no manual cert configuration needed.

See the [Configuration Reference](docs/Configuration.md) for all parameters.

## 🌐 API Endpoints

All endpoints require the `X-API-Key` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | Service health check |
| `GET` | `/api/v1/stats` | Real-time pipeline statistics |
| `POST` | `/api/v1/translate` | Translate a single H3C log line |
| `POST` | `/api/v1/translate/bulk` | Batch translate up to 1000 lines |

```bash
curl -k -H "X-API-Key: <KEY>" https://localhost:8443/api/v1/health
```

## 🔒 Security

- **TLS 1.2+** enforced on all connections — TLS 1.0/1.1 rejected
- **IP whitelisting** via CIDR notation on all listeners
- **API key authentication** with timing-safe comparison
- **Rate limiting** — 120 req/min per IP
- **TLS compression disabled** (CRIME mitigation)
- **Systemd hardening** — `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`
- **Async architecture** — immune to Slowloris and thread exhaustion attacks

## 📁 Project Structure

```
h3c-sgbox-translator/
├── src/
│   ├── translator.py          # Main entry point & orchestrator
│   ├── syslog_receiver.py     # Async TLS/TCP syslog listener
│   ├── syslog_forwarder.py    # Async TLS forwarder to SGBox (push mode)
│   ├── syslog_output_server.py # TCP server for SGBox pull mode
│   ├── parser.py              # H3C Comware log parser
│   ├── formatter.py           # SGBox key-value formatter
│   ├── encryption.py          # GPG encryption module
│   └── api_server.py          # aiohttp REST API
├── docs/                      # Wiki documentation
├── tests/                     # Test suite
├── systemd/                   # Service file
├── translator.config          # Default configuration
├── install.sh                 # Automated installer
├── requirements.txt           # Python dependencies
└── pyproject.toml             # Build configuration
```

## 📚 Documentation

Full documentation is available in the [`docs/`](docs/Home.md) directory:

- 📖 [Installation & Deployment](docs/Installation.md)
- ⚙️ [Configuration Reference](docs/Configuration.md)
- 🔗 [SGBox Integration Guide](docs/SGBox-Integration.md)
- 🗺️ [Field Mapping Reference](docs/Field-Mapping.md)
- 🔒 [Security & Encryption](docs/Security-and-Encryption.md)
- 🌐 [API Reference](docs/API-Reference.md)
- 🔧 [Troubleshooting](docs/Troubleshooting.md)

## 📋 Requirements

- **OS:** Debian 13 (Trixie) or compatible Linux
- **Python:** 3.11+
- **Dependencies:** `aiohttp`, `uvloop`, `structlog`, `tenacity`, `pyOpenSSL`, `python-gnupg`
- **Network:** Ports 6514 (inbound), 6154 (outbound to SGBox), 8443 (API)

## 📄 License

This project is licensed under the [GPL License](LICENSE).
