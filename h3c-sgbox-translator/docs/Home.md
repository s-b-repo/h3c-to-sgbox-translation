# H3C to SGBox Secure Log Translator

Translates H3C Comware firewall syslog messages into a clean, parsed key-value format specifically optimized for SGBox SIEM ingestion. Runs natively on CentOS 7+ and Ubuntu with **zero external dependencies** (Python 3.6+ stdlib only).

## High-Level Architecture

The Translator acts as a robust middleman receiving logs from H3C firewalls, parsing the proprietary syslog structure, enriching the data, and forwarding it via a TCP socket to an SGBox Collector.

```text
┌─────────────┐    Syslog (TLS/TCP)    ┌──────────────────────────────────┐   TCP Socket   ┌─────────┐
│ H3C Firewall │─────(Pushes logs)─────►│  H3C-SGBox Translator Server     │◄─(Pulls logs)─┤  SGBox  │
│              │   Port 6514 / 514     │  ┌─────────┐  ┌───────────┐     │    Port 1514   │  SIEM / │
└─────────────┘                        │  │ Parser  │→│ Formatter │     │                │Collector│
                                       │  └─────────┘  └───────────┘     │                └─────────┘
                                       │  ┌──────────────────────────┐   │
                                       │  │ HTTPS API (port 8443)    │   │
                                       │  │ /api/v1/translate        │   │
                                       │  │ /api/v1/health           │   │
                                       │  │ /api/v1/stats            │   │
                                       │  └──────────────────────────┘   │
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

## Getting Started

Navigate to the [Installation](Installation) guide to begin deploying the application on a production-ready Linux host.

### Quick Links

- **[Installation Guide](Installation)**: System preparation, service user creation, and background daemon setup.
- **[Configuration Reference](Configuration)**: Understand the `translator.config` file settings.
- **[SGBox & H3C Setup](SGBox-Integration)**: Configuring the network hardware to talk to the Translator.
- **[Security & Encryption](Security-and-Encryption)**: At-Rest GPG encryption, TLS, and API limits.
- **[API Reference](API-Reference)**: Using the REST API for health checks and ad-hoc translation.
- **[Field Mapping Reference](Field-Mapping)**: How H3C IDs translate exactly to SGBox keys.
- **[Troubleshooting](Troubleshooting)**: What to do if logs are not flowing.
