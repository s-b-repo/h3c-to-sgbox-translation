# H3C-SGBox Translator

**H3C to SGBox Secure Log Translator**

The H3C-SGBox Translator is a high-performance middleware service that acts as a syslog bridge. It receives raw, proprietary Comware syslog events from H3C hardware firewalls, translates them into parsed Key-Value pairs, and serves them over a TCP socket for ingestion by SGBox SIEM Collectors.

Written entirely in Python with zero external dependencies, it securely encrypts logs at rest, supports TLS transport over port 6514, and prevents connection exhaustion.

---

## 📚 Documentation

The complete, detailed documentation for this project is hosted in the **[Wiki](docs/Home.md)**!

### Quick Links

- [Installation & Deployment](docs/Installation.md)
- [Configuration Reference](docs/Configuration.md)
- [SGBox Integration Guide](docs/SGBox-Integration.md)
- [Field Mapping](docs/Field-Mapping.md)
- [Security & Encryption](docs/Security-and-Encryption.md)
- [REST API Reference](docs/API-Reference.md)
- [Troubleshooting & Bug Reports](docs/Troubleshooting.md)

---

## Quick Start (Local Development)

```bash
# Clone the repository
git clone https://github.com/your-org/h3c-sgbox-translator.git
cd h3c-sgbox-translator

# Start the translator (Foreground)
python3 -m src.translator --config translator.config

# Run the test suite
python3 -m unittest discover tests/ -v
```

See the [Wiki](docs/Home.md) for production deployment instructions using `systemd`.
