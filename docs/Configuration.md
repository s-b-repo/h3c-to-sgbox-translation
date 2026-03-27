# Configuration Reference

The Translator uses a single INI configuration file at `/etc/h3c-translator/translator.config`. This reference documents every section and parameter.

## `[server]`

Controls how the translator binds to network interfaces for receiving H3C syslog.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `syslog_tls_port` | `6514` | Port for encrypted TLS syslog from H3C firewalls |
| `syslog_tcp_port` | `514` | Port for plaintext TCP syslog (fallback) |
| `api_port` | `8443` | Port for the HTTPS REST API |
| `bind_address` | `0.0.0.0` | Interface to bind — `0.0.0.0` listens on all interfaces |
| `max_connections` | `100` | Maximum concurrent syslog connections (enforced by asyncio semaphore) |
| `daemonize` | `false` | Fork to background. Use `false` when running under systemd |
| `pid_file` | `/var/run/h3c-translator.pid` | PID file location for daemon mode |

## `[tls]`

TLS certificate configuration used for both the inbound syslog listener and the outbound connection to SGBox.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `cert_file` | — | Path to the server's PEM certificate (for inbound TLS listener) |
| `key_file` | — | Path to the server's PEM private key |
| `ca_file` | `ca-bundle.pem` | CA bundle for verifying SGBox's TLS cert. Auto-fetched by `install.sh` (Google roots + system CAs) |
| `require_client_cert` | `false` | Enforce mutual TLS (mTLS) for inbound connections |
| `min_tls_version` | `TLSv1.2` | Minimum TLS version (`TLSv1.2` or `TLSv1.3`). Drops TLS 1.0/1.1 |

> **Note:** The `ca_file` is automatically created by `install.sh` at `/etc/h3c-translator/certs/ca-bundle.pem` by merging Google Trust Services roots with the system CA bundle. You typically don't need to change this.

## `[security]`

Network-level and API security controls.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `allowed_ips` | `0.0.0.0/0` | Comma-separated CIDR whitelist. Only these IPs can connect. Example: `10.16.18.0/24,10.13.0.0/24` |
| `api_key` | `CHANGE_ME...` | API key required in `X-API-Key` header. Generate with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `allow_plaintext` | `false` | Allow plain HTTP API calls when TLS certs are not configured. **Not recommended for production.** |
| `allowed_ports` | `6514,514,8443` | Informational — documents which ports this service binds to |

## `[sgbox]`

Controls how translated logs are delivered to SGBox.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `mode` | `push` | **`push`** (recommended) — translator forwards logs to SGBox. **`pull`** — SGBox collector connects to translator's `output_port` |
| `host` | — | **REQUIRED.** SGBox SIEM IP address or hostname (push mode). Supports multiple destinations: `host = 10.10.0.52,10.10.0.53` for parallel fan-out |
| `port` | `514` | SGBox syslog port. Standard: 514 for UDP/TCP, 6514 for TLS |
| `tls_port` | `6514` | TLS syslog port (only used when `protocol = tls`) |
| `output_port` | `1514` | TCP port SGBox collectors connect to (pull mode only) |
| `protocol` | `udp` | Output protocol: `udp` (recommended), `tcp`, or `tls` |
| `forwarder_backend` | `rsyslog` | **`rsyslog`** (recommended) — uses the system rsyslog daemon for forwarding. Generates `/etc/rsyslog.d/h3c-sgbox.conf` and restarts rsyslog automatically. **`python`** — legacy direct socket forwarding with built-in retry |
| `rsyslog_log_scope` | `all` | Log scope when using rsyslog backend: **`all`** (`*.*` — all logs) or **`auth`** (`auth,authpriv.*` — authentication logs only) |
| `facility` | `local0` | Syslog facility header (`local0`–`local7`, `user`, `daemon`, etc.) |
| `severity` | `info` | Syslog severity header (`emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`) |

> **rsyslog backend (default):** On startup, the translator writes `/etc/rsyslog.d/h3c-sgbox.conf` with the appropriate forwarding rule (e.g. `*.* @SGBox-IP` for UDP) and restarts the rsyslog daemon. Messages are sent via the `logger` command. If rsyslog is not installed, the translator falls back to the `python` backend automatically.
>
> **python backend (legacy):** Opens direct UDP/TCP/TLS sockets from Python with tenacity exponential backoff retry. Does not require rsyslog.

## `[output]`

Controls how parsed H3C fields are formatted into output text. SGBox accepts CEF natively — no custom pattern needed.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `format` | `cef` | **`cef`** — CEF (Common Event Format). SGBox has built-in normalization, recommended. **`extended`** — key=value, all fields (requires custom SGBox pattern). **`core`** — key=value, minimal fields only |
| `include_hostname` | `true` | Include `shost=<DeviceName>` in CEF extension (or `hostname=` in key=value mode) |
| `include_timestamp` | `true` | Include the original session timestamp in the syslog envelope |

**CEF output example:**
```
<134>Mar 26 15:00:00 FW-01 CEF:0|H3C|Comware|7.0|SESSION_CREATED|Session Permitted|3|src=10.1.1.10 dst=8.8.8.8 spt=52314 dpt=443 proto=TCP act=permit app=HTTPS shost=FW-01
```

## `[encryption]`

Optional GPG encryption at rest. Refer to [Security & Encryption](Security-and-Encryption) for setup details.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `enabled` | `false` | Enable GPG encryption. **Disabled by default** — SGBox does not allow configuring the GPG passphrase, so TLS transport is recommended instead |
| `gpg_home` | `/var/lib/h3c-translator/.gnupg` | GPG keyring directory |
| `gpg_binary` | `gpg` | Path to gpg binary |
| `mode` | `symmetric` | `symmetric` (passphrase) or `asymmetric` (key pair) |
| `passphrase` | — | Passphrase for symmetric mode |
| `recipient` | — | Key ID or email for asymmetric mode |
| `cipher_algo` | `AES256` | Cipher algorithm (`AES256`, `AES192`, `AES128`, `CAST5`, `3DES`) |
| `armor` | `false` | ASCII-armored output (`true`) or binary (`false`, more compact) |
| `encrypt_output` | `true` | Encrypt messages before forwarding (when encryption is enabled) |
| `encrypted_log_dir` | `/var/log/h3c-translator/encrypted` | Directory for encrypted log files |

## `[logging]`

Application logging (not the syslog data — this is the translator's own logs).

| Parameter | Default | Description |
|-----------|---------|-------------|
| `level` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `file` | `/var/log/h3c-translator/translator.log` | Log file path |
| `max_size_mb` | `100` | Maximum log file size (MB) before rotation |
| `backup_count` | `5` | Number of rotated log files to keep |
