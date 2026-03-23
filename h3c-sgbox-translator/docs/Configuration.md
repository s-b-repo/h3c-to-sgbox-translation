# Configuration Reference

The Translator relies entirely on a single INI configuration file, typically located at `/etc/h3c-translator/translator.config`. This guide walks through each section and its parameters.

## `[server]`
Defines how the Translator binds to network interfaces.

* **`syslog_tls_port`** `(default: 6514)`: Port for secure, incoming syslog connections from H3C firewalls.
* **`syslog_tcp_port`** `(default: 514)`: Port for plaintext incoming syslog connections.
* **`api_port`** `(default: 8443)`: Port for the HTTPS REST API endpoints.
* **`bind_address`** `(default: 0.0.0.0)`: Ensure this is `0.0.0.0` to listen on all interfaces so remote machines can connect.
* **`max_connections`** `(default: 100)`: Restricts total concurrent connections to prevent resource exhaustion.
* **`daemonize`** `(default: false)`: Forks the process to the background. *Unix/Linux only.* Use `false` if running under `systemd`.

## `[tls]`
TLS certificate paths for encrypting syslog (Port 6514) and the API (Port 8443).

* **`cert_file`**: Path to the PEM-formatted public certificate.
* **`key_file`**: Path to the PEM-formatted private key.
* **`ca_file`**: Path to the Certificate Authority file (optional unless `require_client_cert` is true).
* **`require_client_cert`** `(default: false)`: Enforces mTLS (mutual TLS) auth if supported by your firewalls.
* **`min_tls_version`** `(default: TLSv1.2)`: Drops fallback to vulnerable protocols like TLS 1.0/1.1. 

## `[security]`

* **`allowed_ips`**: Crucial whitelist for connecting devices. Examples: `10.16.18.0/24,10.17.0.0/24`. Only configured IPs can forward logs or query the API.
* **`api_key`**: A cryptographically random secret required to access the `v1/health` and `v1/stats` APIs. Generates via `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`.
* **`allow_plaintext`** `(default: false)`: Required to be `true` if you bypass the `[tls]` configuration entirely.

## `[sgbox]`
Defines the output behaviour towards SGBox.

* **`mode`** `(default: pull)`: 
  * `pull`: The Translator runs a TCP server (on `output_port`), and the SGBox Collector connects to downloading waiting logs. **Recommended.**
  * `push`: The Translator actively dials `host` on `port` to send UDP/TCP syslog data.
* **`output_port`** `(default: 1514)`: Used when `mode = pull`.
* **`host` / `port`**: Used when `mode = push`. Points to the SGBox SIEM Server's listener.
* **`protocol`** `(default: tcp)`: Output protocol (tcp, udp).
* **`facility` / `severity`**: Default Syslog metadata headers.

## `[output]`
Controls how parsed fields are transformed into text.

* **`format`** `(default: extended)`:
  * `core`: Returns only basics (`proto`, `src`, `dst`, `sport`, `dport`, `action`).
  * `extended`: Returns all mapped fields (including NAT addresses, App types, and rule IDs).
* **`include_hostname`**: Appends `hostname=<DeviceName>` from the raw H3C log headers.
* **`include_timestamp`**: Appends the parsed start time.

## `[logging]`
Controls application stdout and file-based logging (not the actual syslog data).

* **`level`** `(default: INFO)`: Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).
* **`file`**: Target file destination (e.g. `/var/log/h3c-translator/translator.log`).
* **`max_size_mb` / `backup_count`**: Setup for automated log rotation. 

## `[encryption]`
Configures At-Rest GPG Encryption for logs stored locally on the server. Refer to the [Security & Encryption](Security-and-Encryption) page for a detailed explanation of symmetric vs asymmetric setups.
