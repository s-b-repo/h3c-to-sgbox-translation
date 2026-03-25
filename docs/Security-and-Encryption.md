# Security & Encryption

The Translator incorporates multiple layers of security to ensure logs securely transit from the H3C firewall to the SGBox SIEM, while protecting the host environment.

## 1. TLS Syslog Forwarding (Recommended — Port 6154)

The recommended way to secure log transit is TLS syslog forwarding on port **6154**. The translator pushes translated logs directly to SGBox over an encrypted TLS connection.

```ini
[sgbox]
mode = push
host = <sgbox-ip>
port = 6154
protocol = tls
```

The translator reads the `[tls]` section for the CA certificate used to verify the SGBox server. If you have a custom CA, point `ca_file` to it; otherwise, the system default trust store is used.

### Certificate Setup (Automatic)

The `install.sh` script automatically builds a trusted CA bundle at `/etc/h3c-translator/certs/ca-bundle.pem` by:

1. **Fetching Google Trust Services root CAs** from `https://pki.goog/roots.pem`
2. **Merging with the system CA bundle** (`/etc/ssl/certs/ca-certificates.crt`)

This covers virtually every public CA, so the translator can verify SGBox's TLS certificate regardless of which CA issued it. **No manual certificate configuration is required.**

> [!TIP]
> To refresh the CA bundle (e.g. after a CA rotation), re-run `install.sh` or manually:
> ```bash
> curl -sSL https://pki.goog/roots.pem -o /etc/h3c-translator/certs/google-roots.pem
> cat /etc/h3c-translator/certs/google-roots.pem /etc/ssl/certs/ca-certificates.crt \
>     > /etc/h3c-translator/certs/ca-bundle.pem
> ```

---

## 2. At-Rest GPG Encryption (SGBox Compatible)

> [!WARNING]
> SGBox does **not** allow configuring a custom GPG passphrase. Because of this limitation, **TLS transport** (Section 1 above) is the recommended security mechanism for most deployments. GPG encryption at rest is disabled by default.

The Translator supports encrypting logs at rest using GPG before they are stored on disk. This is fully compatible with SGBox's native filesystem encryption capabilities.

### Configuration (`[encryption]` section)
To enable encryption, ensure `python-gnupg` and `gpg` are installed on your host.

```ini
[encryption]
# Enable the encryption engine
enabled = true

# Where GPG stores its keys (ensure the service user owns this)
gpg_home = /var/lib/h3c-translator/.gnupg

# Mode: symmetric (passphrase) or asymmetric (key pair)
mode = symmetric

# If mode=symmetric, set a strong passphrase here
passphrase = YOUR_STRONG_PASSPHRASE

# If mode=asymmetric, set the recipient's Key ID or Email
recipient = admin@sgbox.local

# Cipher to use (Default: AES256)
cipher_algo = AES256

# Write ASCII armored files instead of raw binary
armor = false

# Directory where encrypted log files are stored
encrypted_log_dir = /var/log/h3c-translator/encrypted
```

### Symmetric vs Asymmetric Mode
* **Symmetric Mode**: Uses AES256 and a shared passphrase defined in `translator.config`. This is simpler to setup but requires managing the secret securely.
* **Asymmetric Mode**: You must import the SGBox Collector's public GPG key into the translator's keyring (`sudo -u h3c-translator gpg --homedir /var/lib/h3c-translator/.gnupg --import sgbox_pub.asc`). The translator then encrypts the logs so that *only* the SGBox private key can decrypt them.

## 3. Network Security Features

| Feature | Details |
|---------|---------|
| **API Key Auth** | `X-API-Key` header enforced using timing-safe string comparison. |
| **IP Whitelists** | CIDR-based whitelisting (`allowed_ips`) enforced on all TCP/TLS bindings. |
| **TLS 1.2+** | Actively drops connections using deprecated TLS 1.0 or 1.1 algorithms. |
| **Forced TLS** | Rejects plain HTTP API calls unless `allow_plaintext = true` is explicitly set. |
| **Rate Limiting** | 120 req/min per IP address on the API to prevent brute-force querying. |
| **CRIME Mitigation** | TLS compression is explicitly disabled across the stack. |

## 4. Application Hardening

| Feature | Details |
|---------|---------|
| **Asynchronous Architecture** | All socket handling utilizes Python `asyncio`, eliminating thread exhaustion attacks like Slowloris. |
| **Memory Boundaries** | Bulk API translation limits payloads to a maximum of 1000 lines and capped body sizes. |
| **Connection Limits** | The `max_connections` parameter uses semaphores to cap the number of concurrent SGBox Collectors. |
| **Systemd Confinement** | The recommended systemd service file utilizes `NoNewPrivileges`, `PrivateTmp`, and `ProtectSystem=full`. |
| **Input Sanitization** | `json.loads` exceptions are trapped, and HTTP error bodies are completely sanitized of stack traces before returning to the user. |
