# Security & Encryption

The Translator incorporates multiple layers of security to ensure logs securely transit from the H3C firewall to the SGBox SIEM, while protecting the host environment.

## 1. At-Rest GPG Encryption (SGBox Compatible)

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

## 2. Network Security Features

| Feature | Details |
|---------|---------|
| **API Key Auth** | `X-API-Key` header enforced using timing-safe string comparison. |
| **IP Whitelists** | CIDR-based whitelisting (`allowed_ips`) enforced on all TCP/TLS bindings. |
| **TLS 1.2+** | Actively drops connections using deprecated TLS 1.0 or 1.1 algorithms. |
| **Forced TLS** | Rejects plain HTTP API calls unless `allow_plaintext = true` is explicitly set. |
| **Rate Limiting** | 120 req/min per IP address on the API to prevent brute-force querying. |
| **CRIME Mitigation** | TLS compression is explicitly disabled across the stack. |

## 3. Application Hardening

| Feature | Details |
|---------|---------|
| **Asynchronous Architecture** | All socket handling utilizes Python `asyncio`, eliminating thread exhaustion attacks like Slowloris. |
| **Memory Boundaries** | Bulk API translation limits payloads to a maximum of 1000 lines and capped body sizes. |
| **Connection Limits** | The `max_connections` parameter uses semaphores to cap the number of concurrent SGBox Collectors. |
| **Systemd Confinement** | The recommended systemd service file utilizes `NoNewPrivileges`, `PrivateTmp`, and `ProtectSystem=full`. |
| **Input Sanitization** | `json.loads` exceptions are trapped, and HTTP error bodies are completely sanitized of stack traces before returning to the user. |
