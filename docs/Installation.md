# Full Installation & Deployment Guide

This guide covers deploying the **H3C-SGBox Translator v2.0.0** on a Debian 13 (Trixie) server. The project ships with an automated `install.sh` script that handles everything.

## Quick Install (Automated)

Clone or extract the project, then run:

```bash
sudo bash install.sh
```

This automatically:
1. Installs system packages (`python3`, `openssl`, `curl`, `ca-certificates`, etc.)
2. Creates the `h3c-translator` service user (no login shell)
3. Creates directories (`/opt/h3c-sgbox-translator`, `/etc/h3c-translator`, `/var/log/h3c-translator`)
4. Sets up a Python virtual environment with all pip dependencies
5. **Fetches Google Trust Services root CAs** from `https://pki.goog/roots.pem`
6. **Merges with system CAs** into `/etc/h3c-translator/certs/ca-bundle.pem`
7. Generates a self-signed TLS certificate for the inbound syslog listener
8. Installs and enables the systemd service

After `install.sh` completes, edit the config and start the service:

```bash
sudo nano /etc/h3c-translator/translator.config
sudo systemctl start h3c-translator
```

---

## Manual Installation

If you prefer manual setup or are on a non-Debian system, follow the steps below.

### 1. System Preparation

Ensure your system has Python 3.11+ and the required packages:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv openssl curl ca-certificates
```

### 2. Create a Dedicated Service User

The translator should never run as root:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin h3c-translator
```

### 3. Create Required Directories

```bash
sudo mkdir -p /opt/h3c-sgbox-translator
sudo mkdir -p /etc/h3c-translator/certs
sudo mkdir -p /var/log/h3c-translator
sudo chown -R h3c-translator:h3c-translator /var/log/h3c-translator
```

### 4. Deploy the Code

```bash
sudo cp -r src /opt/h3c-sgbox-translator/
sudo cp pyproject.toml requirements.txt /opt/h3c-sgbox-translator/
sudo cp translator.config /etc/h3c-translator/translator.config
```

### 5. Create Virtual Environment & Install Dependencies

```bash
sudo python3 -m venv /opt/h3c-sgbox-translator/venv
sudo /opt/h3c-sgbox-translator/venv/bin/pip install --upgrade pip wheel
sudo /opt/h3c-sgbox-translator/venv/bin/pip install -r /opt/h3c-sgbox-translator/requirements.txt
```

### 6. Fetch Trusted CA Bundle (for outbound TLS to SGBox)

The translator needs trusted CA certificates to verify SGBox's TLS certificate. The install script fetches **Google Trust Services root CAs** and merges them with the **system CA bundle**:

```bash
# Download Google Trust Services root CAs
curl -sSL https://pki.goog/roots.pem -o /etc/h3c-translator/certs/google-roots.pem

# Merge Google roots + system CA bundle
cat /etc/h3c-translator/certs/google-roots.pem \
    /etc/ssl/certs/ca-certificates.crt \
    > /etc/h3c-translator/certs/ca-bundle.pem
```

> **Why?** SGBox does not provide their TLS certificate or CA info. The merged bundle covers every major public CA, so the translator can verify SGBox's cert regardless of the issuer.

### 7. Generate Self-Signed TLS Certificate (Inbound Listener)

For the H3C → translator syslog connection on port 6514:

```bash
sudo openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout /etc/h3c-translator/certs/server.key \
    -out /etc/h3c-translator/certs/server.crt \
    -days 365 \
    -subj "/CN=h3c-translator/O=H3C-SGBox/C=ZA"

sudo chmod 600 /etc/h3c-translator/certs/server.key
sudo chown -R h3c-translator:h3c-translator /etc/h3c-translator/certs
```

### 8. Secure Configuration

Generate a secure API key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Edit the configuration:
```bash
sudo nano /etc/h3c-translator/translator.config
```

Essential settings:
1. `[security]` → `api_key = <YOUR_GENERATED_KEY>`
2. `[security]` → `allowed_ips = <YOUR_FIREWALL_AND_SGBOX_SUBNETS>`
3. `[sgbox]` → `host = <SGBOX_IP>` and verify `port = 6154`, `protocol = tls`

Lock down permissions:
```bash
sudo chown root:h3c-translator /etc/h3c-translator/translator.config
sudo chmod 640 /etc/h3c-translator/translator.config
```

### 9. Setup Systemd Service

```bash
sudo cp systemd/h3c-translator.service /lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable h3c-translator
```

**Service file** (`h3c-translator.service`):
```ini
[Unit]
Description=H3C to SGBox Log Translator Service (v2.0.0)
After=network.target

[Service]
Type=simple
User=h3c-translator
Group=h3c-translator
ExecStart=/opt/h3c-sgbox-translator/venv/bin/python3 -m src.translator \
    --config /etc/h3c-translator/translator.config
WorkingDirectory=/opt/h3c-sgbox-translator
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

### 10. Start & Verify

```bash
sudo systemctl start h3c-translator
sudo systemctl status h3c-translator
sudo journalctl -u h3c-translator -f
```

You should see:
- `receiver.tls_started port=6514`
- `forwarder.connected protocol=TLS host=<SGBOX_IP> port=6154`
- `translator.running output_mode=push output_port=6154`

### 11. Firewall Rules

Allow traffic for the required ports:

**UFW (Debian/Ubuntu):**
```bash
sudo ufw allow 6514/tcp   # H3C → translator (inbound syslog TLS)
sudo ufw allow 514/tcp    # H3C → translator (inbound syslog TCP, optional)
sudo ufw allow 8443/tcp   # REST API (HTTPS)
# Port 6154 is outbound (translator → SGBox), usually allowed by default
```

**Firewalld (RHEL/CentOS):**
```bash
sudo firewall-cmd --permanent --add-port=6514/tcp
sudo firewall-cmd --permanent --add-port=514/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

### 12. Verification

Test the API from your workstation:
```bash
curl -k -H "X-API-Key: <KEY>" https://<TRANSLATOR_IP>:8443/api/v1/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "h3c-sgbox-translator",
  "version": "2.0.0"
}
```

---

### Next Steps
Head over to the [SGBox Integration](SGBox-Integration) guide to configure your H3C firewall and SGBox collector.
