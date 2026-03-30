# Full Installation & Deployment Guide

This guide covers deploying the **H3C-SGBox Translator v2.0.0** on a Debian 13 (Trixie) server. The project ships with an automated `install.sh` script that handles everything.

## Quick Install (Automated)

Clone or extract the project, then run:

```bash
sudo bash install.sh
```

This automatically:
1. Installs system packages (`python3`, `openssl`, `curl`, `rsyslog`, `ca-certificates`, etc.)
2. Creates the `h3c-translator` service user (no login shell)
3. Creates directories (`/opt/h3c-sgbox-translator`, `/etc/h3c-translator`, `/var/log/h3c-translator`)
4. Sets up a Python virtual environment with all pip dependencies (including `daemonize`)
5. **Fetches Google Trust Services root CAs** from `https://pki.goog/roots.pem`
6. **Merges with system CAs** into `/etc/h3c-translator/certs/ca-bundle.pem`
7. Generates a self-signed TLS certificate for the inbound syslog listener

After `install.sh` completes, edit the config and start the daemon:

```bash
sudo nano /etc/h3c-translator/translator.config

# Start as daemon
/opt/h3c-sgbox-translator/venv/bin/python3 -m src.translator \
    --config /etc/h3c-translator/translator.config --daemon
```

---

## Manual Installation

If you prefer manual setup or are on a non-Debian system, follow the steps below.

### 1. System Preparation

Ensure your system has Python 3.11+ and the required packages:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv openssl curl rsyslog ca-certificates
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
3. `[sgbox]` → `host = <SGBOX_IP>` and verify `port = 514`, `protocol = udp`
4. `[sgbox]` → `forwarder_backend = parallel` (recommended — sends via rsyslog + UDP)

Lock down permissions:
```bash
sudo chown root:h3c-translator /etc/h3c-translator/translator.config
sudo chmod 640 /etc/h3c-translator/translator.config
```

### 9. Start as Daemon

The translator uses the pip `daemonize` package for proper Unix daemon management. No systemd service file is needed.

```bash
# Start the daemon
/opt/h3c-sgbox-translator/venv/bin/python3 -m src.translator \
    --config /etc/h3c-translator/translator.config --daemon

# Or with custom PID/log files
/opt/h3c-sgbox-translator/venv/bin/python3 -m src.translator \
    --config /etc/h3c-translator/translator.config --daemon \
    --pid-file /var/run/h3c.pid --log-file /var/log/h3c-translator/daemon.log
```

Daemon management commands:
```bash
# Check if running
cat /var/run/h3c-translator.pid && ps -p $(cat /var/run/h3c-translator.pid)

# Stop the daemon
kill $(cat /var/run/h3c-translator.pid)

# Force stop
kill -9 $(cat /var/run/h3c-translator.pid)

# View logs
tail -f /var/log/h3c-translator/translator.log
```

> **Tip:** To run on boot without systemd, add this to `/etc/rc.local` or create a cron `@reboot` entry:
> ```
> @reboot /opt/h3c-sgbox-translator/venv/bin/python3 -m src.translator --config /etc/h3c-translator/translator.config --daemon
> ```

### 10. Verify

```bash
tail -f /var/log/h3c-translator/translator.log
```

You should see:
- `receiver.tls_started port=6514`
- `forwarder.backend=parallel` (or `rsyslog`)
- `forwarder.rsyslog_config_written path=/etc/rsyslog.d/h3c-sgbox.conf`
- `translator.running output_mode=push`

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
