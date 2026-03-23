# Full Installation & Deployment Guide

This guide provides step-by-step instructions for installing the **H3C-SGBox Translator** on a production Linux server (CentOS 7+ / RHEL / Ubuntu).

## 1. System Preparation

First, ensure your system is up-to-date and has Python 3 installed. The translator relies entirely on the Python Standard Library, meaning **no `pip install` or external dependencies are required** for the core engine (with `python-gnupg` required optionally for encryption).

**For CentOS/RHEL:**
```bash
sudo yum update -y
sudo yum install -y python3 openssl
```

**For Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3 openssl
```

## 2. Create a Dedicated Service User
For security, the translator should never run as root. We will create a dedicated system user with no login shell.

**Standard Linux (CentOS/RHEL/Ubuntu):**
```bash
sudo useradd -r -s /sbin/nologin h3c-translator
```

**If `useradd` does not exist (e.g., specific Debian/Alpine setups), try `adduser` instead:**
```bash
sudo adduser --system --no-create-home --group --shell /usr/sbin/nologin h3c-translator
```

## 3. Create Required Directories
Create the necessary folder structure for the application code, configurations, certificates, and logs.

```bash
# Application code
sudo mkdir -p /opt/h3c-sgbox-translator

# Configuration and TLS certificates
sudo mkdir -p /etc/h3c-translator/certs

# Log directory
sudo mkdir -p /var/log/h3c-translator

# Set ownership of the log directory so the service user can write to it
sudo chown -R h3c-translator:h3c-translator /var/log/h3c-translator
```

## 4. Deploy the Code
Copy the project files into the `/opt/` directory. Assuming you have extracted the source code to your current directory:

```bash
# Copy source code and tests
sudo cp -r src /opt/h3c-sgbox-translator/
sudo cp -r tests /opt/h3c-sgbox-translator/
sudo cp -r systemd /opt/h3c-sgbox-translator/

# Copy the configuration file to /etc
sudo cp translator.config /etc/h3c-translator/translator.config

# Lock down permissions on the source code
sudo chown -R root:root /opt/h3c-sgbox-translator
sudo chmod -R 755 /opt/h3c-sgbox-translator
```

## 5. Generate TLS Certificates
The translator requires TLS certificates to secure the incoming H3C syslog stream (port 6514) and the REST API (port 8443).

You can use certificates signed by your corporate CA, or generate a self-signed certificate:

```bash
# Generate a self-signed certificate valid for 10 years
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/h3c-translator/certs/server.key \
  -out /etc/h3c-translator/certs/server.crt \
  -subj "/C=US/ST=State/L=City/O=Security/CN=translator.local"

# Secure the certificate files
sudo chown -R root:h3c-translator /etc/h3c-translator/certs
sudo chmod 640 /etc/h3c-translator/certs/server.key
sudo chmod 644 /etc/h3c-translator/certs/server.crt
```

## 6. Secure Configuration (API Key & Whitelists)

### Generate a Secure API Key
You need an API key to query the health and statistical endpoints.
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```
*(Copy the exact output string)*

### Edit the Configuration
Open the configuration file:
```bash
sudo vi /etc/h3c-translator/translator.config
```

Make the following absolute essential changes:
1. In `[security]`, set `api_key = <YOUR_GENERATED_KEY>`
2. In `[security]`, set `allowed_ips = 10.0.0.0/8, 192.168.1.0/24` *(Replace with your firewall and SGBox IP subnets)*
3. In `[sgbox]`, ensure `mode = pull` and `output_port = 1514`

**Secure Configuration File Permissions:**
Since `translator.config` contains your API key, it must be protected:
```bash
sudo chown root:h3c-translator /etc/h3c-translator/translator.config
sudo chmod 640 /etc/h3c-translator/translator.config
```

## 7. Setup the Systemd Service
To ensure the translator runs automatically on boot and restarts if it crashes, create a systemd service file.

```bash
sudo cp /opt/h3c-sgbox-translator/systemd/h3c-translator.service /etc/systemd/system/
```
Or create it manually:
```bash
sudo vi /etc/systemd/system/h3c-translator.service
```

**Sample Contents:**
```ini
[Unit]
Description=H3C to SGBox Log Translator Service
After=network.target

[Service]
Type=simple
User=h3c-translator
Group=h3c-translator

# The path to the Python executable and your application entry point
ExecStart=/usr/bin/python3 -m src.translator --config /etc/h3c-translator/translator.config
WorkingDirectory=/opt/h3c-sgbox-translator

# Restart behavior
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

## 8. Start & Enable the Service

Reload the systemd daemon to pick up the new service, enable it to start on boot, and start it immediately:

```bash
sudo systemctl daemon-reload
sudo systemctl enable h3c-translator
sudo systemctl start h3c-translator
```

Verify the service is running successfully:
```bash
sudo systemctl status h3c-translator
```
*(You should see `Active: active (running)` in green)*

View the real-time application logs to ensure it bound to the ports successfully:
```bash
sudo journalctl -u h3c-translator -f
```

## 9. Firewalld / UFW Allow Rules

You must allow incoming traffic through the Linux host's firewall for the 3 required ports:
- **6514 / TCP:** Incoming secure syslog from H3C
- **8443 / TCP:** Secure HTTPS REST API (for health checks)
- **1514 / TCP:** Outgoing TCP socket (SGBox Collector pulls logs from here)

**If using Firewalld (CentOS/RHEL):**
```bash
sudo firewall-cmd --permanent --add-port=6514/tcp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

**If using UFW (Ubuntu/Debian):**
```bash
sudo ufw allow 6514/tcp
sudo ufw allow 1514/tcp
sudo ufw allow 8443/tcp
```

## 10. Verification

Test the integration from your workstation or the SGBox collector using `curl`. 
*(Replace `<IP>` with the local IP of your Linux server, and `<KEY>` with the API key you generated in Step 6)*:

```bash
curl -k -H "X-API-Key: <KEY>" https://<IP>:8443/api/v1/health
```

**Expected Output:**
```json
{
  "status": "healthy",
  "service": "h3c-sgbox-translator",
  "version": "1.0.0"
}
```

### Next Steps 
Your translator service is now securely deployed! 
Head over to the [SGBox Integration](SGBox-Integration) guide to configure your H3C Firewall CLI to send logs and your SGBox Admin UI to connect and capture them.
