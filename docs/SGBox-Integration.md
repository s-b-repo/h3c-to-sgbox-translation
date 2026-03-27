# SGBox End-to-End Setup & Configuration Guide

This guide covers configuring the complete **H3C → Translator → SGBox** pipeline. The translator supports two delivery modes: **Push** (recommended) and **Pull** (legacy).

## Architecture Overview

### Push Mode (Recommended — via rsyslog)

The translator writes translated logs to the local rsyslog daemon, which forwards them to SGBox over UDP, TCP, or TLS.

```text
[H3C Firewall] ──(syslog TLS/TCP)──► [Translator] ──(logger)──► [rsyslog] ──(UDP/TCP/TLS)──► [SGBox SIEM]
                  Port 6514 / 514                              /etc/rsyslog.d/         Port 514
                                                               h3c-sgbox.conf
```

### Pull Mode (Legacy — SGBox Connects)

SGBox collectors connect to the translator's TCP socket to pull logs.

```text
[H3C Firewall] ──(syslog TLS/TCP)──► [Translator] ◄──(TCP pull)── [SGBox Collector]
                  Port 6514 / 514                     Port 1514
```

---

## 1. Translator Configuration ⚙️

### Push Mode (Recommended — rsyslog)

```ini
[sgbox]
mode = push
host = <SGBOX_IP>
port = 514
protocol = udp
forwarder_backend = rsyslog
rsyslog_log_scope = all
facility = local0
severity = info
```

On startup, the translator:
1. Generates `/etc/rsyslog.d/h3c-sgbox.conf` containing the forwarding rule (e.g. `*.* @<SGBOX_IP>`)
2. Restarts the rsyslog daemon (`systemctl restart rsyslog`)
3. Sends translated messages via the `logger` command

rsyslog handles delivery, queuing, and retry natively.

> **Protocol prefixes in the rsyslog config:**
> - `@` = UDP forwarding (default)
> - `@@` = TCP forwarding
> - `@@` + TLS directives = TLS forwarding

### Push Mode — Python Backend (Legacy)

For environments without rsyslog, set `forwarder_backend = python` to use direct Python sockets:

```ini
[sgbox]
mode = push
host = <SGBOX_IP>
port = 514
protocol = udp
forwarder_backend = python
```

The python backend includes built-in tenacity exponential backoff for automatic reconnection.

### Pull Mode (Legacy)

```ini
[sgbox]
mode = pull
output_port = 1514
```

In pull mode, the translator runs a TCP server on `output_port` and waits for SGBox collectors to connect.

*After any config change, restart the service: `sudo systemctl restart h3c-translator`*

---

## 2. H3C Firewall Setup 🧱

Configure the H3C Comware firewall to send NAT/Session logs to the translator:

```text
system-view

# Option A: TLS (Encrypted — Recommended)
info-center loghost <TRANSLATOR_IP> port 6514 transport tcp tls

# Option B: TCP (Plaintext fallback)
info-center loghost <TRANSLATOR_IP> port 514

# Enable NAT session logging
nat log enable

# Set severity threshold
info-center source nat channel loghost log level informational
```

---

## 3. SGBox SIEM / Collector Setup 🛡️

### 3.1 Configure Log Source

#### For Push Mode (rsyslog — recommended)

SGBox needs to be listening for incoming syslog:

1. Navigate to **LM → Configuration**
2. Add a new **Syslog Source** (or configure your local Collector)
3. Set the listener to accept connections on **UDP port 514** (or TCP/TLS as configured)
4. The translator's rsyslog daemon will forward logs directly

> **Tip:** If using TLS, configure SGBox to listen on port 6514 and set `protocol = tls` + `port = 6514` in the translator config.

#### For Pull Mode (port 1514)

1. Navigate to **LM → Configuration**
2. Add a new **Syslog Source**
3. Set the configuration to connect to `<TRANSLATOR_IP>` on **TCP port 1514**
4. *(Depending on your SGBox version, this may be under Collector settings → Remote Syslog)*

### 3.2 Create the Regex Pattern (REQUIRED) 🚨

H3C is **not** auto-recognized by SGBox. Without this step, SGBox receives data but cannot extract fields.

1. Navigate to **LM → Configuration → Pattern**
2. Click **New Pattern**
3. Select the Translator IP as the Host and click **Search**. You should see raw lines like:
   `proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=5231 dport=443 action=permit`

**Enter the following Regex:**
```regex
proto=(\w+)\s+src=([\d\.]+)\s+dst=([\d\.]+)\s+sport=(\d+)\s+dport=(\d+)\s+action=(\w+)(?:\s+app=(\w+))?(?:\s+.*?hostname=([\w\-]+))?
```

**Map the Captured Groups to SGBox Parameters:**

| Capture Group | Map to SGBox Parameter | Description |
|---|---|---|
| Group 1 | `Protocol` | Network protocol (TCP/UDP) |
| Group 2 | `Source Address` | Initiator IP |
| Group 3 | `Destination Address` | Target IP |
| Group 4 | `Source Port` | Initiator Port |
| Group 5 | `Destination Port` | Target Port |
| Group 6 | `Action` | Firewall action (permit/deny) |
| Group 7 | `Application` | *(Optional)* App name e.g. dns |
| Group 8 | `Device Name` | *(Optional)* Firewall hostname |

Click **Create** and name it `H3C Translated Logs`.

### 3.3 Create Dashboard (Optional)

1. Go to **LM → Analysis → The Events Queries**
2. Search for the pattern `H3C Translated Logs`
3. Build charts grouping by `Source Address`, `Destination Port`, or `Action`

---

## 4. Uploading a Custom TLS Certificate to SGBox 🔐

By default SGBox ships with a self-signed certificate. For production use — especially when the translator pushes logs over TLS on port 6154 — you should upload a proper certificate so the translator can verify SGBox's identity.

> [!IMPORTANT]
> Requires **SGBox version 5.3.0 or later**. Check your version under **SCM → System Info**.

### 4.1 Generate Certificates (Recommended — `generate_certs.sh`)

The project includes an interactive script that generates a **private CA**, a **translator certificate**, and an **SGBox certificate** — all signed by the same CA for a proper chain of trust.

```bash
# From the project directory (or /opt/h3c-sgbox-translator after install)
sudo bash generate_certs.sh --cert-dir /etc/h3c-translator/certs \
    --config /etc/h3c-translator/translator.config
```

The script will:

1. **Generate a Private CA** — 4096-bit RSA, 10-year validity
2. **Generate Translator cert** — signed by the CA, with SANs for localhost + machine IP
3. **Generate SGBox cert** — signed by the CA, prompts for SGBox hostname/IP
4. **Update the CA bundle** — appends the CA cert so the translator trusts both certs

At each step, if files already exist, you will be prompted to **[O]verwrite** or **[S]kip**.

> [!TIP]
> The script also runs during `install.sh` automatically.

<details>
<summary><strong>Manual alternative (if not using the script)</strong></summary>

```bash
# Generate a key + self-signed cert valid for 1 year
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout sgbox.key -out sgbox.crt -days 365 \
  -subj "/CN=sgbox.local/O=MyOrg"
```

</details>

### 4.2 Upload to SGBox

1. Log in to the **SGBox web console** as an administrator
2. Navigate to **SCM → Action → Upload custom certificate**
3. Upload the three files:
   - **Certificate file** → select `sgbox.crt`
   - **Private key file** → select `sgbox.key`
   - **Chain certificate** → select `ca.crt` (the generated CA)
4. Optionally, specify the **web server name** (FQDN) that matches the certificate's CN or SAN
5. Click **Upload** / **Apply**

> [!WARNING]
> After uploading, SGBox restarts its web server. You will briefly lose access to the web console. Wait 30–60 seconds and reconnect.

### 4.3 Verify the Connection

After uploading to SGBox and restarting the translator, verify the TLS chain:

```bash
# Verify SGBox's certificate from the translator host
openssl s_client -connect <SGBOX_IP>:6514 \
  -CAfile /etc/h3c-translator/certs/ca-bundle.pem </dev/null

# Look for: Verify return code: 0 (ok)
```

```bash
# Check certificate details
openssl s_client -connect <SGBOX_IP>:6514 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

> [!NOTE]
> If you used `generate_certs.sh`, the CA is already in the bundle — no manual trust configuration needed.

---

## 5. Verification ✅

### Check Translator Health
```bash
curl -k -H "X-API-Key: <YOUR_KEY>" https://<TRANSLATOR_IP>:8443/api/v1/health
```

### Check Active Connections & Statistics
```bash
curl -k -H "X-API-Key: <YOUR_KEY>" https://<TRANSLATOR_IP>:8443/api/v1/stats
```

**Push mode** — look for:
- `receiver → messages_received`: increasing (H3C is sending logs)
- `forwarder → messages_sent`: matching received count (logs delivered to SGBox)

**Pull mode** — look for:
- `output_server → collectors_connected`: 1 or more (SGBox is connected)
- `output_server → messages_sent`: matching received count

### Check from the Command Line
```bash
# Verify the service is running
sudo systemctl status h3c-translator

# View real-time logs
sudo journalctl -u h3c-translator -f

# Verify port bindings
# Verify port bindings
ss -tlnp | grep -E '(514|1514|6514|8443)'

# Check rsyslog config (push mode with rsyslog backend)
cat /etc/rsyslog.d/h3c-sgbox.conf

# Verify rsyslog is running and forwarding
systemctl status rsyslog
```
