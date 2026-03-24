# SGBox End-to-End Setup & Configuration Guide

This guide covers configuring the complete **H3C → Translator → SGBox** pipeline. The translator supports two delivery modes: **Push** (recommended) and **Pull** (legacy).

## Architecture Overview

### Push Mode (Recommended — TLS on Port 6154)

The translator actively pushes translated logs to SGBox over an encrypted TLS connection.

```text
[H3C Firewall] ──(syslog TLS/TCP)──► [Translator] ──(TLS push)──► [SGBox SIEM]
                  Port 6514 / 514                     Port 6154
```

### Pull Mode (Legacy — SGBox Connects)

SGBox collectors connect to the translator's TCP socket to pull logs.

```text
[H3C Firewall] ──(syslog TLS/TCP)──► [Translator] ◄──(TCP pull)── [SGBox Collector]
                  Port 6514 / 514                     Port 1514
```

---

## 1. Translator Configuration ⚙️

### Push Mode (Recommended)

```ini
[sgbox]
mode = push
host = <SGBOX_IP>
port = 6154
protocol = tls
facility = local0
severity = info
```

The translator uses the auto-fetched CA bundle at `/etc/h3c-translator/certs/ca-bundle.pem` (created by `install.sh`) to verify SGBox's TLS certificate. No manual certificate configuration is required.

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

#### For Push Mode (port 6154)

SGBox needs to be listening for incoming TLS syslog on port 6154:

1. Navigate to **LM → Configuration**
2. Add a new **Syslog Source** (or configure your local Collector)
3. Set the listener to accept connections on **TCP/TLS port 6154**
4. The translator will push logs directly — no polling required

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

## 4. Verification ✅

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
ss -tlnp | grep -E '(514|1514|6514|6154|8443)'
```
