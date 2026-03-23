# SGBox End-to-End Setup & Configuration Guide

This guide covers the complete setup of the H3C → Translator → SGBox pipeline using the recommended **Pull Mode**, where SGBox Collectors connect to the Translator to retrieve logs.

## Architecture: The Pull Model

```text
[H3C Firewall] ──(pushes syslog)──► [Translator] ◄──(pulls logs)── [SGBox Collector / SIEM]
                  Port 6514 / 514          Port 1514
```

---

## 1. Translator Configuration ⚙️

The translator acts as a middleman. It receives logs from the firewall, translates them, and holds them on a TCP port for SGBox to collect.

Ensure your `translator.config` matches these core settings:

### SGBox Settings (Listening for SGBox Collector)
```ini
[sgbox]
# MUST be set to pull — SGBox connects to the translator
mode = pull

# The TCP port SGBox will connect to
output_port = 1514
```

*After configuring, restart the service: `systemctl restart h3c-translator`*

---

## 2. H3C Firewall Setup 🧱

Configure the H3C Comware firewall to send NAT/Session logs to the Translator's IP address.

Access the firewall CLI:
```text
system-view

# Option A: TLS (Encrypted - Recommended)
info-center loghost <TRANSLATOR_IP> port 6514 transport tcp tls

# Option B: TCP (Plaintext)
info-center loghost <TRANSLATOR_IP> port 514

# Enable NAT session logging
nat log enable

# Set severity threshold
info-center source nat channel loghost log level informational
```

---

## 3. SGBox SIEM / Collector Setup 🛡️

SGBox requires two things: 
1. Connecting to the translator to pull the logs.
2. A Regex Pattern to parse the translated Key=Value fields.

### 3.1 Configure Log Source (Pulling logs)
In the SGBox web interface, you need to configure a log source to pull from a remote TCP port:

1. Navigate to **LM → Configuration**
2. Add a new **Syslog Source** (or configure your local Collector).
3. Set the configuration to connect to `<TRANSLATOR_IP>` on TCP port `1514`.
   *(Note: Depending on your exact SGBox version, this may be under Collector settings → Remote Syslog).*

### 3.2 Create the Regex Pattern (REQUIRED) 🚨
H3C is **not** auto-recognized by SGBox. Without this step, SGBox receives the data but cannot extract the fields.

1. Navigate to **LM → Configuration → Pattern**
2. Click **New Pattern**
3. Select the Translator IP as the Host and click **Search**. You should see raw lines like:
   `proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=5231 dport=443 action=permit`

**Enter the following Regex:**
```regex
proto=(\w+)\s+src=([\d\.]+)\s+dst=([\d\.]+)\s+sport=(\d+)\s+dport=(\d+)\s+action=(\w+)(?:\s+app=(\w+))?(?:\s+.*?hostname=([\w\-]+))?
```

**Map the Captured Groups to SGBox Parameters:**
*Important: Use existing parameters from the dropdown to save performance.*

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
Once the pattern is active:
1. Go to **LM → Analysis → The Events Queries**
2. Search for the pattern `H3C Translated Logs`
3. You can now build charts grouping by `Source Address`, `Destination Port`, or `Action`.

---

## 4. Verification Check ✅

To confirm the pipeline is flowing:

**1. Check Translator Health:**
```bash
curl -k -H "X-API-Key: <YOUR_KEY>" https://<TRANSLATOR_IP>:8443/api/v1/health
```

**2. Check Active Connections:**
```bash
curl -k -H "X-API-Key: <YOUR_KEY>" https://<TRANSLATOR_IP>:8443/api/v1/stats
```
*Look at the output:*
- `receiver -> received`: Should be increasing (H3C is sending logs)
- `output_server -> collectors_connected`: Should be `1` or more (SGBox is dialed in)
- `output_server -> messages_sent`: Should match `received` (Logs are successfully flowing to SGBox)
