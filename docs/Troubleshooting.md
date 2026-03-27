# Troubleshooting & Auditing

If logs are not flowing from H3C to SGBox, follow this guide to diagnose and resolve issues.

## Diagnostics Cheat Sheet

```bash
# Check if the service is running
sudo systemctl status h3c-translator

# Tail real-time logs (filter for errors)
sudo journalctl -u h3c-translator -f | grep -i error

# View the application's own log file
tail -f /var/log/h3c-translator/translator.log

# Check rsyslog config and status
cat /etc/rsyslog.d/h3c-sgbox.conf
sudo systemctl status rsyslog

# Test inbound TLS connectivity (from H3C's perspective)
openssl s_client -connect localhost:6514

# Test outbound TLS to SGBox (from translator's perspective)
openssl s_client -connect <SGBOX_IP>:6514 -CAfile /etc/h3c-translator/certs/ca-bundle.pem

# Check which processes are on the required ports
ss -tlnp | grep -E '(514|1514|6514|8443)'

# Verify the CA bundle is valid
openssl x509 -in /etc/h3c-translator/certs/ca-bundle.pem -text -noout | head -20
```

## Common Issues

### Service & Connection Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| `forwarder.backend=python` when rsyslog expected | rsyslog not installed | Run `apt-get -y install rsyslog` and restart the translator |
| `RuntimeError: TLS cert_file not configured` | Missing inbound TLS certificates | Run `install.sh` to generate them, or set `allow_plaintext = true` temporarily |
| `forwarder.connection_lost` in logs | TLS handshake failed to SGBox | Verify SGBox is listening. Test with `openssl s_client -connect <SGBOX_IP>:6514` |
| `ssl.SSLCertVerificationError` | CA bundle cannot verify SGBox's cert | Re-run `install.sh` to refresh the CA bundle, or manually rebuild it (see below) |
| `ConnectionRefusedError` | SGBox not listening on port | Confirm SGBox is configured to accept syslog on the configured port |
| Service starts then exits immediately | Port already in use | Check with `ss -tlnp \| grep 6514` — another process may be binding the port |
| `/etc/rsyslog.d/h3c-sgbox.conf` not created | Permission denied | Run the translator as root or with sudo, or manually write the rsyslog config |

### API Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 Unauthorized` | Wrong/missing API key | Ensure `X-API-Key` header matches the config exactly |
| `403 Forbidden` | Source IP not whitelisted | Add your IP to `allowed_ips` in the config |
| `429 Too Many Requests` | Rate limit hit (120 req/min) | Wait 60 seconds |
| `400 Bad Request` | Invalid JSON body | Validate your JSON syntax |

### Data Flow Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| SGBox shows 0 events | Translator not forwarding | Check `mode` in config — use `push` with `protocol = tls` for direct delivery |
| No logs from H3C | Routing or TLS issue | Test with `tcpdump -i eth0 port 6514`. Try plain TCP `514` to rule out cert issues |
| Logs arrive but unparsed in SGBox | Missing regex pattern | Create the SGBox pattern as described in [SGBox Integration](SGBox-Integration#32-create-the-regex-pattern-required-) |
| Out of Memory (OOM) | Slow SGBox consumer (pull mode) | Ensure you're on v2.0.0 which uses bounded asyncio queues. Consider switching to push mode |

## CA Bundle Issues

If TLS verification fails because the CA bundle is stale or missing:

```bash
# Re-fetch Google Trust Services roots
curl -sSL https://pki.goog/roots.pem -o /etc/h3c-translator/certs/google-roots.pem

# Rebuild the merged bundle
cat /etc/h3c-translator/certs/google-roots.pem \
    /etc/ssl/certs/ca-certificates.crt \
    > /etc/h3c-translator/certs/ca-bundle.pem

# Restart the service
sudo systemctl restart h3c-translator
```

## Code Audit & Known Caveats

A comprehensive architectural audit was performed in March 2026. Major findings and resolutions:

| Issue | Severity | Resolution |
|-------|----------|------------|
| **Slowloris DoS** | Critical | Refactored from `ThreadingMixIn` to `asyncio`-based socket limits with configurable semaphore |
| **Slow-Consumer OOM** | High | Replaced unbounded buffers with capped `asyncio.Queue` per client |
| **Bulk JSON Memory Spikes** | Medium | Restricted payload to 512KB max, capped array at 1000 lines |
| **Daemonization on Windows** | Low | Added explicit OS check with graceful error message |
| **No TLS cert verification** | Medium | Auto-fetched CA bundle (Google roots + system CAs) with PEM validation |
| **rsyslog integration** | Enhancement | Uses system rsyslog daemon for forwarding — follows SGBox Debian integration guide |

## rsyslog Backend Troubleshooting

If you're using the rsyslog backend (default), these steps help diagnose forwarding issues:

```bash
# Verify rsyslog is running
sudo systemctl status rsyslog

# Check the generated config
cat /etc/rsyslog.d/h3c-sgbox.conf

# Test rsyslog forwarding manually
logger -p local0.info -t h3c-test "Test message from h3c-translator"

# Watch rsyslog's own log for errors
tail -f /var/log/syslog | grep -i error

# Force rsyslog to reload config
sudo systemctl restart rsyslog
```

| Symptom | Cause | Fix |
|---------|-------|-----|
| Config file not created | Translator lacks write access to `/etc/rsyslog.d/` | Run as root or use `forwarder_backend = python` |
| rsyslog not forwarding | Config file present but rsyslog not restarted | `sudo systemctl restart rsyslog` |
| Fell back to python backend | rsyslog package not installed | `apt-get -y install rsyslog` |
