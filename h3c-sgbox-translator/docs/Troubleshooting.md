# Troubleshooting & Auditing

If the logs are not flowing from the H3C firewall to SGBox, follow these troubleshooting steps.

## Diagnostics Cheat Sheet

```bash
# Check if the service crashed or restarted
sudo systemctl status h3c-translator

# Tail the real-time application logs filtering for errors
sudo journalctl -u h3c-translator -f | grep -i error

# Or view the Python logger's file output directly
tail -f /var/log/h3c-translator/translator.log

# Test TLS connectivity from the H3C's perspective
openssl s_client -connect localhost:6514

# Check which processes are binding the required ports
ss -tlnp | grep -E '(514|1514|6514|8443)'
```

## Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `RuntimeError: TLS cert_file not configured` | Missing certificates. | Run the `openssl req` command from the installation guide or set `allow_plaintext = true`. |
| API returns `401 Unauthorized` | Wrong/missing API key. | Ensure your curl request includes `-H "X-API-Key: <KEY>"`. |
| API returns `403 Forbidden` | Source IP is rejected. | Add your workstation's IP to the `allowed_ips` comma-separated list. |
| SGBox shows 0 Events | SGBox is not connected. | Ensure `mode = pull` in the translator config, and SGBox is configured to dial port 1514. Check firewall rules. |
| No logs arriving from H3C | Bad routing or TLS misconfiguration. | Verify with `tcpdump -i eth0 port 6514`. Try using plain TCP `514` temporarily to rule out certificate/TLS negotiation failures. |
| Out of Memory (OOM) Kills | Slow SGBox consumer. | Addressed in the April audit—ensure you are on the latest version which uses bounded asyncio queues to drop logs if SGBox stalls. |

## Code Audit & Known Caveats

A comprehensive architectural audit was performed in March 2026. The major findings and their resolutions are summarized below.

* **Slowloris DoS Vulnerability**: The original API Server used Python's `ThreadingMixIn` which spawned infinite threads per HTTP request. An attacker traversing the IP whitelist could crash the app. *Fixed by refactoring to `asyncio`-based socket limits.*
* **Slow-Consumer Memory Exhaustion**: If the SGBox TCP connection stalled but did not drop, Python's internal `drain()` write buffer would grow exponentially, inducing an OOM crash. *Fixed by utilizing capped `asyncio.Queue` structures per client.*
* **Bulk JSON Memory Spikes**: Sending a massive JSON array to the `/translate/bulk` endpoint resulted in large RAM spikes. *Fixed by restricting the maximum payload size to `512KB` and capping the array at 1000 lines.*
* **Daemonization Crashes on Windows**: The `--daemon` CLI flag utilized `os.fork()`, causing instant crashes on Windows environments where the system call natively does not exist. *Fixed by throwing an explicit OS Not Supported exception and failing gracefully.*
