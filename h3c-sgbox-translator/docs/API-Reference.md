# API Reference

The Translator exposes an HTTPS REST API typically running on port `8443`. This interface allows external monitoring tools, SIEMs, or administrators to check the health of the service, retrieve vital statistics, and test translations directly.

> **Authentication Required:** All endpoints require the `X-API-Key` header. Your API key is defined in the `[security]` section of `translator.config`.

## Ping / Health Check

Checks if the service is running and parsing configurations correctly.

**Request:**
```bash
curl -k -H "X-API-Key: <KEY>" https://localhost:8443/api/v1/health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "h3c-sgbox-translator",
  "version": "1.0.0"
}
```

## View Statistics

Returns real-time data flow statistics.

**Request:**
```bash
curl -k -H "X-API-Key: <KEY>" https://localhost:8443/api/v1/stats
```

**Response (200 OK):**
```json
{
  "uptime_seconds": 3600,
  "metrics": {
    "receiver": {
      "logs_received": 15420,
      "bytes_received": 2048560
    },
    "parser": {
      "successful_translations": 15410,
      "failed_translations": 10
    },
    "output_server": {
      "collectors_connected": 1,
      "messages_sent": 15410
    }
  }
}
```

## Translate Single Log

Allows you to submit a raw H3C syslog string and immediately see how the parser engine processes it. Useful for debugging specific rules.

**Request:**
```bash
curl -k -X POST -H "X-API-Key: <KEY>" \
  -H "Content-Type: application/json" \
  https://localhost:8443/api/v1/translate \
  -d '{"raw": "Protocol(1001)=TCP;SrcIPAddr(1003)=10.1.1.10;DstIPAddr(1007)=8.8.8.8;SrcPort(1004)=52314;DstPort(1008)=443;Event(1048)=(8)Session created"}'
```

**Response (200 OK):**
```json
{
  "original": "Protocol(1001)...",
  "translated": "proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=52314 dport=443 action=permit",
  "status": "success"
}
```

## Translate Bulk

Process up to 1000 logs in a single JSON payload. Suitable for batch offline processing.

**Request:**
```bash
curl -k -X POST -H "X-API-Key: <KEY>" \
  -H "Content-Type: application/json" \
  https://localhost:8443/api/v1/translate/bulk \
  -d '{
    "lines": [
      "Protocol(1001)=TCP;SrcIPAddr(1003)=1.1.1.1;DstIPAddr(1007)=2.2.2.2;SrcPort(1004)=80;DstPort(1008)=443;Event(1048)=(8)Session created"
    ]
  }'
```

**Response (200 OK):**
```json
{
  "processed_count": 1,
  "successful_count": 1,
  "failed_count": 0,
  "results": [
    "proto=TCP src=1.1.1.1 dst=2.2.2.2 sport=80 dport=443 action=permit"
  ]
}
```

## Common HTTP Errors

| Code | Reason | Resolution |
|------|--------|------------|
| `401 Unauthorized` | Missing or invalid `X-API-Key`. | Verify the key matches the config file exactly. |
| `403 Forbidden` | Your IP address is not whitelisted. | Add your machine's IP to `allowed_ips` in the config. |
| `429 Too Many Requests` | You triggered the rate limit. | Wait 60 seconds. |
| `400 Bad Request` | Invalid JSON syntax. | Ensure your request body is valid JSON. |
