# API Reference

The Translator exposes an HTTPS REST API on port `8443`. This interface provides health monitoring, statistics, and ad-hoc translation testing.

> **Authentication Required:** All endpoints require the `X-API-Key` header. The key is defined in `[security]` → `api_key` in `translator.config`.

## Endpoints

### `GET /api/v1/health` — Health Check

Checks if the service is running and all components are initialized.

**Request:**
```bash
curl -k -H "X-API-Key: <KEY>" https://localhost:8443/api/v1/health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "h3c-sgbox-translator",
  "version": "2.0.0"
}
```

---

### `GET /api/v1/stats` — Real-Time Statistics

Returns data flow statistics for all pipeline components.

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
      "connections_total": 5,
      "messages_received": 15420,
      "tls_errors": 0
    },
    "forwarder": {
      "messages_sent": 15410,
      "messages_failed": 10,
      "reconnections": 1
    }
  }
}
```

**Key metrics to monitor:**
- `receiver.messages_received` — should be increasing (H3C is sending logs)
- `forwarder.messages_sent` — should track close to `messages_received` (logs reaching SGBox)
- `forwarder.reconnections` — occasional reconnects are normal; constant reconnects indicate network issues
- `receiver.tls_errors` — should be 0; non-zero indicates TLS misconfiguration

> **Note:** In pull mode (`mode = pull`), the `forwarder` key is replaced by `output_server` with fields `collectors_connected`, `messages_sent`, and `messages_dropped`.

---

### `POST /api/v1/translate` — Translate Single Log

Submit a raw H3C syslog string and see how the parser processes it. Useful for debugging.

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
  "original": "Protocol(1001)=TCP;SrcIPAddr(1003)=10.1.1.10...",
  "translated": "proto=TCP src=10.1.1.10 dst=8.8.8.8 sport=52314 dport=443 action=permit",
  "status": "success"
}
```

---

### `POST /api/v1/translate/bulk` — Bulk Translation

Process up to **1000 logs** in a single request (max payload 512KB).

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

---

## Error Responses

| Code | Reason | Resolution |
|------|--------|------------|
| `401 Unauthorized` | Missing or invalid `X-API-Key` header | Verify the key matches `api_key` in config |
| `403 Forbidden` | Source IP not in `allowed_ips` whitelist | Add your IP/CIDR to the config |
| `429 Too Many Requests` | Rate limit exceeded (120 req/min/IP) | Wait 60 seconds and retry |
| `400 Bad Request` | Invalid JSON or missing `raw`/`lines` field | Check your request body is valid JSON |
| `413 Payload Too Large` | Bulk request exceeds 512KB or 1000 lines | Split into smaller batches |

## Rate Limiting

The API enforces a rate limit of **120 requests per minute per IP address** to prevent abuse. When exceeded, the API returns `429 Too Many Requests` with a `Retry-After` header.
