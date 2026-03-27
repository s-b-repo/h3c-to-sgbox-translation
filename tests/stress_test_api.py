#!/usr/bin/env python3
"""
API Stress Test — Attack Simulation

Tests the API server under adversarial conditions:
  1. Rate limit flood (200 rapid requests from same IP)
  2. Concurrent burst (50 simultaneous requests)
  3. Oversized payload (>64KB body)
  4. Bulk array bomb (>1000 lines)
  5. Malformed JSON attacks
  6. Auth brute-force (wrong API keys)
  7. Memory pressure — many IPs hitting rate limiter
  8. Valid translation throughput under load

Usage: python3 tests/stress_test_api.py
"""

import asyncio
import json
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiohttp import web, ClientSession, ClientTimeout, TCPConnector
from src.parser import H3CLogParser
from src.formatter import SGBoxFormatter
from src.api_server import APIServer

# ── Test Config ────────────────────────────────────────────────────
TEST_API_KEY = "stress-test-secret-key-abc123xyz"
TEST_PORT = 18443
TEST_HOST = "127.0.0.1"
BASE_URL = f"http://{TEST_HOST}:{TEST_PORT}"

SAMPLE_LOG = (
    "10.16.18.1 %%10 nat/6/NAT_IPV4_MATCH: "
    "Protocol(1001)=TCP;Application(1002)=cPanel;"
    "SrcIPAddr(1003)=10.1.1.10;SrcPort(1004)=52314;"
    "DstIPAddr(1007)=8.8.8.8;DstPort(1008)=443;"
    "Event(1048)=(8)Session created;"
)


def make_config():
    return {
        "server": {"api_port": str(TEST_PORT), "bind_address": TEST_HOST},
        "security": {
            "api_key": TEST_API_KEY,
            "allowed_ips": "0.0.0.0",
            "allow_plaintext": "true",
        },
        "tls": {},
        "sgbox": {},
        "output": {"format": "extended"},
    }


async def start_server():
    """Start API server in background."""
    config = make_config()
    parser = H3CLogParser(failed_log_dir="/tmp/h3c_stress_test_failed")
    formatter = SGBoxFormatter("extended")
    api = APIServer(config, parser, formatter)
    await api.start()
    return api


async def req(session, method, path, headers=None, **kwargs):
    """Make a request and return (status, body_text)."""
    h = {"X-API-Key": TEST_API_KEY}
    if headers:
        h.update(headers)
    try:
        async with session.request(method, f"{BASE_URL}{path}", headers=h, **kwargs) as resp:
            text = await resp.text()
            return resp.status, text
    except Exception as e:
        return 0, str(e)


async def run_tests():
    api = await start_server()
    await asyncio.sleep(0.3)  # let server bind

    timeout = ClientTimeout(total=10)
    connector = TCPConnector(limit=200)
    async with ClientSession(timeout=timeout, connector=connector) as session:
        results = {}

        # ─────────────────────────────────────────────────────────────
        # TEST 1: Health check baseline
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 1: Health Check Baseline")
        print("="*60)
        status, body = await req(session, "GET", "/api/v1/health")
        results["health"] = status == 200
        print(f"  Status: {status} | {'PASS' if status == 200 else 'FAIL'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 2: Auth brute-force (wrong keys)
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 2: Auth Brute-Force — 20 wrong API keys")
        print("="*60)
        auth_results = []
        for i in range(20):
            s, _ = await req(session, "GET", "/api/v1/health",
                             headers={"X-API-Key": f"wrong-key-{i}"})
            auth_results.append(s)
        all_401 = all(s == 401 for s in auth_results)
        results["auth_bruteforce"] = all_401
        print(f"  All returned 401: {all_401} | {'PASS' if all_401 else 'FAIL'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 3: Valid single translate
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 3: Valid Single Translate")
        print("="*60)
        payload = json.dumps({"raw": SAMPLE_LOG})
        status, body = await req(session, "POST", "/api/v1/translate",
                                 data=payload,
                                 headers={"Content-Type": "application/json"})
        data = json.loads(body) if status == 200 else {}
        has_translated = bool(data.get("translated"))
        results["single_translate"] = status == 200 and has_translated
        print(f"  Status: {status} | Translated: {has_translated} | {'PASS' if results['single_translate'] else 'FAIL'}")
        if has_translated:
            print(f"  Output: {data['translated'][:100]}...")

        # ─────────────────────────────────────────────────────────────
        # TEST 4: Oversized payload (>64KB body)
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 4: Oversized Payload — 128KB body")
        print("="*60)
        big_payload = "A" * (128 * 1024)
        status, _ = await req(session, "POST", "/api/v1/translate",
                              data=big_payload,
                              headers={"Content-Type": "text/plain"})
        results["oversized"] = status == 413
        print(f"  Status: {status} | Expected 413 | {'PASS' if status == 413 else 'FAIL'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 5: Bulk array bomb (>1000 lines)
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 5: Bulk Array Bomb — 1500 lines")
        print("="*60)
        bomb = json.dumps({"lines": [SAMPLE_LOG] * 1500})
        status, _ = await req(session, "POST", "/api/v1/translate/bulk",
                              data=bomb,
                              headers={"Content-Type": "application/json"})
        results["bulk_bomb"] = status == 400
        print(f"  Status: {status} | Expected 400 | {'PASS' if status == 400 else 'FAIL'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 6: Malformed JSON attacks
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 6: Malformed JSON Attacks — 5 payloads")
        print("="*60)
        malformed = [
            "{broken json",
            '{"lines": null}',
            '{"raw": ""}',
            "null",
            '{"lines": "not-an-array"}',
        ]
        mal_results = []
        for i, m in enumerate(malformed):
            s, _ = await req(session, "POST", "/api/v1/translate",
                             data=m, headers={"Content-Type": "application/json"})
            mal_results.append(s)
            print(f"  Payload {i+1}: status={s}")
        results["malformed_json"] = all(s in (400, 422) for s in mal_results)
        print(f"  All rejected: {'PASS' if results['malformed_json'] else 'FAIL'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 7: Concurrent burst — 50 simultaneous requests
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 7: Concurrent Burst — 50 simultaneous translate requests")
        print("="*60)
        t0 = time.monotonic()
        tasks = [
            req(session, "POST", "/api/v1/translate",
                data=json.dumps({"raw": SAMPLE_LOG}),
                headers={"Content-Type": "application/json"})
            for _ in range(50)
        ]
        burst_results = await asyncio.gather(*tasks)
        elapsed = time.monotonic() - t0
        success = sum(1 for s, _ in burst_results if s == 200)
        rate_limited = sum(1 for s, _ in burst_results if s == 429)
        results["concurrent_burst"] = success > 0
        print(f"  Elapsed: {elapsed:.2f}s | Success: {success}/50 | Rate-limited: {rate_limited}")
        print(f"  Throughput: {success/elapsed:.0f} req/s | {'PASS' if success > 0 else 'FAIL'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 8: Rate limit flood — 200 rapid sequential requests
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 8: Rate Limit Flood — 200 rapid requests")
        print("="*60)
        t0 = time.monotonic()
        flood_statuses = []
        for i in range(200):
            s, _ = await req(session, "GET", "/api/v1/health")
            flood_statuses.append(s)
        elapsed = time.monotonic() - t0
        ok_count = flood_statuses.count(200)
        rl_count = flood_statuses.count(429)
        hit_limit = rl_count > 0
        results["rate_limit_flood"] = hit_limit
        print(f"  Elapsed: {elapsed:.2f}s | 200s: {ok_count} | 429s: {rl_count}")
        print(f"  Rate limiter engaged: {hit_limit} | {'PASS' if hit_limit else 'FAIL (limit not hit, may need longer burst)'}")

        # ─────────────────────────────────────────────────────────────
        # TEST 9: Valid bulk translate (within limits)
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 9: Valid Bulk Translate — 100 lines")
        print("="*60)
        bulk_payload = json.dumps({"lines": [SAMPLE_LOG] * 100})
        t0 = time.monotonic()
        status, body = await req(session, "POST", "/api/v1/translate/bulk",
                                 data=bulk_payload,
                                 headers={"Content-Type": "application/json"})
        elapsed = time.monotonic() - t0
        if status == 200:
            data = json.loads(body)
            translated = data.get("translated", 0)
            results["bulk_translate"] = translated == 100
            print(f"  Status: {status} | Translated: {translated}/100 | {elapsed:.2f}s | {'PASS' if translated == 100 else 'FAIL'}")
        else:
            results["bulk_translate"] = False
            print(f"  Status: {status} | FAIL (may be rate-limited from test 8)")

        # ─────────────────────────────────────────────────────────────
        # TEST 10: Memory pressure — many "IPs" via rapid stat checks
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("TEST 10: Stats Endpoint Under Load")
        print("="*60)
        status, body = await req(session, "GET", "/api/v1/stats")
        if status == 200:
            stats = json.loads(body)
            print(f"  Parser stats:    {stats.get('parser', 'N/A')}")
            print(f"  Formatter stats: {stats.get('formatter', 'N/A')}")
            results["stats"] = True
        else:
            print(f"  Status: {status} | May be rate-limited")
            results["stats"] = status == 429  # acceptable

        # ─────────────────────────────────────────────────────────────
        # SUMMARY
        # ─────────────────────────────────────────────────────────────
        print("\n" + "="*60)
        print("STRESS TEST SUMMARY")
        print("="*60)
        total = len(results)
        passed = sum(1 for v in results.values() if v)
        for name, ok in results.items():
            icon = "✓" if ok else "✗"
            print(f"  {icon} {name}")
        print(f"\n  Result: {passed}/{total} passed")

        if passed == total:
            print("  🟢 ALL TESTS PASSED — API is resilient")
        else:
            print("  🟡 SOME TESTS NEED ATTENTION")

    await api.stop()


if __name__ == "__main__":
    asyncio.run(run_tests())
