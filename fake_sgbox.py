#!/usr/bin/env python3
"""
Fake SGBox Receiver with optional TLS support.

Simulates the SGBox SIEM receiving translated syslog messages.
Supports both plain TCP and TLS modes.

Usage:
    # Plain TCP:
    python3 fake_sgbox.py --port 5141

    # TLS mode:
    python3 fake_sgbox.py --port 5141 --tls --cert /tmp/h3c-test-certs/server.crt --key /tmp/h3c-test-certs/server.key
"""

import argparse
import socket
import ssl
import threading
import sys


def handle_client(conn, addr, is_tls=False):
    """Handle a single client connection."""
    proto = "TLS" if is_tls else "TCP"
    print(f"[FAKE-SGBOX] ✓ Translator CONNECTED via {proto} from {addr[0]}:{addr[1]}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[FAKE-SGBOX] Connection closed by {addr[0]}:{addr[1]}")
                break
            messages = data.decode("utf-8", errors="replace").strip().split("\n")
            for msg in messages:
                if msg.strip():
                    print(f"[FAKE-SGBOX] ✓ RECEIVED LOG ({proto}): {msg}")
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[FAKE-SGBOX] Connection lost from {addr[0]}:{addr[1]}: {e}")
    except ssl.SSLError as e:
        print(f"[FAKE-SGBOX] ✗ TLS error from {addr[0]}:{addr[1]}: {e}")
    except Exception as e:
        print(f"[FAKE-SGBOX] Error: {e}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Fake SGBox syslog receiver")
    parser.add_argument("--port", type=int, default=5141, help="Port to listen on")
    parser.add_argument("--bind", default="127.0.0.1", help="Bind address")
    parser.add_argument("--tls", action="store_true", help="Enable TLS")
    parser.add_argument("--cert", default="", help="TLS certificate file")
    parser.add_argument("--key", default="", help="TLS private key file")
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.bind, args.port))
    server.listen(5)

    ssl_ctx = None
    match args.tls:
        case True:
            if not args.cert or not args.key:
                print(f"[FAKE-SGBOX] ✗ TLS requires --cert and --key")
                sys.exit(1)
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ssl_ctx.load_cert_chain(args.cert, args.key)
            print(f"[FAKE-SGBOX] ✓ TLS enabled")
            print(f"[FAKE-SGBOX]   Cert: {args.cert}")
            print(f"[FAKE-SGBOX]   Key:  {args.key}")
        case False:
            print(f"[FAKE-SGBOX] Running in plain TCP mode")

    proto = "TLS" if ssl_ctx else "TCP"
    print(f"\n{'='*60}")
    print(f"[FAKE-SGBOX] Listening on {proto}://{args.bind}:{args.port}")
    print(f"[FAKE-SGBOX] Waiting for translator to connect...")
    print(f"{'='*60}\n")

    try:
        while True:
            conn, addr = server.accept()
            match ssl_ctx:
                case None:
                    t = threading.Thread(target=handle_client, args=(conn, addr, False), daemon=True)
                case _:
                    try:
                        tls_conn = ssl_ctx.wrap_socket(conn, server_side=True)
                        print(f"[FAKE-SGBOX] ✓ TLS handshake complete with {addr[0]}:{addr[1]}")
                        t = threading.Thread(target=handle_client, args=(tls_conn, addr, True), daemon=True)
                    except ssl.SSLError as e:
                        print(f"[FAKE-SGBOX] ✗ TLS handshake FAILED from {addr[0]}:{addr[1]}: {e}")
                        conn.close()
                        continue
            t.start()
    except KeyboardInterrupt:
        print(f"\n[FAKE-SGBOX] Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
