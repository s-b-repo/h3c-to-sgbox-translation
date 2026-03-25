#!/usr/bin/env python3
"""
Spoofed Syslog Test Sender

Sends syslog messages with a spoofed source IP to test the H3C translator.
Supports both UDP (scapy, requires root) and TCP (socket, no root needed).

Usage:
    # UDP with spoofed IP (requires sudo):
    sudo ./spoof_test.py -t 10.10.0.59 -p 514 -s 10.10.0.99

    # TCP mode (no spoofing, no root needed):
    ./spoof_test.py -t 10.10.0.59 -p 514 --tcp
"""

import argparse
import socket
import sys


def send_tcp_syslog(target_ip, target_port, message):
    """Send a syslog message over TCP (no spoofing, no root needed)."""
    print(f"[*] Sending TCP syslog message...")
    print(f"    Target: {target_ip}:{target_port}")
    print(f"    Message: {message}\n")

    if not message.startswith("<"):
        payload = f"<14> {message}"
    else:
        payload = message

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, target_port))
        sock.sendall((payload + "\n").encode("utf-8"))
        sock.close()
        print("[+] TCP message sent successfully.")
    except Exception as e:
        print(f"[-] TCP send failed: {e}")


def send_udp_syslog(target_ip, target_port, message):
    """Send a plain UDP syslog message (no spoofing, no root needed)."""
    print(f"[*] Sending UDP syslog message...")
    print(f"    Target: {target_ip}:{target_port}")
    print(f"    Message: {message}\n")

    if not message.startswith("<"):
        payload = f"<14> {message}"
    else:
        payload = message

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload.encode("utf-8"), (target_ip, target_port))
        sock.close()
        print("[+] UDP message sent successfully.")
    except Exception as e:
        print(f"[-] UDP send failed: {e}")


def send_spoofed_udp_syslog(target_ip, target_port, spoofed_ip, message):
    """Send a UDP syslog message with a spoofed source IP (requires root + scapy)."""
    try:
        from scapy.all import IP, UDP, send, Raw
    except ImportError:
        print("[-] Error: Scapy is not installed. Install with: sudo apt install python3-scapy")
        print("    Falling back to plain UDP (no spoofing)...")
        send_udp_syslog(target_ip, target_port, message)
        return

    print(f"[*] Crafting spoofed UDP syslog packet...")
    print(f"    Target:     {target_ip}:{target_port}")
    print(f"    Spoofed IP: {spoofed_ip}")
    print(f"    Message:    {message}\n")

    if not message.startswith("<"):
        payload = f"<14> {message}"
    else:
        payload = message

    packet = IP(src=spoofed_ip, dst=target_ip) / UDP(sport=514, dport=target_port) / Raw(load=payload.encode("utf-8"))

    try:
        send(packet, verbose=False)
        print("[+] Spoofed packet sent successfully.")
    except PermissionError:
        print("[-] Error: Must run with sudo for IP spoofing.")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Send test syslog messages to the H3C translator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # UDP with spoofed source IP (requires sudo + scapy):
  sudo ./spoof_test.py -t 10.10.0.59 -p 514 -s 10.10.0.99

  # Plain UDP (no spoofing, no root needed):
  ./spoof_test.py -t 10.10.0.59 -p 514

  # TCP mode (no spoofing, no root needed):
  ./spoof_test.py -t 10.10.0.59 -p 514 --tcp

  # Custom H3C-style message:
  ./spoof_test.py -t 10.10.0.59 -p 514 -m "10.0.0.1 nat/6/NAT %%10 FILTER/6/FILTER_ZONE_INTERZONE: Protocol(1001)=6;Application(1002)=cPanel;SrcIPAddr(1003)=192.168.1.5;DstIPAddr(1007)=8.8.8.8;SrcPort(1004)=12345;DstPort(1008)=443;Event(1048)=(8)Session created;"
""",
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP of the translator VM")
    parser.add_argument("-p", "--port", type=int, default=514, help="Target port (default: 514)")
    parser.add_argument("-s", "--spoof", default=None, help="Source IP to spoof (requires sudo + scapy)")
    parser.add_argument("--tcp", action="store_true", help="Use TCP instead of UDP")
    parser.add_argument("-m", "--message", default=None, help="Custom syslog message to send")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of messages to send")

    args = parser.parse_args()

    # Default test message that the H3C parser will recognize
    if args.message is None:
        args.message = (
            "10.10.0.99 nat/6/NAT FW-TEST %%10 FILTER/6/FILTER_ZONE_INTERZONE: "
            "Protocol(1001)=6;Application(1002)=HTTPS;SrcIPAddr(1003)=192.168.1.100;"
            "SrcPort(1004)=54321;DstIPAddr(1007)=10.0.0.1;DstPort(1008)=443;"
            "NatSrcIPAddr(1005)=102.134.120.50;NatSrcPort(1006)=40000;"
            "Event(1048)=(8)Session created;Category(1174)=web;"
        )

    for i in range(args.count):
        if args.count > 1:
            print(f"\n--- Message {i+1}/{args.count} ---")

        if args.tcp:
            send_tcp_syslog(args.target, args.port, args.message)
        elif args.spoof:
            send_spoofed_udp_syslog(args.target, args.port, args.spoof, args.message)
        else:
            send_udp_syslog(args.target, args.port, args.message)
