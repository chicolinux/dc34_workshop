#!/usr/bin/env python3
"""
Module 6 — TCP/IP Header Covert Channels

Demonstrates encoding data in normally-unused or rarely-inspected
fields of IP and TCP headers.

Channels demonstrated:
  1. IP Identification field  — 16 bits, often sequential or random
  2. IP ToS / DSCP field      — 6 bits, typically 0x00, ignored in transit
  3. TCP Urgent Pointer       — 16 bits, valid when URG flag set, but URG rarely used
  4. IP Reserved bit          — 1 bit (the "Evil Bit" from RFC 3514)
  5. Timing channel           — encode bits in inter-packet delay

Bandwidth is low but stealth is high — these channels cross firewalls
and deep packet inspection that only checks packet content, not field values.

Usage:
  sudo python3 module6/tcp_covert.py --demo ipid   --send "HELLO" --target 10.0.0.2
  sudo python3 module6/tcp_covert.py --demo timing --send "HI"    --target 10.0.0.2
  sudo python3 module6/tcp_covert.py --recv ipid   --iface eth0
"""

import argparse
import struct
import time
import threading

from scapy.all import (
    IP, TCP, ICMP, Raw,
    send, sniff, AsyncSniffer,
    conf, RandShort,
)

conf.verb = 0

# ── Channel 1: IP Identification field ────────────────────────────────────────

def ipid_send(message: str, target: str, delay: float = 0.1):
    """
    Encode message bytes in the IP ID field (2 bytes per packet).
    Each packet carries 2 bytes of the message.
    Uses ICMP echo requests to blend with normal ping traffic.
    """
    data = message.encode()
    # Pad to even length
    if len(data) % 2 != 0:
        data += b"\x00"

    total_pkts = len(data) // 2
    print(f"[*] IP ID channel: sending '{message}' as {total_pkts} ICMP packets")

    for i in range(0, len(data), 2):
        # Pack 2 bytes as a 16-bit big-endian integer into IP ID
        ip_id = struct.unpack(">H", data[i:i+2])[0]
        pkt = IP(dst=target, id=ip_id) / ICMP(seq=i // 2) / Raw(load=b"\x00" * 8)
        send(pkt, verbose=False)
        time.sleep(delay)

    # Send sentinel (IP ID = 0xFFFF signals end of message)
    send(IP(dst=target, id=0xFFFF) / ICMP() / Raw(b"\x00" * 8), verbose=False)
    print("[+] Sent (end sentinel: IP ID=0xFFFF)")


def ipid_recv(iface: str, timeout: int = 30):
    """Listen for ICMP echo requests and decode IP ID values."""
    print(f"[*] IP ID receiver on {iface} (waiting {timeout}s)")
    message_bytes = bytearray()

    def callback(pkt):
        if not (pkt.haslayer(ICMP) and pkt[ICMP].type == 8):
            return
        ip_id = pkt[IP].id
        if ip_id == 0xFFFF:
            decoded = message_bytes.decode(errors="replace").rstrip("\x00")
            print(f"\n[+] Message received: '{decoded}'")
            return
        hi = (ip_id >> 8) & 0xFF
        lo = ip_id & 0xFF
        message_bytes.extend([hi, lo])
        print(f"\r  Received {len(message_bytes)} bytes...", end="", flush=True)

    sniff(iface=iface, filter="icmp", prn=callback, timeout=timeout, store=False)


# ── Channel 2: IP ToS / DSCP Field ────────────────────────────────────────────

def tos_send(message: str, target: str, delay: float = 0.1):
    """
    Encode 6 bits per packet in the DSCP field (upper 6 bits of ToS byte).
    Traffic still routes normally — most routers copy ToS without modification.
    """
    data = message.encode()
    bits = "".join(f"{byte:08b}" for byte in data)

    # Pad bits to multiple of 6
    pad = (6 - len(bits) % 6) % 6
    bits += "0" * pad

    total_pkts = len(bits) // 6
    print(f"[*] ToS/DSCP channel: sending '{message}' as {total_pkts} packets")

    for i in range(0, len(bits), 6):
        chunk = bits[i:i+6]
        dscp = int(chunk, 2)
        tos  = dscp << 2    # DSCP occupies bits 7-2 of ToS

        pkt = IP(dst=target, tos=tos) / ICMP(seq=i // 6)
        send(pkt, verbose=False)
        time.sleep(delay)

    # Sentinel: ToS=0xFF (normally never used)
    send(IP(dst=target, tos=0xFF) / ICMP(), verbose=False)
    print("[+] Sent (end sentinel: ToS=0xFF)")


# ── Channel 3: TCP Urgent Pointer ─────────────────────────────────────────────

def urgent_send(message: str, target: str, port: int = 80, delay: float = 0.1):
    """
    Encode 2 bytes of message per packet in the TCP Urgent Pointer field.
    URG flag is NOT set — most stacks ignore the urgent pointer when URG=0.
    Looks like normal TCP SYN traffic to a firewall.
    """
    data = message.encode()
    if len(data) % 2 != 0:
        data += b"\x00"

    print(f"[*] TCP Urgent Pointer channel: sending '{message}' as {len(data)//2} SYN packets to {target}:{port}")

    for i in range(0, len(data), 2):
        urgptr = struct.unpack(">H", data[i:i+2])[0]
        pkt = IP(dst=target) / TCP(
            dport=port,
            sport=RandShort(),
            flags="S",       # SYN — URG flag deliberately NOT set
            urgptr=urgptr,   # covert data here
            seq=i // 2,
        )
        send(pkt, verbose=False)
        time.sleep(delay)

    # Sentinel
    send(IP(dst=target) / TCP(dport=port, sport=RandShort(), flags="S", urgptr=0xFFFF), verbose=False)
    print("[+] Sent (sentinel: urgptr=0xFFFF)")


# ── Channel 4: Timing Channel ─────────────────────────────────────────────────

SHORT_DELAY = 0.1    # encodes bit = 0
LONG_DELAY  = 0.3    # encodes bit = 1

def timing_send(message: str, target: str):
    """
    Encode bits in inter-packet timing.
    Short delay = 0, Long delay = 1.
    Very low bandwidth (~3 bps at these delays) but impossible to block
    with content-based DPI.
    """
    data  = message.encode()
    bits  = "".join(f"{byte:08b}" for byte in data)
    total = len(bits)

    print(f"[*] Timing channel: sending {total} bits ({len(data)} bytes)")
    print(f"[*] Estimated time: {total * (SHORT_DELAY + LONG_DELAY) / 2:.1f}s")

    for i, bit in enumerate(bits):
        pkt = IP(dst=target) / ICMP(seq=i)
        send(pkt, verbose=False)
        delay = LONG_DELAY if bit == "1" else SHORT_DELAY
        time.sleep(delay)

    # End marker: send 8 packets with max delay
    for _ in range(8):
        send(IP(dst=target) / ICMP(), verbose=False)
        time.sleep(LONG_DELAY * 3)

    print("[+] Timing transmission complete")


def timing_recv(iface: str, threshold: float = 0.2, timeout: int = 120):
    """
    Receive timing channel. Measures inter-packet delay:
    < threshold = bit 0, >= threshold = bit 1.
    """
    print(f"[*] Timing receiver on {iface}  threshold={threshold}s")
    bits = []
    last_time = [None]
    silence_count = [0]

    def callback(pkt):
        if not (pkt.haslayer(ICMP) and pkt[ICMP].type == 8):
            return
        now = time.time()
        if last_time[0] is not None:
            delta = now - last_time[0]
            if delta >= threshold * 2.5:
                # Long silence = end of transmission
                silence_count[0] += 1
                if silence_count[0] >= 3 and bits:
                    # Decode
                    bit_str = "".join(bits)
                    # Group into bytes
                    n = len(bit_str) - (len(bit_str) % 8)
                    decoded = bytes(int(bit_str[i:i+8], 2) for i in range(0, n, 8))
                    print(f"\n[+] Decoded: '{decoded.decode(errors='replace')}'")
                    bits.clear()
                    silence_count[0] = 0
            else:
                bit = "1" if delta >= threshold else "0"
                bits.append(bit)
                silence_count[0] = 0
        last_time[0] = now

    sniff(iface=iface, filter="icmp", prn=callback, timeout=timeout, store=False)


# ── Main ───────────────────────────────────────────────────────────────────────

CHANNELS = {
    "ipid":   (ipid_send,    ipid_recv),
    "tos":    (tos_send,     None),
    "urgent": (urgent_send,  None),
    "timing": (timing_send,  timing_recv),
}

def main():
    parser = argparse.ArgumentParser(description="TCP/IP header covert channel demos")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", choices=list(CHANNELS), help="Send mode: choose channel")
    group.add_argument("--recv", choices=[k for k, v in CHANNELS.items() if v[1]], help="Receive mode")

    parser.add_argument("--send",   default="DEFCON34", help="Message to send (default: DEFCON34)")
    parser.add_argument("--target", default="10.0.0.2")
    parser.add_argument("--port",   type=int, default=80)
    parser.add_argument("--iface",  default=conf.iface)
    parser.add_argument("--delay",  type=float, default=0.1)
    args = parser.parse_args()

    if args.demo:
        send_fn, _ = CHANNELS[args.demo]
        if args.demo == "urgent":
            send_fn(args.send, args.target, args.port, args.delay)
        elif args.demo == "timing":
            send_fn(args.send, args.target)
        else:
            send_fn(args.send, args.target, args.delay)

    elif args.recv:
        _, recv_fn = CHANNELS[args.recv]
        recv_fn(args.iface)


if __name__ == "__main__":
    main()
