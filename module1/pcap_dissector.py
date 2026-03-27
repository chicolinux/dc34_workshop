#!/usr/bin/env python3
"""
Module 1 — Exercise 1-B: PCAP Dissector

Given a PCAP file, extract:
  1. All unique source IPs
  2. Reassembled HTTP request body from TCP payload chunks
  3. Write filtered TCP-only packets to a new PCAP

Usage:
  sudo python3 module1/pcap_dissector.py samples/http_session.pcap

Complete the TODO sections to finish the exercise.
"""

import sys
from scapy.all import rdpcap, wrpcap, IP, TCP, Raw, conf

conf.verb = 0


def load_pcap(path: str):
    """Load packets from a PCAP file."""
    try:
        pkts = rdpcap(path)
        print(f"[+] Loaded {len(pkts)} packets from {path}")
        return pkts
    except FileNotFoundError:
        print(f"[-] File not found: {path}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error loading PCAP: {e}")
        sys.exit(1)


def unique_source_ips(pkts) -> set:
    """
    TODO: Return a set of all unique source IP addresses
    found across all packets that have an IP layer.

    Hint: iterate pkts, check p.haslayer(IP), access p[IP].src
    """
    # === YOUR CODE HERE ===
    sources = set()
    for p in pkts:
        if p.haslayer(IP):
            sources.add(p[IP].src)
    # === END YOUR CODE ===
    return sources


def reassemble_http_body(pkts) -> bytes:
    """
    TODO: Reassemble the HTTP request from TCP Raw payloads.

    Strategy:
      - Filter packets that are TCP and have a Raw layer
      - Sort by TCP sequence number
      - Concatenate the Raw payloads in sequence order
      - Return the combined bytes

    Note: This is a simplified reassembly — it works for the provided
    sample where no retransmissions or out-of-order delivery occur.
    """
    # === YOUR CODE HERE ===
    tcp_data = []
    for p in pkts:
        if p.haslayer(TCP) and p.haslayer(Raw):
            tcp_data.append((p[TCP].seq, p[Raw].load))

    # Sort by sequence number
    tcp_data.sort(key=lambda x: x[0])

    # Deduplicate and concatenate
    seen_seqs = set()
    body = b""
    for seq, payload in tcp_data:
        if seq not in seen_seqs:
            seen_seqs.add(seq)
            body += payload
    # === END YOUR CODE ===
    return body


def filter_tcp_packets(pkts):
    """
    TODO: Return a list containing only packets that have a TCP layer.
    """
    # === YOUR CODE HERE ===
    return [p for p in pkts if p.haslayer(TCP)]
    # === END YOUR CODE ===


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file> [output.pcap]")
        sys.exit(1)

    input_file  = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "filtered.pcap"

    pkts = load_pcap(input_file)

    # Task 1 — unique source IPs
    print("\n[*] Task 1: Unique source IPs")
    src_ips = unique_source_ips(pkts)
    for ip in sorted(src_ips):
        print(f"    {ip}")

    # Task 2 — HTTP body reassembly
    print("\n[*] Task 2: Reassembled HTTP payload")
    body = reassemble_http_body(pkts)
    if body:
        # Print the first 1024 bytes as text
        printable = body[:1024].decode("utf-8", errors="replace")
        print(printable)
    else:
        print("    (no TCP payload data found)")

    # Task 3 — filter and save TCP packets
    print(f"\n[*] Task 3: Saving TCP-only packets to {output_file}")
    tcp_pkts = filter_tcp_packets(pkts)
    wrpcap(output_file, tcp_pkts)
    print(f"    Wrote {len(tcp_pkts)} TCP packets to {output_file}")


if __name__ == "__main__":
    main()
