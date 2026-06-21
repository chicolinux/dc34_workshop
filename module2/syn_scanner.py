#!/usr/bin/env python3
"""
Module 2 — Exercise 2-A: SYN Port Scanner

Half-open TCP scan: sends SYN, reads SYN-ACK / RST, never completes the handshake.
Because the OS never sees a completed connection, the target's application layer
never receives a connection request — stealthier than a full-connect scan.

Usage:
  sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 1-1024
  sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 22,80,443,8080
  sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 1-65535 --timeout 0.5
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from scapy.all import IP, TCP, sr, conf, RandShort

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)


def parse_ports(port_spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' into a list of ints."""
    ports = []
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def syn_scan(
    target: str,
    ports: list[int],
    timeout: float = 2.0,
    chunk_size: int = 500,
) -> dict[int, str]:
    """
    Send SYN probes to all ports, return dict of {port: state}.

    States:
      open     — received SYN-ACK (0x12)
      closed   — received RST (0x04)
      filtered — no response within timeout
    """
    results: dict[int, str] = {}

    # Build all SYN probes at once
    probes = [
        IP(dst=target) / TCP(dport=p, sport=int(RandShort()), flags="S", seq=1000)
        for p in ports
    ]

    print(f"[*] Sending {len(probes)} SYN probes to {target} (chunk_size={chunk_size})")

    # Send in chunks to avoid overwhelming the kernel socket buffer
    answered_all = []
    unanswered_all = []

    for i in range(0, len(probes), chunk_size):
        chunk = probes[i : i + chunk_size]
        ans, unans = sr(chunk, timeout=timeout, verbose=False)
        answered_all.extend(ans)
        unanswered_all.extend(unans)

    # Classify answered
    for sent, recv in answered_all:
        dport = sent[TCP].dport
        if recv.haslayer(TCP):
            flags = recv[TCP].flags
            if flags & 0x12 == 0x12:   # SYN + ACK
                results[dport] = "open"
                # Send RST to cleanly close the half-open connection
                # (prevents target's state table from accumulating SYN-RECEIVED entries)
                from scapy.all import send as scapy_send
                rst = IP(dst=target) / TCP(
                    dport=dport,
                    sport=sent[TCP].sport,
                    flags="R",
                    seq=recv[TCP].ack,
                )
                scapy_send(rst, verbose=False)
            elif flags & 0x04:          # RST
                results[dport] = "closed"
        elif recv.haslayer(ICMP):
            # ICMP type 3 code 1/2/3/9/10/13 = administratively filtered
            results[dport] = "filtered"

    # Everything that got no response
    for sent in unanswered_all:
        dport = sent[TCP].dport
        if dport not in results:
            results[dport] = "filtered"

    return results


def print_results(target: str, results: dict[int, str]):
    open_ports   = {p: s for p, s in results.items() if s == "open"}
    closed_ports = {p: s for p, s in results.items() if s == "closed"}
    filtered     = {p: s for p, s in results.items() if s == "filtered"}

    print(f"\n{'='*50}")
    print(f"SYN Scan Results for {target}")
    print(f"{'='*50}")
    print(f"{'PORT':<10} {'STATE':<12}")
    print(f"{'-'*22}")
    for port in sorted(open_ports):
        print(f"{port:<10} {'open':<12}")
    for port in sorted(closed_ports)[:20]:   # only show first 20 closed
        print(f"{port:<10} {'closed':<12}")
    if len(closed_ports) > 20:
        print(f"  ... and {len(closed_ports) - 20} more closed ports")

    print(f"\nSummary: {len(open_ports)} open | {len(closed_ports)} closed | {len(filtered)} filtered")


def main():
    parser = argparse.ArgumentParser(description="Scapy SYN port scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--ports", default="1-1024", help="Port range or list (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-chunk timeout (default: 2s)")
    parser.add_argument("--chunk", type=int, default=500, help="Probes per sr() call (default: 500)")
    parser.add_argument("--output", default="results.json", help="Output JSON file")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] Target: {args.target}")
    print(f"[*] Ports:  {len(ports)} ports ({args.ports})")

    start = time.time()
    results = syn_scan(args.target, ports, timeout=args.timeout, chunk_size=args.chunk)
    elapsed = time.time() - start

    print_results(args.target, results)
    print(f"\n[*] Scan completed in {elapsed:.1f}s")

    # Save JSON
    output = {
        "target": args.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "ports": {str(p): s for p, s in results.items()},
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[*] Results saved to {args.output}")


# Needed for RST sending inside scan function
from scapy.all import ICMP  # noqa: E402 (import after sys.path set)

if __name__ == "__main__":
    main()
