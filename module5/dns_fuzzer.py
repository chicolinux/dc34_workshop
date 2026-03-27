#!/usr/bin/env python3
"""
Module 5 — Exercise 5-A: DNS Fuzzer

Fuzzes a DNS server by mutating fields in DNS query packets.
Uses a canary probe after each fuzz packet to detect server crashes.
Saves crash-triggering packets to PCAP files.

Target: Dnsmasq or BIND9 running on the target VM (UDP port 53)

Start DNS server on target:
  sudo dnsmasq --no-daemon --no-resolv --listen-address=0.0.0.0 --port=53

Usage:
  sudo python3 module5/dns_fuzzer.py --target 10.0.0.2
  sudo python3 module5/dns_fuzzer.py --target 10.0.0.2 --iters 500 --seed 42
"""

import argparse
import datetime
import time
import random
import struct
from pathlib import Path

from scapy.all import (
    IP, UDP, DNS, DNSQR, DNSRR,
    fuzz, sr1, send, wrpcap,
    conf,
)

conf.verb = 0

CRASH_DIR = Path("crashes")
CRASH_DIR.mkdir(exist_ok=True)

DNS_PORT = 53


# ── Canary probe ───────────────────────────────────────────────────────────────

def dns_canary(target: str, timeout: float = 2.0) -> bool:
    """
    Send a valid DNS query for 'version.bind' (CH class).
    Returns True if server responds to any DNS query.
    """
    canary = (
        IP(dst=target)
        / UDP(dport=DNS_PORT)
        / DNS(id=0xCAFE, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    reply = sr1(canary, timeout=timeout, verbose=False)
    return reply is not None and reply.haslayer(DNS)


# ── Mutation generators ────────────────────────────────────────────────────────

def generate_boundary_queries(target: str):
    """DNS-specific boundary values for each header field."""
    base = IP(dst=target) / UDP(dport=DNS_PORT)

    # Fuzz ID field
    for id_val in [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]:
        yield base / DNS(id=id_val, rd=1, qd=DNSQR(qname="example.com"))

    # Fuzz QR + opcode flags
    for opcode in range(0, 16):
        yield base / DNS(id=random.randint(1, 0xFFFF), opcode=opcode, rd=1,
                         qd=DNSQR(qname="test.example.com"))

    # Fuzz qtype values
    qtypes = [0, 1, 2, 5, 6, 12, 15, 16, 28, 33, 255, 256, 65535]
    for qt in qtypes:
        yield base / DNS(id=random.randint(1, 0xFFFF), rd=1,
                         qd=DNSQR(qname="example.com", qtype=qt))

    # Fuzz qclass values
    qclasses = [0, 1, 3, 4, 255, 0xFFFF]
    for qc in qclasses:
        yield base / DNS(id=random.randint(1, 0xFFFF), rd=1,
                         qd=DNSQR(qname="example.com", qclass=qc))

    # Long / weird qnames
    long_names = [
        "a" * 63 + ".com",                             # max label length
        "a" * 64 + ".com",                             # exceeds max label length
        ("x" * 63 + ".") * 4 + "com",                 # deep nesting
        "test\x00null.com",                            # null byte in name
        "\xff\xfe\xfd.example.com",                   # high bytes
        "." * 20 + "com",                              # many dots
        "",                                            # empty qname
    ]
    for name in long_names:
        try:
            yield base / DNS(id=random.randint(1, 0xFFFF), rd=1,
                             qd=DNSQR(qname=name))
        except Exception:
            pass

    # QDCOUNT mismatches (claim N questions but send 1)
    for qdcount in [0, 2, 10, 255, 0xFFFF]:
        yield base / DNS(id=random.randint(1, 0xFFFF), rd=1, qdcount=qdcount,
                         qd=DNSQR(qname="example.com"))


def generate_fuzz_queries(target: str, count: int = 200):
    """Scapy fuzz()-based random DNS mutations."""
    base = IP(dst=target) / UDP(dport=DNS_PORT)
    for _ in range(count):
        # fuzz() randomizes every field in DNS while keeping types valid
        yield base / fuzz(DNS(rd=1, qd=DNSQR(qname="fuzz.example.com")))


# ── Core fuzzer ────────────────────────────────────────────────────────────────

def fuzz_dns(target: str, iters: int = 500, seed: int | None = None, delay: float = 0.02):
    if seed is not None:
        random.seed(seed)

    print(f"[*] DNS Fuzzer targeting {target}:{DNS_PORT}")
    print(f"[*] Iterations: {iters}  Seed: {seed}")
    print(f"[*] Crash output: {CRASH_DIR}/\n")

    if not dns_canary(target):
        print(f"[-] DNS server at {target}:{DNS_PORT} not responding to canary query")
        print("    Start with: sudo dnsmasq --no-daemon --listen-address=0.0.0.0")
        return

    print("[+] DNS server alive, starting fuzz...\n")

    crashes     = []
    iteration   = 0
    last_packet = None

    generators = [
        generate_boundary_queries(target),
        generate_fuzz_queries(target, count=iters),
    ]

    for gen in generators:
        for pkt in gen:
            if iteration >= iters:
                break
            iteration += 1
            last_packet = pkt

            try:
                send(pkt, verbose=False)
            except Exception:
                pass

            time.sleep(delay)

            # Canary check every 10 packets
            if iteration % 10 == 0:
                alive = dns_canary(target)
                print(f"\r  iter={iteration:4d}  crashes={len(crashes)}", end="", flush=True)

                if not alive:
                    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                    fname = CRASH_DIR / f"dns_crash_{ts}_iter{iteration}.pcap"
                    if last_packet:
                        wrpcap(str(fname), [last_packet])
                    crashes.append({"iteration": iteration, "file": str(fname)})
                    print(f"\n[!] Crash at iteration {iteration}! Saved to {fname}")

                    # Wait for recovery
                    for _ in range(15):
                        time.sleep(1)
                        if dns_canary(target):
                            print("[+] DNS server recovered")
                            break
                    else:
                        print("[-] DNS server did not recover — restart manually")
                        break

    print(f"\n\n{'='*50}")
    print(f"[*] Done: {iteration} packets, {len(crashes)} crashes")
    if crashes:
        for c in crashes:
            print(f"  iter={c['iteration']}  {c['file']}")
    else:
        print("[*] No crashes detected — server is robust (or canary threshold is too low)")


def main():
    parser = argparse.ArgumentParser(description="DNS server fuzzer")
    parser.add_argument("--target", default="10.0.0.2")
    parser.add_argument("--iters",  type=int,   default=500)
    parser.add_argument("--seed",   type=int,   default=None)
    parser.add_argument("--delay",  type=float, default=0.02, help="Delay between packets (s)")
    args = parser.parse_args()

    fuzz_dns(args.target, iters=args.iters, seed=args.seed, delay=args.delay)


if __name__ == "__main__":
    main()
