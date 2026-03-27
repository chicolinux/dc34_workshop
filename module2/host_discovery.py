#!/usr/bin/env python3
"""
Module 2 — Host Discovery
Performs ARP sweep (Layer 2) and ICMP/TCP ping (Layer 3) in parallel.

Usage:
  sudo python3 module2/host_discovery.py 10.0.0.0/24
  sudo python3 module2/host_discovery.py 10.0.0.0/24 --method all
"""

import argparse
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import (
    Ether, IP, TCP, ICMP, ARP, UDP,
    srp1, sr1,
    conf, RandShort,
)

conf.verb = 0

LIVE_HOSTS: dict[str, dict] = {}
LOCK = threading.Lock()


# ── ARP Sweep (Layer 2 — most reliable on local /24) ─────────────────────────

def arp_ping(ip: str, iface: str, timeout: float = 1.0) -> dict | None:
    """Send ARP request; return dict with ip/mac on reply, else None."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    reply = srp1(pkt, iface=iface, timeout=timeout, verbose=False)
    if reply and reply.haslayer(ARP) and reply[ARP].op == 2:
        return {"ip": ip, "mac": reply[ARP].hwsrc, "method": "ARP"}
    return None


# ── ICMP Echo Ping ─────────────────────────────────────────────────────────────

def icmp_ping(ip: str, timeout: float = 1.0) -> dict | None:
    """Send ICMP echo; return dict on reply."""
    pkt = IP(dst=ip, ttl=64) / ICMP()
    reply = sr1(pkt, timeout=timeout, verbose=False)
    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
        return {"ip": ip, "ttl": reply[IP].ttl, "method": "ICMP"}
    return None


# ── TCP SYN Ping ───────────────────────────────────────────────────────────────

def tcp_syn_ping(ip: str, port: int = 80, timeout: float = 1.0) -> dict | None:
    """Send TCP SYN; host is up if we get SYN-ACK or RST."""
    pkt = IP(dst=ip) / TCP(dport=port, sport=RandShort(), flags="S")
    reply = sr1(pkt, timeout=timeout, verbose=False)
    if reply and reply.haslayer(TCP):
        flags = reply[TCP].flags
        if flags & 0x12 == 0x12 or flags & 0x04:   # SYN-ACK or RST
            return {"ip": ip, "method": f"TCP-SYN:{port}"}
    return None


# ── UDP Ping (triggers ICMP unreachable on closed port) ───────────────────────

def udp_ping(ip: str, port: int = 33434, timeout: float = 2.0) -> dict | None:
    """Send UDP to a likely-closed high port; ICMP unreachable means host is up."""
    pkt = IP(dst=ip) / UDP(dport=port, sport=RandShort())
    reply = sr1(pkt, timeout=timeout, verbose=False)
    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 3:
        return {"ip": ip, "method": "UDP-ping"}
    return None


# ── Worker: probe a single IP with all selected methods ───────────────────────

def probe_host(ip: str, methods: list[str], iface: str) -> dict | None:
    """Try each discovery method in order; return first success."""
    for method in methods:
        result = None
        if method == "arp":
            result = arp_ping(ip, iface)
        elif method == "icmp":
            result = icmp_ping(ip)
        elif method == "tcp":
            result = tcp_syn_ping(ip)
        elif method == "udp":
            result = udp_ping(ip)
        if result:
            return result
    return None


# ── Main sweep ────────────────────────────────────────────────────────────────

def sweep(
    network: str,
    methods: list[str],
    iface: str,
    workers: int = 64,
) -> dict[str, dict]:
    """Sweep all IPs in `network` concurrently."""
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(ip) for ip in net.hosts()]

    print(f"[*] Sweeping {len(hosts)} hosts in {network}")
    print(f"[*] Methods: {', '.join(methods)} | Workers: {workers}\n")

    results = {}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_host, ip, methods, iface): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    results[ip] = result
                    print(f"  [UP] {ip:15s}  via {result['method']}"
                          + (f"  mac={result.get('mac','')}" if result.get("mac") else "")
                          + (f"  ttl={result.get('ttl','')}" if result.get("ttl") else ""))
            except Exception as e:
                pass  # silently skip unreachable hosts

    return results


def print_summary(results: dict):
    print(f"\n{'='*50}")
    print(f"Live hosts found: {len(results)}")
    print(f"{'IP':<18} {'Method':<20} {'MAC/TTL'}")
    print("-" * 50)
    for ip, info in sorted(results.items()):
        extra = info.get("mac") or str(info.get("ttl", ""))
        print(f"{ip:<18} {info['method']:<20} {extra}")


def main():
    parser = argparse.ArgumentParser(description="Host discovery with Scapy")
    parser.add_argument("network", help="Target network, e.g. 10.0.0.0/24")
    parser.add_argument(
        "--method",
        choices=["arp", "icmp", "tcp", "udp", "all"],
        default="arp",
        help="Discovery method (default: arp)",
    )
    parser.add_argument("--iface", default=conf.iface, help="Network interface")
    parser.add_argument("--workers", type=int, default=64, help="Thread count")
    args = parser.parse_args()

    methods = ["arp", "icmp", "tcp", "udp"] if args.method == "all" else [args.method]
    results = sweep(args.network, methods, args.iface, args.workers)
    print_summary(results)


if __name__ == "__main__":
    main()
