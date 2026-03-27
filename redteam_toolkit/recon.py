"""
Red Team Toolkit — Recon Module

Wraps host discovery, port scanning, and OS fingerprinting from Module 2.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from module2.host_discovery  import sweep as _sweep
from module2.syn_scanner     import syn_scan as _syn_scan, parse_ports
from module2.os_fingerprint  import fingerprint as _fingerprint


def sweep(network: str, method: str = "arp", iface: str = None, workers: int = 64) -> dict:
    """
    Discover live hosts on a network.

    Args:
        network:  CIDR range, e.g. '10.0.0.0/24'
        method:   'arp' | 'icmp' | 'tcp' | 'udp' | 'all'
        iface:    interface name (auto-detect if None)
        workers:  thread count

    Returns:
        dict of {ip: {'method': ..., 'mac': ..., 'ttl': ...}}
    """
    from scapy.all import conf
    iface = iface or conf.iface
    methods = ["arp", "icmp", "tcp", "udp"] if method == "all" else [method]
    return _sweep(network, methods, iface, workers)


def syn_scan(target: str, ports: str = "1-1024", timeout: float = 2.0) -> dict:
    """
    SYN port scan.

    Args:
        target:  target IP
        ports:   port range string: '1-1024' or '22,80,443'
        timeout: per-chunk timeout in seconds

    Returns:
        dict of {port: 'open'|'closed'|'filtered'}
    """
    port_list = parse_ports(ports)
    return _syn_scan(target, port_list, timeout=timeout)


def os_fingerprint(target: str, port: int = 80) -> None:
    """
    Print OS fingerprinting results for target.

    Args:
        target:  target IP
        port:    TCP port to probe (should be open)
    """
    _fingerprint(target, port)


def full_recon(target_or_network: str, ports: str = "1-1024") -> dict:
    """
    Run a complete recon workflow:
      1. Host discovery (if network given)
      2. SYN scan on discovered hosts
      3. OS fingerprint on each host

    Args:
        target_or_network:  single IP or CIDR range
        ports:              port range to scan

    Returns:
        dict of {ip: {'ports': {...}, 'os_info': ...}}
    """
    import ipaddress

    results = {}

    # Determine if input is a network or single IP
    try:
        ipaddress.ip_network(target_or_network, strict=False)
        is_network = "/" in target_or_network
    except ValueError:
        is_network = False

    if is_network:
        print(f"[*] Phase 1: Host discovery on {target_or_network}")
        live_hosts = sweep(target_or_network)
        targets = list(live_hosts.keys())
        print(f"[+] Found {len(targets)} live hosts")
    else:
        targets = [target_or_network]

    for ip in targets:
        print(f"\n[*] Phase 2: Port scan on {ip}")
        port_results = syn_scan(ip, ports)
        open_ports   = {p: s for p, s in port_results.items() if s == "open"}

        results[ip] = {
            "ports":   port_results,
            "open":    open_ports,
        }

        print(f"[+] {ip}: {len(open_ports)} open ports")

    return results
