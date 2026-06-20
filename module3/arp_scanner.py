#!/usr/bin/env python3
"""
Module 3 — Passive ARP Observer

Listens passively for ARP traffic on the local segment and builds
a MAC-to-IP mapping table from observed ARP requests and replies.
No active probes — purely passive reconnaissance.

Red team use: run this while lying low before the active phase.
You'll discover live hosts and their MAC addresses without sending
any traffic yourself.

Usage:
  sudo python3 module3/arp_scanner.py --iface eth0
  sudo python3 module3/arp_scanner.py --iface eth0 --timeout 60
"""

import argparse
import time
import signal
import sys
from collections import defaultdict

from scapy.all import ARP, Ether, sniff, conf

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

# MAC-to-IP and IP-to-MAC tables
mac_to_ip: dict[str, set] = defaultdict(set)
ip_to_mac: dict[str, set] = defaultdict(set)
event_log: list[dict] = []

stop = False


def arp_callback(pkt):
    """Process each ARP packet and update the observation tables."""
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    src_mac = arp.hwsrc.lower()
    src_ip  = arp.psrc
    op      = "request" if arp.op == 1 else "reply"

    # Skip obviously invalid entries
    if src_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return
    if src_ip in ("0.0.0.0", "255.255.255.255"):
        return

    new_entry = src_ip not in ip_to_mac or src_mac not in ip_to_mac[src_ip]

    mac_to_ip[src_mac].add(src_ip)
    ip_to_mac[src_ip].add(src_mac)

    entry = {"time": time.time(), "mac": src_mac, "ip": src_ip, "op": op}
    event_log.append(entry)

    if new_entry:
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}] ARP {op:8s}  {src_ip:15s}  {src_mac}")

        # Detect possible ARP spoofing: multiple MACs for same IP
        if len(ip_to_mac[src_ip]) > 1:
            macs = ", ".join(ip_to_mac[src_ip])
            print(f"  [!] CONFLICT: {src_ip} seen with multiple MACs: {macs}")


def print_table():
    print("\n" + "=" * 55)
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Notes'}")
    print("-" * 55)

    # Sorted by IP
    import ipaddress
    try:
        sorted_ips = sorted(ip_to_mac.keys(), key=lambda x: ipaddress.ip_address(x))
    except Exception:
        sorted_ips = sorted(ip_to_mac.keys())

    for ip in sorted_ips:
        macs = ip_to_mac[ip]
        for mac in macs:
            note = "[CONFLICT]" if len(macs) > 1 else ""
            print(f"  {ip:<16} {mac:<20} {note}")

    print(f"\nTotal unique IPs:  {len(ip_to_mac)}")
    print(f"Total unique MACs: {len(mac_to_ip)}")
    print(f"Total ARP events:  {len(event_log)}")


def main():
    global stop

    parser = argparse.ArgumentParser(description="Passive ARP observer")
    parser.add_argument("--iface",   default=conf.iface, help="Interface to listen on")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0 = run forever)")
    args = parser.parse_args()

    def handle_sigint(sig, frame):
        global stop
        stop = True

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"[*] Passive ARP observer on {args.iface}")
    print("[*] Press Ctrl-C to stop and print summary\n")
    print(f"  {'Time':8s}  {'Op':8s}  {'IP':15s}  {'MAC'}")
    print("  " + "-" * 50)

    kwargs = {"iface": args.iface, "filter": "arp", "prn": arp_callback, "store": False}
    if args.timeout > 0:
        kwargs["timeout"] = args.timeout

    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        pass

    print_table()


if __name__ == "__main__":
    main()
