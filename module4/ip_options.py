#!/usr/bin/env python3
"""
Module 4 — IP Options Demo

Demonstrates offensive use of IP options:
  - Loose Source and Record Route (LSRR): force a packet through a specific path
  - Record Route (RR): capture the path a packet traverses (7-hop limit)
  - Timestamp: record timestamps at each hop

Red team relevance:
  - LSRR can reach otherwise-unreachable hosts via a compromised relay
  - RR reveals internal routing paths not visible in normal traceroute
  - Both are dropped by most internet routers but often pass within enterprise LAN

Usage:
  sudo python3 module4/ip_options.py --demo lsrr --target 10.0.0.2 --via 10.0.0.1
  sudo python3 module4/ip_options.py --demo rr   --target 10.0.0.2
  sudo python3 module4/ip_options.py --demo frag --target 10.0.0.2
"""

import argparse
from scapy.all import (
    IP, TCP, ICMP, Raw,
    IPOption_LSRR, IPOption_RR, IPOption_Timestamp,
    send, sr1, fragment,
    conf,
)

conf.verb = 0


# ── Loose Source and Record Route (LSRR) ──────────────────────────────────────

def demo_lsrr(target: str, via: str):
    """
    LSRR forces the packet to pass through `via` before reaching `target`.
    The packet's destination field is set to the first waypoint;
    subsequent hops are listed in the LSRR option.
    """
    print(f"[*] LSRR: routing packet through {via} to reach {target}")

    pkt = (
        IP(
            dst=via,    # first hop is the forced waypoint
            options=IPOption_LSRR(routers=[via, target], pointer=4),
        )
        / ICMP()
    )

    pkt.show()
    reply = sr1(pkt, timeout=2, verbose=False)

    if reply:
        print(f"[+] Reply from: {reply[IP].src}")
        if reply.haslayer(IPOption_LSRR):
            print(f"    LSRR route recorded: {reply[IPOption_LSRR].routers}")
    else:
        print("[-] No reply (LSRR likely dropped by intermediate device)")

    print("\n[!] Note: Most routers drop LSRR packets. Works best within a flat LAN.")


# ── Record Route ──────────────────────────────────────────────────────────────

def demo_record_route(target: str):
    """
    Record Route asks each router to append its address to the option field.
    Limited to 9 hops due to IP header size constraints.
    """
    print(f"[*] Record Route: sending ICMP echo to {target} with RR option")

    pkt = IP(dst=target, options=IPOption_RR(routers=["0.0.0.0"] * 9)) / ICMP()

    pkt.show()
    reply = sr1(pkt, timeout=2, verbose=False)

    if reply and reply.haslayer(IPOption_RR):
        route = [r for r in reply[IPOption_RR].routers if r != "0.0.0.0"]
        print(f"[+] Route recorded ({len(route)} hops): {' -> '.join(route)}")
    elif reply:
        print(f"[+] Reply received from {reply[IP].src} but no RR option in response")
        print("    (target may strip IP options in replies)")
    else:
        print("[-] No reply")


# ── IP Timestamp ──────────────────────────────────────────────────────────────

def demo_timestamp(target: str):
    """
    IP Timestamp requests each hop to append its address + timestamp.
    Can reveal internal RFC 1918 addresses of transit routers.
    """
    print(f"[*] IP Timestamp: sending ICMP echo to {target}")

    pkt = (
        IP(dst=target, options=IPOption_Timestamp(flg=3, internet_address=1))
        / ICMP()
    )

    pkt.show()
    reply = sr1(pkt, timeout=2, verbose=False)

    if reply and reply.haslayer(IPOption_Timestamp):
        ts = reply[IPOption_Timestamp]
        print(f"[+] Timestamp option in reply: {ts}")
    elif reply:
        print(f"[+] Reply from {reply[IP].src}, no timestamp option preserved")
    else:
        print("[-] No reply")


# ── IP Fragmentation for Evasion ──────────────────────────────────────────────

def demo_fragmentation(target: str):
    """
    Fragment a TCP SYN so that the TCP header is split across two fragments.
    IDS sensors that only inspect the first fragment will miss the TCP flags/ports.
    The target reassembles correctly and processes the packet.
    """
    print(f"[*] Fragmentation: splitting TCP SYN header across fragments")

    # Build a packet with enough payload to force meaningful fragmentation
    pkt = (
        IP(dst=target)
        / TCP(dport=80, flags="S")
        / Raw(load=b"X" * 60)
    )

    # fragsize=8 creates many 8-byte fragments — TCP header (20 bytes) split
    frags = fragment(pkt, fragsize=8)
    print(f"[+] Created {len(frags)} IP fragments (fragsize=8 bytes)")

    for i, frag in enumerate(frags):
        offset = frag[IP].frag * 8
        more   = "MF" if frag[IP].flags & 0x01 else "last"
        print(f"    Fragment {i+1}: offset={offset}  flags={more}  len={len(frag[IP].payload)}")

    print(f"\n[*] Sending {len(frags)} fragments to {target}...")
    from scapy.all import send as scapy_send
    scapy_send(frags, verbose=False)
    print("[+] Sent. Check tcpdump/Wireshark on target to confirm reassembly.")

    print("\n[!] Evasion note: IDS rules matching 'tcp[13]=0x02' (SYN flag) on the")
    print("    first fragment will MISS this scan — the TCP header only appears in")
    print("    the second fragment. The target OS reassembles and processes it normally.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IP options and fragmentation demo")
    parser.add_argument("--demo", choices=["lsrr", "rr", "ts", "frag", "all"], default="all")
    parser.add_argument("--target", default="10.0.0.2")
    parser.add_argument("--via",    default="10.0.0.1", help="Waypoint for LSRR demo")
    args = parser.parse_args()

    demos = {
        "lsrr": lambda: demo_lsrr(args.target, args.via),
        "rr":   lambda: demo_record_route(args.target),
        "ts":   lambda: demo_timestamp(args.target),
        "frag": lambda: demo_fragmentation(args.target),
    }

    if args.demo == "all":
        for name, fn in demos.items():
            print(f"\n{'='*55}")
            fn()
    else:
        demos[args.demo]()


if __name__ == "__main__":
    main()
