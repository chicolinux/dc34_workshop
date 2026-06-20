#!/usr/bin/env python3
"""
Module 1 — Scapy Fundamentals
Reference script: run sections interactively or study the annotated examples.

Requires root. Run as: sudo python3 module1/fundamentals.py
"""

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, Raw, ARP,
    send, sendp, sr, sr1, srp, srp1,
    sniff, AsyncSniffer,
    wrpcap, rdpcap,
    conf, ls, lsc,
    hexdump, RandShort,
)

TARGET = "192.168.56.2"

conf.verb = 0                # suppress per-packet noise in production scripts
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)
IFACE  = conf.iface          # the lab interface (e.g. eth1); override if needed


# ══════════════════════════════════════════════════════════════════════════════
# 1.1  PACKET CONSTRUCTION
# ══════════════════════════════════════════════════════════════════════════════

def section_construction():
    print("\n=== 1.1 Packet Construction ===")

    # Layer stacking uses the / operator.
    # Each layer is a Python class with named fields.
    pkt = Ether() / IP(dst=TARGET) / TCP(dport=80, flags="S")

    # .show() prints every layer and field with computed values
    pkt.show()

    # .show2() forces Scapy to compute auto-fields (chksum, len) before display.
    # This is what the packet looks like *on the wire*.
    pkt.show2()

    # hexdump(pkt) shows the raw bytes — standalone function in Scapy 2.6+
    hexdump(pkt)

    # Access fields by index or by layer class
    print("Destination IP :", pkt[IP].dst)
    print("TCP flags       :", pkt[TCP].flags)
    print("TCP sport       :", pkt[TCP].sport)   # auto-filled by Scapy

    # ls() shows all fields for a given layer class
    # Uncomment to explore:
    # ls(IP)
    # ls(TCP)


# ══════════════════════════════════════════════════════════════════════════════
# 1.2  SEND AND RECEIVE
# ══════════════════════════════════════════════════════════════════════════════

def section_send_receive():
    print("\n=== 1.2 Send and Receive ===")

    # ── Layer 3 (IP-level, OS handles Ethernet framing) ──────────────────────

    # send() fires and forgets — no response expected
    send(IP(dst=TARGET) / ICMP(), verbose=False)
    print("Sent ICMP echo with send()")

    # sr1() sends one packet and returns the first matching reply (or None on timeout)
    reply = sr1(IP(dst=TARGET) / ICMP(), timeout=2, verbose=False)
    if reply:
        print(f"sr1() got reply from {reply[IP].src}, TTL={reply[IP].ttl}")
    else:
        print("sr1() timed out — target may be down or filtering ICMP")

    # sr() sends a list of packets and returns (answered, unanswered)
    probes = [IP(dst=TARGET) / TCP(dport=p, flags="S") for p in [22, 80, 443]]
    answered, unanswered = sr(probes, timeout=2, verbose=False)

    print(f"sr(): {len(answered)} answered, {len(unanswered)} unanswered")
    for sent, recv in answered:
        flags = recv[TCP].flags if recv.haslayer(TCP) else "no-TCP"
        print(f"  port {sent[TCP].dport}: {flags}")

    # ── Layer 2 (full Ethernet frame, need to supply MAC addresses) ───────────

    # sendp() sends at Layer 2 — useful for ARP, custom Ethernet frames
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=TARGET), iface=IFACE, verbose=False)
    print("Sent ARP broadcast with sendp()")

    # srp1() sends at Layer 2 and waits for the first reply
    arp_reply = srp1(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=TARGET),
        iface=IFACE, timeout=2, verbose=False,
    )
    if arp_reply:
        print(f"srp1() ARP reply: {TARGET} is at {arp_reply[ARP].hwsrc}")


# ══════════════════════════════════════════════════════════════════════════════
# 1.3  SNIFFING
# ══════════════════════════════════════════════════════════════════════════════

def section_sniffing():
    print("\n=== 1.3 Sniffing ===")

    # Blocking sniff: captures up to `count` packets matching `filter`, then returns
    print("Sniffing 5 packets (BPF: icmp or arp)...")
    pkts = sniff(iface=IFACE, filter="icmp or arp", count=5, timeout=10)
    print(f"Captured {len(pkts)} packets")
    for p in pkts:
        print(" ", p.summary())

    # Callback-style: prn is called for every captured packet in real time
    def print_src_dst(pkt):
        if pkt.haslayer(IP):
            print(f"  IP {pkt[IP].src} -> {pkt[IP].dst}  proto={pkt[IP].proto}")

    print("\nCapturing 5 IP packets with callback...")
    sniff(iface=IFACE, filter="ip", count=5, timeout=10, prn=print_src_dst)

    # AsyncSniffer: non-blocking, runs in background thread — essential for attack scripts
    sniffer = AsyncSniffer(iface=IFACE, filter="tcp", store=True)
    sniffer.start()
    # ... do other work here (send attack packets, etc.) ...
    import time; time.sleep(2)
    sniffer.stop()
    captured = sniffer.results
    print(f"\nAsyncSniffer captured {len(captured)} TCP packets in 2 seconds")


# ══════════════════════════════════════════════════════════════════════════════
# 1.4  PCAP I/O
# ══════════════════════════════════════════════════════════════════════════════

def section_pcap():
    print("\n=== 1.4 PCAP I/O ===")

    # Build a small packet list to save
    pkts = [IP(dst=TARGET) / ICMP(seq=i) / Raw(load=f"pkt{i}".encode()) for i in range(5)]

    # Write to PCAP
    wrpcap("/tmp/demo.pcap", pkts)
    print("Wrote /tmp/demo.pcap")

    # Read back
    loaded = rdpcap("/tmp/demo.pcap")
    print(f"Loaded {len(loaded)} packets from PCAP")

    # Iterate and filter
    icmp_pkts = [p for p in loaded if p.haslayer(ICMP)]
    print(f"  ICMP packets: {len(icmp_pkts)}")

    # Access specific fields from loaded packets
    for p in icmp_pkts:
        payload = p[Raw].load.decode(errors="replace") if p.haslayer(Raw) else ""
        print(f"  seq={p[ICMP].seq}  payload={payload!r}")


# ══════════════════════════════════════════════════════════════════════════════
# 1.5  SCAPY IN A PYTHON SCRIPT (not the interactive shell)
# ══════════════════════════════════════════════════════════════════════════════

def section_scripting():
    print("\n=== 1.5 Scripting Patterns ===")

    # Always suppress verbose output in scripts
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Safe sr1 wrapper — returns None instead of raising on timeout
    def probe(target, port, timeout=1):
        pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=int(RandShort()))
        return sr1(pkt, timeout=timeout, verbose=False)

    reply = probe(TARGET, 22)
    if reply and reply.haslayer(TCP):
        state = "open" if reply[TCP].flags & 0x12 == 0x12 else "closed"
        print(f"Port 22: {state}")
    else:
        print("Port 22: filtered (no response)")


# ══════════════════════════════════════════════════════════════════════════════
# EXERCISE 1-A: Packet Anatomy Lab (starter code — fill in the TODOs)
# ══════════════════════════════════════════════════════════════════════════════

def exercise_1a():
    print("\n=== Exercise 1-A: Packet Anatomy Lab ===")

    # TODO 1: Build Ether/IP/TCP targeting TARGET port 80
    pkt = ...  # your code here

    # TODO 2: Print with .show2() and note auto-filled fields

    # TODO 3: Override ttl=64, flags="DF", seq=1000

    # TODO 4: Send with sr1(), capture response
    #         reply = sr1(pkt, timeout=2, verbose=False)

    # TODO 5: Print reply TCP flags field
    #         print(reply[TCP].flags)

    print("Complete the TODOs in exercise_1a()")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Module 1 fundamentals demo")
    parser.add_argument(
        "--section",
        choices=["construction", "send_receive", "sniffing", "pcap", "scripting", "1a", "all"],
        default="all",
    )
    args = parser.parse_args()

    sections = {
        "construction":  section_construction,
        "send_receive":  section_send_receive,
        "sniffing":      section_sniffing,
        "pcap":          section_pcap,
        "scripting":     section_scripting,
        "1a":            exercise_1a,
    }

    if args.section == "all":
        for fn in sections.values():
            fn()
    else:
        sections[args.section]()
