#!/usr/bin/env python3
"""
Module 2 — Exercise 2-B: OS Fingerprinting

Passive OS inference from:
  - TTL value on ICMP echo reply
  - TCP initial window size in SYN-ACK
  - TCP options order and values in SYN-ACK

This is a simplified p0f-style fingerprinter. Not comprehensive, but
illustrates exactly how tools like Nmap -O and p0f work under the hood.

Usage:
  sudo python3 module2/os_fingerprint.py 10.0.0.2
  sudo python3 module2/os_fingerprint.py 10.0.0.2 --port 443
"""

import argparse
from scapy.all import IP, TCP, ICMP, sr1, conf, RandShort

conf.verb = 0


# ── Signature database ─────────────────────────────────────────────────────────
# Format: (ttl_max, window_size, options_order_signature) → OS description
#
# ttl_max: TTL values decay in transit; we bucket by starting TTL
# window: initial TCP receive window in SYN-ACK
# opts: list of TCP option kinds in order (2=MSS, 4=SACK, 8=Timestamp, 3=WScale, 1=NOP, 0=EOL)

OS_SIGNATURES = [
    # (ttl_bucket, window_min, window_max, option_kinds, label)
    (64,  5720,  5840,   [2, 4, 8, 1, 3], "Linux 5.x (Debian/Ubuntu/Kali)"),
    (64,  14480, 14480,  [2, 4, 8, 1, 3], "Linux 4.x (older kernel)"),
    (64,  65535, 65535,  [2, 1, 1, 8, 1, 3], "macOS / iOS"),
    (128, 65535, 65535,  [2, 3, 1, 1, 4],  "Windows 10 / Server 2019"),
    (128, 64240, 64240,  [2, 4, 8, 1, 3],  "Windows 11 / Server 2022"),
    (255, 4128,  4128,   [2],               "Cisco IOS"),
    (255, 8192,  16384,  [2],               "Network device (generic)"),
    (64,  32120, 32120,  [2, 4, 8, 1, 3],  "Linux 3.x"),
    (64,  8192,  8192,   [2, 1, 1, 1, 1],  "OpenBSD / FreeBSD"),
]


def ttl_bucket(ttl: int) -> int:
    """Normalize observed TTL to the likely starting TTL (64, 128, or 255)."""
    if ttl <= 64:
        return 64
    elif ttl <= 128:
        return 128
    else:
        return 255


def parse_tcp_options(options) -> list[int]:
    """
    Extract TCP option kinds from the options list returned by Scapy.

    Scapy returns options as a list of tuples: [('MSS', 1460), ('SAckOK', b''), ...]
    Map name → kind number.
    """
    name_to_kind = {
        "MSS": 2, "NOP": 1, "SAckOK": 4, "Timestamp": 8,
        "WScale": 3, "EOL": 0, "AltChkSum": 14,
    }
    kinds = []
    for opt in options:
        name = opt[0] if isinstance(opt, tuple) else opt
        k = name_to_kind.get(name)
        if k is not None:
            kinds.append(k)
    return kinds


def match_os(ttl: int, window: int, option_kinds: list[int]) -> str:
    """Find the best matching OS signature."""
    bucket = ttl_bucket(ttl)
    best_match = "Unknown"
    best_score = 0

    for (sig_ttl, win_min, win_max, sig_opts, label) in OS_SIGNATURES:
        if sig_ttl != bucket:
            continue
        score = 0
        if win_min <= window <= win_max:
            score += 3
        if option_kinds == sig_opts:
            score += 5
        elif option_kinds[:len(sig_opts)] == sig_opts:
            score += 2
        if score > best_score:
            best_score = score
            best_match = label

    return best_match


# ── Probe functions ────────────────────────────────────────────────────────────

def icmp_probe(target: str, timeout: float = 2.0) -> dict | None:
    """Send ICMP echo and extract TTL from reply."""
    reply = sr1(IP(dst=target, ttl=64) / ICMP(), timeout=timeout, verbose=False)
    if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
        return {"ttl": reply[IP].ttl}
    return None


def tcp_syn_probe(target: str, port: int, timeout: float = 2.0) -> dict | None:
    """Send SYN and extract fingerprint data from SYN-ACK."""
    pkt = IP(dst=target) / TCP(
        dport=port,
        sport=RandShort(),
        flags="S",
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (0, 0)),
            ("NOP", None),
            ("WScale", 6),
        ],
    )
    reply = sr1(pkt, timeout=timeout, verbose=False)
    if not (reply and reply.haslayer(TCP)):
        return None

    flags = reply[TCP].flags
    if flags & 0x12 != 0x12:   # not SYN-ACK
        return None

    # Send RST to clean up the half-open connection
    from scapy.all import send
    rst = IP(dst=target) / TCP(
        dport=port, sport=pkt[TCP].sport,
        flags="R", seq=reply[TCP].ack,
    )
    send(rst, verbose=False)

    return {
        "ttl":     reply[IP].ttl,
        "window":  reply[TCP].window,
        "options": parse_tcp_options(reply[TCP].options),
    }


# ── Main fingerprinter ─────────────────────────────────────────────────────────

def fingerprint(target: str, port: int):
    print(f"[*] Fingerprinting {target} (TCP/{port})")

    # Probe 1: ICMP TTL
    print("\n[1] ICMP echo probe")
    icmp_result = icmp_probe(target)
    if icmp_result:
        print(f"    TTL observed: {icmp_result['ttl']}  →  starting TTL bucket: {ttl_bucket(icmp_result['ttl'])}")
    else:
        print("    No ICMP response (filtered)")

    # Probe 2: TCP SYN fingerprint
    print(f"\n[2] TCP SYN probe on port {port}")
    tcp_result = tcp_syn_probe(target, port)
    if tcp_result:
        print(f"    TTL:      {tcp_result['ttl']}")
        print(f"    Window:   {tcp_result['window']}")
        print(f"    TCP opts: {tcp_result['options']}")

        os_guess = match_os(tcp_result["ttl"], tcp_result["window"], tcp_result["options"])
        print(f"\n[+] OS Guess: {os_guess}")

        if icmp_result:
            icmp_guess = match_os(icmp_result["ttl"], 0, [])
            print(f"[+] TTL-only guess from ICMP: TTL={icmp_result['ttl']} bucket={ttl_bucket(icmp_result['ttl'])}")
    else:
        print(f"    Port {port} not responding (closed or filtered)")
        if icmp_result:
            print(f"\n[+] TTL-only OS guess: {ttl_bucket(icmp_result['ttl'])}-class device")


def main():
    parser = argparse.ArgumentParser(description="TCP/ICMP OS fingerprinter")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("--port", type=int, default=80, help="TCP port to probe (default: 80)")
    args = parser.parse_args()
    fingerprint(args.target, args.port)


if __name__ == "__main__":
    main()
