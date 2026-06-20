#!/usr/bin/env python3
"""
Environment verification script for DC34 Scapy Workshop.
Run as root: sudo python3 setup/verify_env.py
"""

import sys
import os
import socket
import subprocess
import importlib

TARGET_IP = "192.168.56.2"
MIN_PYTHON = (3, 10)
MIN_SCAPY = (2, 5, 0)

RESET = "\033[0m"
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
BOLD  = "\033[1m"

passed = 0
failed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  {GREEN}[OK]{RESET}   {msg}")


def fail(msg, hint=""):
    global failed
    failed += 1
    print(f"  {RED}[FAIL]{RESET} {msg}")
    if hint:
        print(f"         {YELLOW}Hint:{RESET} {hint}")


def warn(msg):
    print(f"  {YELLOW}[WARN]{RESET} {msg}")


def section(title):
    print(f"\n{BOLD}--- {title} ---{RESET}")


# ── Python version ─────────────────────────────────────────────────────────────
section("Python Version")
if sys.version_info >= MIN_PYTHON:
    ok(f"Python {sys.version.split()[0]}")
else:
    fail(
        f"Python {sys.version.split()[0]} is too old (need {'.'.join(map(str, MIN_PYTHON))}+)",
        "Install Python 3.10+ from your package manager.",
    )

# ── Root / raw socket capability ──────────────────────────────────────────────
section("Privileges")
if os.geteuid() == 0:
    ok("Running as root")
else:
    fail(
        "Not running as root",
        "Re-run with: sudo python3 setup/verify_env.py",
    )

# ── Scapy import and version ──────────────────────────────────────────────────
section("Scapy Installation")
try:
    import scapy
    from scapy.all import conf, IP, TCP, UDP, Ether, ARP, ICMP, DNS, Raw
    from scapy.all import send, sendp, sr, sr1, srp, sniff, wrpcap, rdpcap
    from scapy.all import fuzz, fragment, RandIP, RandShort

    # Parse version
    ver_str = scapy.__version__
    parts = ver_str.split(".")
    ver_tuple = tuple(int(x) for x in parts[:3] if x.isdigit())

    if ver_tuple >= MIN_SCAPY:
        ok(f"Scapy {ver_str}")
    else:
        fail(
            f"Scapy {ver_str} is too old (need {'.'.join(map(str, MIN_SCAPY))}+)",
            "pip3 install --upgrade scapy",
        )
except ImportError as e:
    fail(f"Cannot import Scapy: {e}", "pip3 install scapy")

# ── Raw socket test ───────────────────────────────────────────────────────────
section("Raw Socket Access")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.close()
    ok("Raw socket creation succeeded")
except PermissionError:
    fail(
        "Cannot create raw socket",
        "Run as root or: sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)",
    )
except Exception as e:
    fail(f"Unexpected error creating raw socket: {e}")

# ── Network interface ─────────────────────────────────────────────────────────
section("Network Interface")
try:
    from scapy.all import conf, get_if_list
    ifaces = get_if_list()
    ok(f"Available interfaces: {', '.join(ifaces)}")

    if conf.iface:
        ok(f"Default interface: {conf.iface}")
    else:
        warn("conf.iface is empty; set it manually: conf.iface = 'eth0'")

    # Check if any interface has 192.168.56.x
    from scapy.all import get_if_addr
    found_lab_ip = False
    for iface in ifaces:
        try:
            addr = get_if_addr(iface)
            if addr.startswith("192.168.56."):
                ok(f"Lab IP {addr} found on interface {iface}")
                found_lab_ip = True
        except Exception:
            pass
    if not found_lab_ip:
        warn(
            "No interface with 192.168.56.x found. "
            "If using a different network range, adjust TARGET_IP at top of this script."
        )
except Exception as e:
    fail(f"Interface check failed: {e}")

# ── Target reachability ────────────────────────────────────────────────────────
section("Target Reachability")
try:
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", TARGET_IP],
        capture_output=True,
        timeout=5,
    )
    if result.returncode == 0:
        ok(f"Target {TARGET_IP} is reachable via ICMP")
    else:
        warn(
            f"Target {TARGET_IP} did not respond to ICMP ping. "
            "It may still be reachable (ICMP could be filtered). Start the target VM."
        )
except subprocess.TimeoutExpired:
    warn(f"Ping to {TARGET_IP} timed out")
except FileNotFoundError:
    warn("ping command not found; skipping reachability check")

# ── Scapy packet construction ─────────────────────────────────────────────────
section("Scapy Packet Construction")
try:
    pkt = Ether() / IP(dst=TARGET_IP) / TCP(dport=80, flags="S")
    assert pkt[IP].dst == TARGET_IP
    assert pkt[TCP].dport == 80
    ok("Ether/IP/TCP packet construction works")

    arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=TARGET_IP)
    ok("ARP packet construction works")

    icmp_pkt = IP(dst=TARGET_IP) / ICMP() / Raw(load=b"DEFCON34")
    ok("ICMP packet construction works")

    dns_pkt = IP(dst=TARGET_IP) / UDP(dport=53) / DNS(rd=1)  # type: ignore[name-defined]
    ok("DNS packet construction works")

    fuzz_pkt = fuzz(IP()) / fuzz(TCP())
    ok("fuzz() function works")

    fragments = fragment(IP(dst=TARGET_IP) / TCP(dport=80) / Raw(load=b"A" * 100))
    ok(f"fragment() produced {len(fragments)} fragments")
except Exception as e:
    fail(f"Packet construction failed: {e}")

# ── Optional dependencies ─────────────────────────────────────────────────────
section("Optional Dependencies")
for pkg in ["netaddr", "tabulate", "cryptography"]:
    try:
        importlib.import_module(pkg)
        ok(f"{pkg} is installed")
    except ImportError:
        warn(f"{pkg} not found — some helper scripts may fail. pip3 install {pkg}")

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{BOLD}{'='*50}{RESET}")
total = passed + failed
print(f"{BOLD}Results: {GREEN}{passed} passed{RESET}  {RED}{failed} failed{RESET}  (out of {total} checks)")
if failed == 0:
    print(f"\n{GREEN}{BOLD}You're ready for the workshop!{RESET}")
else:
    print(f"\n{RED}Fix the failed checks before the workshop starts.{RESET}")
    print("Ask an instructor if you're stuck.")
print()
