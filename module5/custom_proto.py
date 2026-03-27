#!/usr/bin/env python3
"""
Module 5 — Exercise 5-B: Custom Protocol Definition in Scapy

Defines the DC34 workshop binary protocol as a Scapy Packet subclass.
This allows you to:
  - Build valid frames with Python syntax
  - Use fuzz() on the entire frame or individual fields
  - Dissect captured frames automatically
  - Layer on top of IP/TCP with /

Protocol spec (from target_server.py):
  ┌──────────┬──────────┬──────────┬──────────────────────┐
  │ Magic    │ Opcode   │ Length   │ Payload              │
  │ 2 bytes  │ 1 byte   │ 2 bytes  │ Length bytes         │
  └──────────┴──────────┴──────────┴──────────────────────┘
"""

import struct
from scapy.packet import Packet, bind_layers
from scapy.fields import (
    XShortField,
    XByteField,
    FieldLenField,
    StrLenField,
    ConditionalField,
    ByteEnumField,
)
from scapy.layers.inet import TCP


# ── Opcode constants ───────────────────────────────────────────────────────────

OPCODES = {
    0x01: "PING",
    0x02: "PONG",
    0x03: "ECHO",
    0x04: "UPPER",
    0x05: "STATS",
    0x06: "QUIT",
    0xEE: "ERROR",
    0xFF: "DEBUG",
}

MAGIC = 0xDC34


# ── Scapy layer definition ────────────────────────────────────────────────────

class DC34Proto(Packet):
    """
    Custom Scapy layer for the DC34 workshop protocol.

    Usage:
        from module5.custom_proto import DC34Proto, MAGIC

        # Build a PING frame
        pkt = DC34Proto(magic=MAGIC, opcode=0x01)
        pkt.show()

        # Build an ECHO frame with payload
        pkt = DC34Proto(opcode=0x03) / Raw(b"hello world")
        pkt.show2()

        # Fuzz the opcode and length fields
        fuzzed = fuzz(DC34Proto())
        fuzzed.show()
    """

    name = "DC34Proto"

    fields_desc = [
        # Magic bytes — should be 0xDC34 for valid frames
        XShortField("magic", MAGIC),

        # Opcode — one of the defined command bytes
        ByteEnumField("opcode", 0x01, OPCODES),

        # Length — number of bytes in payload; auto-computed when payload is present
        FieldLenField("length", None, length_of="payload", fmt="!H"),

        # Payload — variable length string based on `length` field
        StrLenField("payload", b"", length_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return b"", s


# ── Bind to TCP port 9000 so Scapy auto-dissects ─────────────────────────────
bind_layers(TCP, DC34Proto, dport=9000)
bind_layers(TCP, DC34Proto, sport=9000)


# ── Helper: send a frame over a raw TCP socket ────────────────────────────────

def send_frame(host: str, port: int, frame: DC34Proto) -> bytes:
    """
    Connect to host:port, send a DC34Proto frame, return raw response bytes.
    Uses stdlib socket (not Scapy send) for reliable TCP delivery.
    """
    import socket
    raw = bytes(frame)
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(raw)
        try:
            response = s.recv(4096)
        except socket.timeout:
            response = b""
    return response


def parse_response(raw: bytes) -> "DC34Proto | None":
    """Parse raw response bytes as a DC34Proto frame."""
    if len(raw) < 5:
        return None
    try:
        return DC34Proto(raw)
    except Exception:
        return None


# ── Quick sanity test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    from scapy.all import fuzz, Raw

    print("=== DC34Proto layer demo ===\n")

    # Valid PING
    ping = DC34Proto(magic=MAGIC, opcode=0x01)
    print("PING frame:")
    ping.show()

    # Valid ECHO with payload
    echo = DC34Proto(opcode=0x03) / Raw(b"Hello DEFCON!")
    print("\nECHO frame:")
    echo.show2()
    print(f"  Raw bytes: {bytes(echo).hex()}")

    # Fuzzed frame — random fields
    fuzzed = fuzz(DC34Proto())
    print("\nFuzzed frame:")
    fuzzed.show()

    # Show boundary values that will be used in the fuzzer
    boundary_opcodes = [0x00, 0x01, 0x06, 0x7F, 0x80, 0xFE, 0xFF]
    boundary_lengths = [0, 1, 63, 64, 65, 255, 256, 65534, 65535]
    print(f"\nBoundary opcodes: {[hex(x) for x in boundary_opcodes]}")
    print(f"Boundary lengths: {boundary_lengths}")
