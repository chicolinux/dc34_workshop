#!/usr/bin/env python3
"""
Module 5 — Intentionally Vulnerable Protocol Server

Implements a simple custom binary protocol for fuzzing practice.
Contains deliberate bugs that attendees will find with their fuzzers.

Protocol specification:
─────────────────────────────────────────────────────────
  Frame format (all fields big-endian):
  ┌──────────┬──────────┬──────────┬──────────────────────┐
  │ Magic    │ Opcode   │ Length   │ Payload              │
  │ 2 bytes  │ 1 byte   │ 2 bytes  │ Length bytes         │
  └──────────┴──────────┴──────────┴──────────────────────┘

  Magic:   0xDC34  (workshop identifier)
  Opcode:
    0x01 = PING   → responds with PONG (opcode 0x02)
    0x02 = PONG   → ignored
    0x03 = ECHO   → responds with same payload
    0x04 = UPPER  → responds with payload uppercased
    0x05 = STATS  → responds with server uptime as ASCII string
    0x06 = QUIT   → server closes connection
    0xFF = DEBUG  → [INTENTIONAL BUG] buffer overflow: copies Length bytes
                    into a fixed 64-byte buffer without bounds check

  Length: number of bytes in Payload field
  Payload: arbitrary bytes (max 65535, but server doesn't always check)

Intentional vulnerabilities (for fuzzing exercises):
  1. Opcode 0xFF + Length > 64: writes past buffer end → crash
  2. Opcode 0x03 + Length = 0xFFFF: server allocates 65535 bytes → OOM-like behavior
  3. Magic = 0x0000: triggers uninitialized variable access
  4. Length field mismatch: Length says 10, only 5 bytes sent → partial read hang

Start the server on the target VM:
  python3 module5/target_server.py [--port 9000]
"""

import argparse
import socket
import struct
import time
import threading
import ctypes
import sys

MAGIC = 0xDC34
PORT  = 9000
start_time = time.time()


# ── Frame parsing ──────────────────────────────────────────────────────────────

def recv_exact(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket, return b'' on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def parse_header(data: bytes):
    """Parse 5-byte frame header. Returns (magic, opcode, length) or raises."""
    if len(data) < 5:
        raise ValueError("Short header")
    magic, opcode, length = struct.unpack(">HBH", data)
    return magic, opcode, length


# ── Protocol handlers ─────────────────────────────────────────────────────────

def handle_ping(conn):
    response = struct.pack(">HBH", MAGIC, 0x02, 0)
    conn.sendall(response)
    return "PONG sent"


def handle_echo(conn, payload):
    response = struct.pack(">HBH", MAGIC, 0x03, len(payload)) + payload
    conn.sendall(response)
    return f"ECHO {len(payload)} bytes"


def handle_upper(conn, payload):
    upper = payload.upper()
    response = struct.pack(">HBH", MAGIC, 0x04, len(upper)) + upper
    conn.sendall(response)
    return f"UPPER {len(payload)} bytes"


def handle_stats(conn):
    uptime = f"uptime={time.time() - start_time:.1f}s threads={threading.active_count()}"
    payload = uptime.encode()
    response = struct.pack(">HBH", MAGIC, 0x05, len(payload)) + payload
    conn.sendall(response)
    return "STATS sent"


def handle_debug(conn, payload):
    """
    BUG 1: Fixed buffer, no bounds check.
    Simulated: if payload > 64 bytes, we crash predictably.
    In a real C implementation this would be a stack overflow.
    """
    BUFFER_SIZE = 64
    if len(payload) > BUFFER_SIZE:
        # Simulate crash: server raises exception (analogous to SIGSEGV)
        raise RuntimeError(
            f"CRASH: DEBUG opcode received {len(payload)} bytes, "
            f"buffer is only {BUFFER_SIZE} bytes — buffer overflow!"
        )
    response = struct.pack(">HBH", MAGIC, 0xFF, len(payload)) + payload
    conn.sendall(response)
    return f"DEBUG {len(payload)} bytes"


# ── Connection handler ─────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr):
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] Connection from {peer}")

    try:
        while True:
            # BUG 3: magic check uses == but doesn't validate separately
            header_data = recv_exact(conn, 5)
            if not header_data:
                break

            magic, opcode, length = parse_header(header_data)

            # BUG 3: if magic == 0x0000 we skip validation
            if magic != MAGIC and magic != 0x0000:
                error = b"BAD MAGIC"
                conn.sendall(struct.pack(">HBH", MAGIC, 0xEE, len(error)) + error)
                continue

            # BUG 4: We trust Length and try to read that many bytes.
            # If client sends Length=65535 but only 5 bytes follow, this hangs.
            payload = recv_exact(conn, length)
            if len(payload) < length:
                print(f"  [{peer}] Short payload (expected {length}, got {len(payload)})")
                break

            print(f"  [{peer}] opcode=0x{opcode:02X} length={length}")

            if opcode == 0x01:
                result = handle_ping(conn)
            elif opcode == 0x03:
                # BUG 2: If length = 0xFFFF (65535), allocate huge buffer
                if length == 0xFFFF:
                    print(f"  [{peer}] WARNING: max-length ECHO — allocating {length} bytes")
                result = handle_echo(conn, payload)
            elif opcode == 0x04:
                result = handle_upper(conn, payload)
            elif opcode == 0x05:
                result = handle_stats(conn)
            elif opcode == 0x06:
                print(f"  [{peer}] QUIT received")
                break
            elif opcode == 0xFF:
                result = handle_debug(conn, payload)  # BUG 1 is here
            else:
                error = f"UNKNOWN OPCODE 0x{opcode:02X}".encode()
                conn.sendall(struct.pack(">HBH", MAGIC, 0xEE, len(error)) + error)
                result = f"unknown opcode 0x{opcode:02X}"
                continue

            print(f"  [{peer}] → {result}")

    except RuntimeError as e:
        print(f"\n[!] SERVER CRASH from {peer}: {e}")
        print("    (In a real server this would be a segfault / SIGSEGV)")
        # Don't close server — allow it to recover and accept next connection
    except ConnectionResetError:
        print(f"  [{peer}] Connection reset")
    except Exception as e:
        print(f"  [{peer}] Error: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected: {peer}")


# ── Server loop ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Vulnerable protocol server for fuzzing practice")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(10)

    print(f"[*] Vulnerable protocol server listening on {args.host}:{args.port}")
    print(f"[*] Protocol: Magic=0xDC34, Opcodes: PING(01) ECHO(03) UPPER(04) STATS(05) QUIT(06) DEBUG(FF)")
    print(f"[*] Intentional bugs active — fuzz me!\n")

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
