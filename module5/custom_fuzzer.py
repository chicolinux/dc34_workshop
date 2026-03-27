#!/usr/bin/env python3
"""
Module 5 — Exercise 5-B: Custom Protocol Fuzzer

Fuzzes the DC34 workshop protocol server using:
  1. Boundary value mutations (known-bad values for each field type)
  2. Random mutation via Scapy's fuzz()
  3. Canary probes to detect server crashes
  4. Crash capture to PCAP and log

Start the server first:
  python3 module5/target_server.py --port 9000

Then run the fuzzer:
  sudo python3 module5/custom_fuzzer.py --target 10.0.0.2 --port 9000

For state-aware fuzzing exercise (5-X), see the extra_stateful_fuzzer() function.
"""

import argparse
import datetime
import os
import socket
import struct
import time
import random
from pathlib import Path

from scapy.all import fuzz, Raw, wrpcap, IP, TCP, conf

conf.verb = 0

# Import our custom protocol layer
import sys
sys.path.insert(0, str(Path(__file__).parent))
from custom_proto import DC34Proto, MAGIC, send_frame, parse_response

CRASH_DIR = Path("crashes")
CRASH_DIR.mkdir(exist_ok=True)

# ── Boundary values ────────────────────────────────────────────────────────────

BOUNDARY_OPCODES = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                    0x07, 0x7F, 0x80, 0xEE, 0xFE, 0xFF]

BOUNDARY_LENGTHS = [0, 1, 2, 8, 16, 32, 63, 64, 65, 127, 128,
                    255, 256, 1023, 1024, 32767, 32768, 65534, 65535]

BOUNDARY_MAGICS  = [0x0000, 0x0001, 0xDC33, 0xDC34, 0xDC35, 0xFFFF, 0xDEAD, 0xBEEF]

INTERESTING_PAYLOADS = [
    b"",
    b"\x00",
    b"\xFF",
    b"A" * 64,
    b"A" * 65,
    b"A" * 128,
    b"A" * 256,
    b"\x00" * 64,
    b"%s%s%s%s%s",           # format string
    b"../../etc/passwd",
    b"\r\n\r\n",
    b"\xFF\xFE\xFD\xFC",
    b"SELECT * FROM users",
    b"`id`",
    bytes(range(256)),        # all byte values
]

# ── Canary probe ───────────────────────────────────────────────────────────────

def is_server_alive(host: str, port: int, timeout: float = 2.0) -> bool:
    """
    Send a known-good PING and check for PONG response.
    Returns True if server is responsive.
    """
    try:
        ping = DC34Proto(magic=MAGIC, opcode=0x01)
        response = send_frame(host, port, ping)
        if len(response) >= 5:
            magic, opcode, _ = struct.unpack(">HBH", response[:5])
            return magic == MAGIC and opcode == 0x02   # PONG
        return False
    except Exception:
        return False


# ── Crash capture ──────────────────────────────────────────────────────────────

def save_crash(frame: DC34Proto, target: str, port: int, iteration: int):
    """Save crash-triggering packet to a PCAP file."""
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = CRASH_DIR / f"crash_{ts}_iter{iteration}.pcap"

    # Wrap in IP/TCP for PCAP storage (so Wireshark can open it)
    pkt = IP(dst=target) / TCP(dport=port, flags="PA") / bytes(frame)
    wrpcap(str(filename), [pkt])

    print(f"\n  [CRASH] Saved to {filename}")
    print(f"  [CRASH] Frame: magic=0x{frame.magic:04X} opcode=0x{frame.opcode:02X} "
          f"length={frame.length} payload={bytes(frame.payload)[:32]!r}")
    return filename


# ── Mutation generators ────────────────────────────────────────────────────────

def boundary_mutations():
    """Generate frames with boundary values in each field."""
    for magic in BOUNDARY_MAGICS:
        for opcode in BOUNDARY_OPCODES:
            yield DC34Proto(magic=magic, opcode=opcode)

    for opcode in BOUNDARY_OPCODES:
        for length in BOUNDARY_LENGTHS:
            # Build raw frame manually to set length without payload constraint
            raw = struct.pack(">HBH", MAGIC, opcode, length)
            yield raw   # raw bytes (not a DC34Proto) to bypass Scapy validation

    for payload in INTERESTING_PAYLOADS:
        for opcode in [0x03, 0x04, 0xFF]:   # ECHO, UPPER, DEBUG
            yield DC34Proto(magic=MAGIC, opcode=opcode, payload=payload)


def random_mutations(seed: int | None = None, count: int = 200):
    """Generate randomly fuzzed frames using Scapy's fuzz()."""
    if seed is not None:
        random.seed(seed)
    for _ in range(count):
        yield fuzz(DC34Proto())


# ── Core fuzzer loop ───────────────────────────────────────────────────────────

def fuzz_server(target: str, port: int, max_iter: int = 1000, seed: int | None = None):
    crash_log = []
    iteration  = 0

    print(f"[*] Fuzzing {target}:{port}")
    print(f"[*] Crash files → {CRASH_DIR}/")
    print(f"[*] Seed: {seed}\n")

    # Check server is up before we start
    if not is_server_alive(target, port):
        print(f"[-] Server at {target}:{port} is not responding to canary ping")
        print("    Start it with: python3 module5/target_server.py")
        return

    print("[+] Server alive, starting fuzz loop...\n")

    generators = [
        ("boundary", boundary_mutations()),
        ("random",   random_mutations(seed=seed, count=max(200, max_iter // 2))),
    ]

    for gen_name, gen in generators:
        if iteration >= max_iter:
            break

        for frame in gen:
            if iteration >= max_iter:
                break

            iteration += 1

            # Send frame (handle both DC34Proto objects and raw bytes)
            try:
                if isinstance(frame, (bytes, bytearray)):
                    # Raw bytes — send directly
                    s = socket.create_connection((target, port), timeout=3)
                    s.sendall(frame)
                    try:
                        s.recv(1024)
                    except Exception:
                        pass
                    s.close()
                else:
                    send_frame(target, port, frame)

            except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError):
                pass   # expected: server closed connection on bad input

            except Exception as e:
                pass

            # Canary check every 10 iterations
            if iteration % 10 == 0:
                alive = is_server_alive(target, port)
                if not alive:
                    print(f"\n[!] Iter {iteration}: SERVER NOT RESPONDING (canary failed)")

                    # The last frame is the likely culprit
                    crash_file = save_crash(
                        frame if isinstance(frame, DC34Proto) else DC34Proto(),
                        target, port, iteration,
                    )
                    crash_log.append({"iteration": iteration, "file": str(crash_file)})

                    # Wait for server to recover (it may restart automatically)
                    print("    Waiting for server recovery...")
                    for _ in range(10):
                        time.sleep(1)
                        if is_server_alive(target, port):
                            print("    [+] Server recovered")
                            break
                    else:
                        print("    [-] Server did not recover — restart manually")
                        break

                # Progress indicator
                print(f"\r  [{gen_name}] iter={iteration:5d}  crashes={len(crash_log)}", end="", flush=True)

    print(f"\n\n{'='*50}")
    print(f"[*] Fuzzing complete: {iteration} iterations, {len(crash_log)} crashes")
    if crash_log:
        print("\nCrash summary:")
        for c in crash_log:
            print(f"  iter={c['iteration']}  file={c['file']}")
    else:
        print("\n[!] No crashes found. Try increasing --iters or adjusting mutation strategy.")

    return crash_log


# ── Extra: Stateful fuzzer skeleton (exercise 5-X) ────────────────────────────

def stateful_fuzzer_skeleton(target: str, port: int):
    """
    Exercise 5-X: Stateful fuzzer that completes a valid handshake
    before fuzzing the COMMAND stage.

    TODO for attendees:
      1. Connect and send a valid PING (opcode 0x01) to verify connection
      2. Only then start fuzzing opcodes 0x03-0xFF
      3. Track which opcodes produced: valid response / error response / crash
      4. Report coverage
    """
    print("\n[*] Stateful fuzzer skeleton")
    print("    Complete the TODOs to implement state-aware fuzzing\n")

    results = {"valid": [], "error": [], "crash": []}

    for opcode in range(0x00, 0x100):
        # TODO 1: open a NEW connection for each probe

        # TODO 2: send PING first (warm up / verify connection is working)
        #   ping_response = send_frame(target, port, DC34Proto(opcode=0x01))

        # TODO 3: send the opcode under test with a benign payload
        #   frame = DC34Proto(opcode=opcode, payload=b"test")
        #   response = send_frame(target, port, frame)

        # TODO 4: classify the response
        #   if valid → results["valid"].append(opcode)
        #   if error  → results["error"].append(opcode)

        # TODO 5: canary check after each probe
        #   if not is_server_alive(target, port):
        #       results["crash"].append(opcode); save_crash(...)

        pass   # remove when implementing

    print(f"  Valid opcodes: {[hex(x) for x in results['valid']]}")
    print(f"  Error opcodes: {[hex(x) for x in results['error']]}")
    print(f"  Crash opcodes: {[hex(x) for x in results['crash']]}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="DC34Proto fuzzer")
    parser.add_argument("--target", default="10.0.0.2")
    parser.add_argument("--port",   type=int, default=9000)
    parser.add_argument("--iters",  type=int, default=1000, help="Max iterations (default: 1000)")
    parser.add_argument("--seed",   type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--stateful", action="store_true", help="Run stateful fuzzer skeleton (exercise 5-X)")
    args = parser.parse_args()

    if args.stateful:
        stateful_fuzzer_skeleton(args.target, args.port)
    else:
        fuzz_server(args.target, args.port, max_iter=args.iters, seed=args.seed)


if __name__ == "__main__":
    main()
