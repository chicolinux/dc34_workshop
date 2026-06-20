# Module 2 — Active Recon and Scanning

## Learning Objectives

- Build port scanners that give you control Nmap abstracts away
- Understand why each scan type works and when to use each
- Fingerprint OS and service versions through packet-level analysis
- Evade basic IDS signatures by crafting non-standard probes

---

## Scan Type Reference

| Scan Type | Probe | Open Response | Closed Response | Stealthy? |
|-----------|-------|--------------|-----------------|-----------|
| SYN (half-open) | TCP SYN | SYN-ACK | RST | Yes — no full connection |
| Full connect | TCP SYN | Full handshake | RST | No — logged by application |
| ACK | TCP ACK | RST (unfiltered) | no reply (stateful FW) | Maps firewalls |
| FIN/NULL/Xmas | FIN or no flags | No reply (open) | RST (closed) | High — odd flags |
| UDP | UDP datagram | App response | ICMP port-unreach | Slow |
| Window | TCP ACK | RST with nonzero window (open?) | RST window=0 | OS-dependent |

## Why SYN Scan is Preferred

A SYN scan never completes the TCP handshake. The target's TCP stack responds, but
the application process never wakes up (no `accept()` call). Most application-layer
logs therefore see nothing. Network-level firewalls and IDS still see the SYN, but
application logs (Apache, nginx, sshd) do not.

## OS Fingerprinting Signals

```
Signal              Linux           Windows         macOS
──────────────────────────────────────────────────────────
Initial TTL         64              128             64
Initial Window      5720-14480      64240-65535     65535
TCP opt order       MSS,SACK,TS,    MSS,WS,NOP,     MSS,NOP,NOP,
                    NOP,WS          NOP,SACK         TS,NOP,WS
```

TTL decays by 1 per hop. If you observe TTL=60, the starting TTL was likely 64
(Linux/macOS, 4 hops away). If TTL=124, starting TTL was likely 128 (Windows).

### TCP Options Order — Why It Matters

The order in which a host lists TCP options in its SYN packet is one of the most reliable
OS fingerprinting signals. Each OS has a fixed, characteristic sequence:

| Option | Full Name | Purpose |
|--------|-----------|---------|
| `MSS` | Maximum Segment Size | Max payload bytes per segment (typically 1460) |
| `SACK` | Selective Acknowledgement | ACK non-contiguous blocks, reducing retransmits |
| `TS` | Timestamps | RTT measurement + PAWS (Protection Against Wrapped Sequence numbers) |
| `WS` | Window Scale | Scales the receive window beyond the 65535-byte limit |
| `NOP` | No Operation | 1-byte padding to align options to 4-byte boundaries |

Linux sends `MSS, SACK, TS, NOP, WS` — the order alone, before examining any values, is
enough to distinguish Linux from Windows or macOS. In Scapy, craft the Linux fingerprint like this:

```python
IP(dst="192.168.56.2") / TCP(
    dport=80, flags="S",
    options=[
        ("MSS",       1460),
        ("SAckOK",    b""),
        ("Timestamp", (0, 0)),
        ("NOP",       None),
        ("WScale",    7),
    ]
)
```

`os_fingerprint.py` sends this probe and compares the SYN-ACK response's option order, TTL,
and window size against known OS profiles to make a guess.

## Evasion Techniques

### IP Fragmentation
Split the TCP header across multiple IP fragments so that IDS sensors
reassembling only the first fragment miss the TCP flags/ports:

```python
from scapy.all import fragment, IP, TCP, Raw
pkt = IP(dst=target) / TCP(dport=80, flags="S") / Raw(b"\x00" * 8)
frags = fragment(pkt, fragsize=8)   # fragment every 8 bytes
send(frags)
```

### TTL Jitter
Send each probe with a slightly randomized TTL to break IDS correlation rules:

```python
import random
for port in ports:
    ttl = random.choice([63, 64, 65, 127, 128])
    sr1(IP(dst=target, ttl=ttl) / TCP(dport=port, flags="S"))
```

### Random Source Ports and Decoys
Use `RandShort()` for sport and add decoy source IPs in the IP options.

### Inter-packet Delay
Slow down the scan rate to stay under per-source PPS thresholds:

```python
import time, random
time.sleep(random.uniform(0.05, 0.2))   # 5-20ms between probes
```

## Exercises

| Exercise | File | Objective |
|----------|------|-----------|
| 2-A | `syn_scanner.py` | Build a SYN scanner with JSON output |
| 2-B | `os_fingerprint.py` | Extract TTL, window, TCP options for OS guess |
| 2-X (extra) | manual | Evade Snort with fragmentation + TTL jitter |

## Comparison to Nmap

| Feature | Nmap | This module |
|---------|------|-------------|
| Speed | Fast (optimized C) | Slower (Python) |
| Output | Rich XML/greppable | JSON (your schema) |
| Customization | Limited to Nmap options | Arbitrary per-packet control |
| Evasion | `--mtu`, `--ttl`, `--data-length` | Full field control |
| Learning | Black box | You see every packet decision |

Use Nmap for production sweeps. Use Scapy when you need to craft something
Nmap cannot express, or when you need to understand exactly what is on the wire.
