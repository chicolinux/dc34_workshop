# Module 1 — Scapy Fundamentals

## Learning Objectives

- Construct packets layer by layer with the `/` stacking operator
- Choose the right send/receive primitive for the job (`send`, `sr`, `sr1`, `sendp`, `srp1`)
- Capture live traffic with blocking, callback, and asynchronous sniffers
- Read and write PCAP files, and pull fields out of captured packets
- Write Scapy that behaves well inside a script (not just the interactive shell)

---

## Layer Stacking

Every layer is a Python class with named fields; `/` stacks them outward from the lowest layer:

```python
pkt = Ether() / IP(dst="192.168.56.2") / TCP(dport=80, flags="S")
pkt.show()      # all layers and fields, with computed values
pkt.show2()     # forces auto-fields (chksum, len) — what goes on the wire
pkt.hexdump()   # raw bytes
pkt[TCP].flags  # access a field by layer class
```

Scapy auto-fills anything you leave out (source port, checksums, lengths). Override a field just by
passing it — `IP(dst=..., ttl=64)`, `TCP(dport=80, flags="S", seq=1000)`.

## Send / Receive Primitives

| Function | Layer | Returns | Use for |
|----------|-------|---------|---------|
| `send()` | 3 (IP) | nothing | Fire-and-forget, no reply expected |
| `sr1()` | 3 (IP) | first reply (or `None`) | One probe, one answer (e.g. a single port) |
| `sr()` | 3 (IP) | `(answered, unanswered)` | A batch of probes at once |
| `sendp()` | 2 (Ether) | nothing | Custom Ethernet frames, ARP |
| `srp1()` | 2 (Ether) | first reply (or `None`) | Layer-2 request/response (e.g. ARP who-has) |

Layer-3 functions let the OS build the Ethernet frame; Layer-2 functions (`p` suffix) require you to
supply MAC addresses and usually an `iface`.

## Sniffing

```python
sniff(iface="eth0", filter="icmp or arp", count=5, timeout=10)   # blocking, BPF filter
sniff(iface="eth0", filter="ip", prn=callback)                   # callback per packet

s = AsyncSniffer(iface="eth0", filter="tcp"); s.start()          # non-blocking, background thread
# ... send attack packets while it captures ...
s.stop(); pkts = s.results
```

`AsyncSniffer` is the important one for attack scripts: it captures in the background while your code
sends packets in the foreground.

## PCAP I/O

```python
wrpcap("/tmp/demo.pcap", pkts)          # write a packet list
loaded = rdpcap("/tmp/demo.pcap")       # read it back
icmp = [p for p in loaded if p.haslayer(ICMP)]
```

## Scripting Notes

- Set `conf.verb = 0` (and/or quiet the `scapy.runtime` logger) so scripts don't spam per-packet output.
- Wrap `sr1()` so a timeout returns `None` instead of stalling, and check `reply.haslayer(TCP)` before
  reading TCP fields.
- A SYN-ACK is `flags & 0x12 == 0x12` — the standard "port open" test.

## Exercises

| Exercise | File | Objective |
|----------|------|-----------|
| 1-A | `fundamentals.py` | Packet anatomy lab — complete the TODOs in `exercise_1a()` |
| 1-B | `pcap_dissector.py` | Extract unique source IPs, reassemble an HTTP body by TCP sequence, write a TCP-only PCAP |

### Running

```bash
# Walk through every fundamentals section (or pick one with --section)
sudo python3 module1/fundamentals.py
sudo python3 module1/fundamentals.py --section sniffing

# Dissect a capture. The fundamentals PCAP demo writes /tmp/demo.pcap you can point at,
# or supply your own HTTP capture.
sudo python3 module1/pcap_dissector.py <capture.pcap> [output.pcap]
```

`fundamentals.py` targets `192.168.56.2` and uses `conf.iface` by default — edit `TARGET`/`IFACE` at the
top of the file if your lab differs.
