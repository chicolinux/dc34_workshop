# Module 1 — Scapy Fundamentals

## Goals for this Module

- Construct packets layer by layer with the `/` stacking operator
- Choose the right send/receive primitive for the job (`send`, `sr`, `sr1`, `sendp`, `srp1`)
- Capture live traffic with blocking, callback, and asynchronous sniffers
- Read and write PCAP files, and pull fields out of captured packets
- Write Scapy that behaves well inside a script (not just the interactive shell)

---

## Before You Start (Interactive REPL)

When using the Scapy interactive shell (`sudo scapy`), the default interface is `eth0` — Vagrant's
NAT link to the outside world. All lab traffic between attacker and target travels on **`eth1`**
(the `192.168.56.0/24` internal network). Run these two lines once at the start of every REPL
session so every `sniff()`, `send()`, and `sr1()` call uses the right NIC without needing an
explicit `iface=` argument:

```python
conf.verb = 0                                          # silence per-packet noise
conf.iface = conf.route.route("192.168.56.0")[0]      # pin to the lab NIC (eth1)
```

The workshop scripts do this for you automatically; it only matters in the interactive shell.

---

## Layer Stacking

Every layer is a Python class with named fields; `/` stacks them outward from the lowest layer:

```python
pkt = Ether() / IP(dst="192.168.56.2") / TCP(dport=80, flags="S")
pkt.show()      # all layers and fields, with computed values
pkt.show2()     # forces auto-fields (chksum, len) — what goes on the wire
hexdump(pkt)    # raw bytes — standalone function in Scapy 2.6+, not a method
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
sniff(iface="eth1", filter="icmp or arp", count=5, timeout=10)   # blocking, BPF filter
sniff(iface="eth1", filter="ip", prn=callback)                   # callback per packet

s = AsyncSniffer(iface="eth1", filter="tcp"); s.start()          # non-blocking, background thread
# ... send attack packets while it captures ...
s.stop(); pkts = s.results
```

`AsyncSniffer` is the important one for attack scripts: it captures in the background while your code
sends packets in the foreground.

## PCAP I/O

**Display live and save to file at the same time** — use `prn` for real-time output while
`sniff` stores packets, then write them to disk after:

```python
pkts = sniff(iface="eth1", filter="icmp or arp", count=5, timeout=10,
             prn=lambda p: p.summary())   # prints each packet as it arrives
wrpcap("/tmp/capture.pcap", pkts)         # save everything captured to disk
```

Swap `p.summary()` for `p.show()` if you want the full field-by-field breakdown per packet.

**Reading back and filtering:**

```python
wrpcap("/tmp/demo.pcap", pkts)                          # write a packet list
loaded = rdpcap("/tmp/demo.pcap")                       # read it back
icmp = [p for p in loaded if p.haslayer(ICMP)]         # filter by layer
```

**pcap vs pcapng:** `wrpcap()` writes classic **pcap** (libpcap format) — the default for this
workshop. It is universally supported by Wireshark, tcpdump, and tshark with no extra flags.
Scapy 2.5+ also provides `wrpcapng()` / `rdpcapng()` for the newer **pcapng** format, but classic
pcap is simpler and sufficient for all workshop exercises.

## Generating Test Traffic from the Target

When practicing sniffing you need something on the wire to capture. Run these from the **target VM**
(`vagrant ssh target`) to generate realistic traffic while your sniffer runs on the attacker:

| Tool | Command | Traffic type |
|------|---------|--------------|
| `ping` | `ping 192.168.56.1` | ICMP echo — simplest smoke test |
| `curl` | `curl http://192.168.56.1` | Real HTTP GET with `Host:` header — best for sniffing exercises |
| `wget` | `wget -q -O /dev/null http://192.168.56.1` | Same as curl, good for repeated downloads |

`curl` is the preferred tool for most sniffing exercises — it generates proper HTTP headers
(including `Host:`) that `arp_mitm.py`'s intercept callback looks for in raw TCP payloads.

For **filter** reference when sniffing the corresponding traffic:

```python
# On attacker — start sniffer, then run curl/ping on target during the sleep
s = AsyncSniffer(iface="eth1", filter="icmp"); s.start()        # for ping
s = AsyncSniffer(iface="eth1", filter="tcp port 80"); s.start() # for curl/wget
import time; time.sleep(10)   # generate traffic from target in this window
s.stop(); s.results
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

### Exercise 1-A Walkthrough — Packet Anatomy Lab

**Terminals needed: 2** — T1 attacker (runs the script), T2 target (generates live traffic for the sniffing section)

**Step 1 — Run the reference sections to see expected output before editing (T1):**
```bash
sudo python3 /vagrant/module1/fundamentals.py --section construction
sudo python3 /vagrant/module1/fundamentals.py --section send_receive
```

**Step 2 — Generate ICMP traffic for the sniffing section (T2):**
```bash
ping 192.168.56.1
```

**Step 3 — Run the sniffing section while T2 is pinging (T1):**
```bash
sudo python3 /vagrant/module1/fundamentals.py --section sniffing
```

**Step 4 — Open `fundamentals.py` and fill in the five TODOs in `exercise_1a()` (T1):**
```bash
nano /vagrant/module1/fundamentals.py   # or vim, or any editor
sudo python3 /vagrant/module1/fundamentals.py --section 1a
```

**Step 5 — Run the full script to verify all sections work (T1):**
```bash
sudo python3 /vagrant/module1/fundamentals.py
```

**What you will see:** packet `.show()` and `.show2()` output, `hexdump()` bytes, `sr1()` reply with TTL,
sniffed packet summaries, PCAP written to `/tmp/demo.pcap`.

---

### Exercise 1-B Walkthrough — PCAP Analysis

**Terminals needed: 1** — T1 attacker only (pure file processing, no live traffic required)

**Step 1 — Generate a PCAP to analyze using the fundamentals pcap section (T1):**
```bash
sudo python3 /vagrant/module1/fundamentals.py --section pcap
# writes /tmp/demo.pcap
```

**Step 2 — Run the dissector against it (T1):**
```bash
sudo python3 /vagrant/module1/pcap_dissector.py /tmp/demo.pcap
```

**Optional — Capture real HTTP traffic for a richer dataset (2 terminals):**
```bash
# T1 (attacker): capture HTTP traffic while T2 generates it
sudo python3 -c "
from scapy.all import *
pkts = sniff(iface='eth1', filter='tcp port 80', count=30, timeout=15)
wrpcap('/tmp/http_cap.pcap', pkts)
print(f'Saved {len(pkts)} packets')
"
# T2 (target): curl http://192.168.56.1

# Then dissect the capture:
sudo python3 /vagrant/module1/pcap_dissector.py /tmp/http_cap.pcap http_only.pcap
```

**What you will see:** list of unique source IPs, reassembled HTTP payload (headers + body in
sequence-number order), and a count of TCP-only packets written to the output PCAP.
