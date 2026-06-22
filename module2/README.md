# Module 2 — Active Recon and Scanning

## Goals for this Module

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

## Verifying Evasion with Snort

The target VM runs **Snort IDS** on `eth1` with the community ruleset and the `sfPortscan` and
`frag3` preprocessors enabled. Use it as a truth oracle: if Snort logs an alert, the technique
was caught; if the alert log stays silent, the evasion worked.

### Watch alerts in real time (run on the target VM)

```bash
# Clear old alerts and watch live:
sudo truncate -s 0 /var/log/snort/alert && sudo tail -f /var/log/snort/alert
```

### Step 1 — Establish a baseline (plain scan, should be caught)

```bash
# Attacker:
sudo python3 /vagrant/module2/syn_scanner.py 192.168.56.2 --ports 1-1024
```

Within seconds the alert log on the target should show lines like:

```
06/20-21:20:24  [**] [122:1:1] (portscan) TCP Portscan [**]
[Classification: Attempted Information Leak] [Priority: 2]
{PROTO:255} 192.168.56.1 -> 192.168.56.2
```

### Step 2 — Apply evasion and compare

Run each technique from the Evasion Techniques section above, then check whether the alert
log produced new entries:

| Technique | Expected Snort result |
|-----------|----------------------|
| Plain SYN scan | **Caught** — sfPortscan fires immediately |
| IP fragmentation | **Partial** — sfPortscan silent, frag3 may log reassembly events |
| TTL jitter | **Caught** — sfPortscan still fires; TTL variance alone isn't enough |
| Inter-packet delay (slow scan) | **Evaded** — stays under PPS threshold; no alert |
| Fragmentation + TTL jitter + delay | **Often evaded** — real-world combination |

### What the results mean

- **`[122:1]` portscan alert** → `sfPortscan` caught the scan rate; evasion failed.
- **`[123:x]` frag alerts** → `frag3` reassembled your fragments; packet-level evasion failed.
- **No new lines** during the scan window → evasion succeeded against this ruleset.

> Snort status and alert location:
> ```bash
> sudo systemctl status dc34-snort        # check it is running
> sudo tail /var/log/snort/alert          # one-shot view of recent alerts
> sudo truncate -s 0 /var/log/snort/alert # clear between tests
> ```

## Exercises

| Exercise | File | Objective |
|----------|------|-----------|
| standalone | `host_discovery.py` | ARP/ICMP/TCP sweep to find live hosts |
| 2-A | `syn_scanner.py` | Build a SYN scanner with JSON output |
| 2-B | `os_fingerprint.py` | Extract TTL, window, TCP options for OS guess |
| 2-X (extra) | manual | Evade Snort with fragmentation + TTL jitter |

### Standalone Walkthrough — `host_discovery.py` (Network Sweep)

**Terminals needed: 1** — T1 attacker only

**Step 1 — ARP sweep (fastest, L2 only):**
```bash
sudo python3 /vagrant/module2/host_discovery.py 192.168.56.0/24 --method arp
```

**Step 2 — Try all methods and compare detection rates:**
```bash
sudo python3 /vagrant/module2/host_discovery.py 192.168.56.0/24 --method all
```

**What you will see:** live hosts at `.1` (attacker), `.2` (target), `.254` (gateway), each annotated
with the discovery method and MAC address. ARP is the most reliable on a flat LAN; ICMP and TCP
methods also work but may be filtered by host firewalls.

---

### Exercise 2-A Walkthrough — SYN Port Scanner

**Terminals needed: 2** — T1 attacker (scanner), T2 target (verify which ports are actually open)

**Step 1 — Confirm which services are listening on the target before scanning (T2):**
```bash
ss -tlnp
```

**Step 2 — Run the SYN scanner (T1):**
```bash
sudo python3 /vagrant/module2/syn_scanner.py 192.168.56.2 --ports 1-1024
```

**Step 3 — Compare the scanner's JSON output against the `ss` output from T2 (T1):**
```bash
cat results.json
```

**What you will see:** port 22 (SSH) and port 9000 (vulnerable service) as `open`; most others
as `closed` (RST received) or `filtered` (timeout). JSON file written with timestamp and elapsed time.

---

### Exercise 2-B Walkthrough — OS Fingerprinting

**Terminals needed: 1** — T1 attacker only (target just needs to be running)

**Step 1 — Fingerprint the target on SSH (always open):**
```bash
sudo python3 /vagrant/module2/os_fingerprint.py 192.168.56.2 --port 22
```

**Step 2 — Try a different port to see if the fingerprint changes:**
```bash
sudo python3 /vagrant/module2/os_fingerprint.py 192.168.56.2 --port 9000
```

**What you will see:** ICMP TTL (64 → starting TTL bucket), TCP window size, TCP option order
(`[MSS, SAckOK, Timestamp, NOP, WScale]`), and a scored OS guess — `Linux 5.x` for the Ubuntu target.

---

### Exercise 2-X Walkthrough — Evasion Verification with Snort

**Terminals needed: 2** — T1 attacker (scanner), T2 target (watch Snort alert log)

See the **"Verifying Evasion with Snort"** section above for the full step-by-step. In brief:

```bash
# T2 (target): watch alerts in real time
sudo truncate -s 0 /var/log/snort/alert && sudo tail -f /var/log/snort/alert

# T1 (attacker): baseline — plain SYN scan (should be caught)
sudo python3 /vagrant/module2/syn_scanner.py 192.168.56.2 --ports 1-500

# T1 (attacker): apply fragmentation evasion from the Evasion Techniques section
# and observe whether the [122:1:1] alert disappears from T2
```

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
